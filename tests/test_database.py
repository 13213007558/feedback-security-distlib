# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2013 The Python Software Foundation.
# See LICENSE.txt and CONTRIBUTORS.txt.
#
from __future__ import unicode_literals

import base64
import io
import os
import errno
import hashlib
import logging
import random
import re
import shutil
import stat
import sys
import tempfile
import threading

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    import mock

from compat import unittest

from distlib import DistlibException
from distlib.compat import text_type, StringIO
from distlib.metadata import Metadata, METADATA_FILENAME, LEGACY_METADATA_FILENAME
from distlib.database import (InstalledDistribution, EggInfoDistribution, BaseInstalledDistribution, EXPORTS_FILENAME,
                              DistributionPath, make_graph, get_required_dists, get_dependent_dists, FileAuditResult,
                              AUDIT_MATCHED, AUDIT_TAMPERED, AUDIT_OUTSIDE_ROOTS, AUDIT_UNVERIFIED)
from distlib.util import get_resources_dests, CSVReader, read_exports

from test_util import GlobTestCaseBase
from support import LoggingCatcher, requires_zlib, DistlibTestCase

logger = logging.getLogger(__name__)

# TODO Add a test for getting a distribution provided by another distribution
# TODO Add a test for absolute path RECORD items (e.g. /etc/myapp/config.ini)
# TODO Add tests from the former pep376 project (zipped site-packages, etc.)


class FakeDistsMixin(object):

    def setUp(self):
        super(FakeDistsMixin, self).setUp()

        # make a copy that we can write into for our fake installed
        # distributions
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        self.fake_dists_path = os.path.realpath(os.path.join(tmpdir, 'fake_dists'))
        fake_dists_src = os.path.abspath(os.path.join(os.path.dirname(__file__), 'fake_dists'))
        shutil.copytree(fake_dists_src, self.fake_dists_path)
        # XXX ugly workaround: revert copystat calls done by shutil behind our
        # back (to avoid getting a read-only copy of a read-only file).  we
        # could pass a custom copy_function to change the mode of files, but
        # shutil gives no control over the mode of directories :(
        # see http://bugs.python.org/issue1666318
        for root, dirs, files in os.walk(self.fake_dists_path):
            os.chmod(root, 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o644)
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)


class CommonDistributionTests(FakeDistsMixin):
    """Mixin used to test the interface common to InstalledDistribution
    and EggInfoDistribution classes.

    Derived classes define cls, sample_dist, dirs and records.  These
    attributes are used in test methods.  See source code for details.
    """

    def _get_dist_path(self, distdir):
        here = os.path.abspath(os.path.dirname(__file__))
        return os.path.join(here, 'fake_dists', distdir)

    def test_instantiation(self):
        # check that useful attributes are here
        name, version, distdir = self.sample_dist
        dist_path = self._get_dist_path(distdir)
        dist = self.dist = self.cls(dist_path)
        self.assertEqual(dist.path, dist_path)
        self.assertEqual(dist.name, name)
        self.assertEqual(dist.metadata.name, name)
        self.assertIsInstance(dist.metadata, Metadata)
        self.assertEqual(dist.version, version)
        self.assertEqual(dist.metadata.version, version)

    @requires_zlib
    def test_repr(self):
        dist = self.cls(self.dirs[0])
        # just check that the class name is in the repr
        self.assertIn(self.cls.__name__, repr(dist))

    @requires_zlib
    def test_str(self):
        name, version, distdir = self.sample_dist
        dist = self.cls(self._get_dist_path(distdir))
        self.assertEqual(name, dist.name)
        # Sanity test: dist.name is unicode,
        # but str output contains no u prefix.
        self.assertIsInstance(dist.name, text_type)
        self.assertEqual(version, dist.version)
        self.assertEqual(str(dist), self.expected_str_output)

    @requires_zlib
    def test_comparison(self):
        # tests for __eq__ and __hash__
        dist = self.cls(self.dirs[0])
        dist2 = self.cls(self.dirs[0])
        dist3 = self.cls(self.dirs[1])
        self.assertIn(dist, {dist: True})
        self.assertEqual(dist, dist)

        self.assertIsNot(dist, dist2)
        self.assertEqual(dist, dist2)
        self.assertNotEqual(dist, dist3)
        self.assertNotEqual(dist, ())

    def test_list_installed_files(self):
        for dir_ in self.dirs:
            dist = self.cls(dir_)
            for path, hash, size in dist.list_installed_files():
                record_data = self.records[dist.path]
                self.assertIn(path, record_data)
                self.assertEqual(hash, record_data[path][0])
                self.assertEqual(size, record_data[path][1])

    def test_hash(self):
        datalen = random.randrange(0, 500)
        data = os.urandom(datalen)
        for dir_ in self.dirs:
            dist = self.cls(dir_)
            for hasher in ('sha1', 'sha224', 'sha384', 'sha256', 'sha512', None):
                dist.hasher = hasher
                actual = dist.get_hash(data)
                if hasher is None:
                    digester = hashlib.md5(data)
                else:
                    digester = getattr(hashlib, hasher)(data)
                digest = digester.digest()
                digest = base64.urlsafe_b64encode(digest).rstrip(b'=')
                digest = digest.decode('ascii')
                if hasher is None:
                    expected = digest
                else:
                    expected = '%s=%s' % (hasher, digest)
                self.assertEqual(actual, expected)


class TestDistribution(CommonDistributionTests, DistlibTestCase):

    cls = InstalledDistribution
    sample_dist = 'choxie', '2.0.0.9', 'choxie-2.0.0.9.dist-info'
    expected_str_output = 'choxie 2.0.0.9'

    def setUp(self):

        def get_files(location):
            for path in ('REQUESTED', 'INSTALLER', LEGACY_METADATA_FILENAME, METADATA_FILENAME, EXPORTS_FILENAME):
                p = os.path.join(location + '.dist-info', path)
                if os.path.exists(p):
                    yield p
            for path, dirs, files in os.walk(location):
                for f in files:
                    yield os.path.join(path, f)

        super(TestDistribution, self).setUp()
        self.dirs = [
            os.path.join(self.fake_dists_path, f) for f in os.listdir(self.fake_dists_path) if f.endswith('.dist-info')
        ]

        self.records = {}
        for distinfo_dir in self.dirs:
            dist_location = distinfo_dir.replace('.dist-info', '')
            record_file = os.path.join(distinfo_dir, 'RECORD')

            # Write the files using write_installed_files.
            # list_installed_files should read and match.
            dist = self.cls(distinfo_dir)
            prefix = os.path.dirname(dist_location)
            dist.write_installed_files(get_files(dist_location), prefix)

            with CSVReader(path=record_file) as record_reader:
                record_data = {}
                for row in record_reader:
                    if row == []:
                        continue
                    path, hash, size = (row[:] + [None for i in range(len(row), 3)])
                    record_data[path] = hash, size
            self.records[distinfo_dir] = record_data

    def test_instantiation(self):
        super(TestDistribution, self).test_instantiation()
        self.assertIsInstance(self.dist.requested, bool)

    def test_get_distinfo_file(self):
        # Test the retrieval of dist-info file objects.
        distinfo_name = 'choxie-2.0.0.9'
        other_distinfo_name = 'grammar-1.0a4'
        distinfo_dir = os.path.join(self.fake_dists_path, distinfo_name + '.dist-info')
        dist = InstalledDistribution(distinfo_dir)
        # Test for known good file matches
        distinfo_files = [
            # Relative paths
            'INSTALLER',
            METADATA_FILENAME,
            # Absolute paths
            os.path.join(distinfo_dir, 'RECORD'),
            os.path.join(distinfo_dir, 'REQUESTED'),
        ]

        for distfile in distinfo_files:
            value = dist.get_distinfo_file(distfile)
            self.assertTrue(os.path.isfile(value))
            self.assertEqual(value, os.path.join(distinfo_dir, distfile))

        # Test an absolute path that is part of another distributions dist-info
        other_distinfo_file = os.path.join(self.fake_dists_path, other_distinfo_name + '.dist-info', 'REQUESTED')
        self.assertRaises(DistlibException, dist.get_distinfo_file, other_distinfo_file)
        # Test for a file that should not exist
        self.assertRaises(DistlibException, dist.get_distinfo_file, 'MAGICFILE')

    def test_list_distinfo_files(self):
        distinfo_name = 'towel_stuff-0.1'
        distinfo_dir = os.path.join(self.fake_dists_path, distinfo_name + '.dist-info')
        dist = InstalledDistribution(distinfo_dir)
        # Test for the iteration of the raw path
        distinfo_files = [os.path.join(distinfo_dir, filename) for filename in os.listdir(distinfo_dir)]
        found = list(dist.list_distinfo_files())
        base = self.fake_dists_path
        for i, p in enumerate(found):
            if not os.path.isabs(p):
                found[i] = os.path.join(base, p)
        self.assertEqual(sorted(found), sorted(distinfo_files))
        # Test for the iteration of local absolute paths
        distinfo_files = [os.path.join(sys.prefix, distinfo_dir, path) for path in distinfo_files]
        found = sorted(dist.list_distinfo_files())
        if os.sep != '/':
            self.assertNotIn('/', found[0])
            self.assertIn(os.sep, found[0])
        self.assertEqual(found, sorted(distinfo_files))

    def test_get_resources_path(self):
        distinfo_name = 'babar-0.1'
        distinfo_dir = os.path.join(self.fake_dists_path, distinfo_name + '.dist-info')
        dist = InstalledDistribution(distinfo_dir)
        resource_path = dist.get_resource_path('babar.png')
        self.assertEqual(resource_path, 'babar.png')
        self.assertRaises(KeyError, dist.get_resource_path, 'notexist')

    def test_check_installed_files(self):
        for dir_ in self.dirs:
            dist = self.cls(dir_)
            mismatches = dist.check_installed_files()
            self.assertEqual(mismatches, [])
            # pick a non-empty file at random and change its contents
            # but not its size. Check the failure returned,
            # then restore the file.
            files = [f for f in dist.list_installed_files() if f[-1] not in ('', '0')]
            bad_file = random.choice(files)
            bad_file_name = bad_file[0]
            if not os.path.isabs(bad_file_name):
                base = os.path.dirname(dir_)
                bad_file_name = os.path.join(base, bad_file_name)
            with open(bad_file_name, 'rb') as f:
                data = f.read()
            bad_data = bytes(bytearray(reversed(data)))
            bad_hash = dist.get_hash(bad_data)
            with open(bad_file_name, 'wb') as f:
                f.write(bad_data)
            mismatches = dist.check_installed_files()
            self.assertEqual(mismatches, [(bad_file_name, 'hash', bad_file[1], bad_hash)])
            # now truncate the file by one byte and see what's returned
            with open(bad_file_name, 'wb') as f:
                f.write(bad_data[:-1])
            bad_size = str(len(bad_data) - 1)
            mismatches = dist.check_installed_files()
            self.assertEqual(mismatches, [(bad_file_name, 'size', bad_file[2], bad_size)])

            # now remove the file and see what's returned
            os.remove(bad_file_name)
            mismatches = dist.check_installed_files()
            self.assertEqual(mismatches, [(bad_file_name, 'exists', True, False)])

            # restore the file
            with open(bad_file_name, 'wb') as f:
                f.write(data)


class TestEggInfoDistribution(CommonDistributionTests, LoggingCatcher, DistlibTestCase):

    cls = EggInfoDistribution
    sample_dist = 'bacon', '0.1', 'bacon-0.1.egg-info'
    expected_str_output = 'bacon 0.1'

    def setUp(self):
        super(TestEggInfoDistribution, self).setUp()

        self.dirs = [
            os.path.join(self.fake_dists_path, f) for f in os.listdir(self.fake_dists_path)
            if f.endswith('.egg') or f.endswith('.egg-info')
        ]

        self.records = {}
        for egginfo_dir in self.dirs:
            # dist_location = egginfo_dir.replace('.egg-info', '')
            record_file = os.path.join(egginfo_dir, 'installed-files.txt')

            # dist = self.cls(egginfo_dir)
            # prefix = os.path.dirname(dist_location)
            # dist.write_installed_files(get_files(dist_location), prefix)

            record_data = {}
            if os.path.exists(record_file):
                with open(record_file) as fp:
                    for line in fp:
                        line = line.strip()
                        if line == './':
                            break
                        record_data[line] = None, None
            self.records[egginfo_dir] = record_data

    @unittest.skip('not implemented yet')
    def test_list_installed_files(self):
        # EggInfoDistribution defines list_installed_files but there is no
        # test for it yet; someone needs to add a file with the list of
        # installed files for one of the egg fake dists and write the support
        # code to populate self.records (and then delete this method)
        pass


class TestDatabase(LoggingCatcher, FakeDistsMixin, DistlibTestCase):

    def setUp(self):
        super(TestDatabase, self).setUp()
        sys.path.insert(0, self.fake_dists_path)
        self.addCleanup(sys.path.remove, self.fake_dists_path)

    def test_caches(self):
        # sanity check for internal caches
        d = DistributionPath()
        for name in ('_cache', '_cache_egg'):
            self.assertEqual(getattr(d, name).name, {})
            self.assertEqual(getattr(d, name).path, {})

    def test_distinfo_dirname(self):
        # Given a name and a version, we expect the distinfo_dirname function
        # to return a standard distribution information directory name.

        items = [
            # (name, version, standard_dirname)
            # Test for a very simple single word name and decimal version
            # number
            ('docutils', '0.5', 'docutils-0.5.dist-info'),
            # Test for another except this time with a '-' in the name, which
            # needs to be transformed during the name lookup
            ('python-ldap', '2.5', 'python_ldap-2.5.dist-info'),
            # Test for both '-' in the name and a funky version number
            ('python-ldap', '2.5 a---5', 'python_ldap-2.5 a---5.dist-info'),
        ]

        # Loop through the items to validate the results
        for name, version, standard_dirname in items:
            dirname = DistributionPath.distinfo_dirname(name, version)
            self.assertEqual(dirname, standard_dirname)

    @requires_zlib
    def test_get_distributions(self):
        # Lookup all distributions found in the ``sys.path``.
        # This test could potentially pick up other installed distributions
        non_egg_dists = [('grammar', '1.0a4'), ('choxie', '2.0.0.9'), ('towel-stuff', '0.1'), ('babar', '0.1')]
        egg_dists = [('bacon', '0.1'), ('cheese', '2.0.2'), ('coconuts-aster', '10.3'), ('banana', '0.4'),
                     ('strawberry', '0.6'), ('truffles', '5.0'), ('nut', 'funkyversion')]

        all_dists = non_egg_dists + egg_dists

        d = DistributionPath()
        ed = DistributionPath(include_egg=True)

        cases = ((d, non_egg_dists, InstalledDistribution), (ed, all_dists, BaseInstalledDistribution))

        fake_dists_path = self.fake_dists_path
        for enabled in (True, False):
            if not enabled:
                d.cache_enabled = False
                ed.cache_enabled = False
                d.clear_cache()
                ed.clear_cache()

            for distset, fake_dists, allowed_class in cases:
                found_dists = []

                # Verify the fake dists have been found.
                dists = list(distset.get_distributions())
                for dist in dists:
                    self.assertIsInstance(dist, allowed_class)
                    if (dist.name in dict(fake_dists) and dist.path.startswith(fake_dists_path)):
                        found_dists.append((dist.name, dist.version))
                    else:
                        # check that it doesn't find anything more than this
                        self.assertFalse(dist.path.startswith(fake_dists_path))
                    # otherwise we don't care what other dists are found

                # Finally, test that we found all that we were looking for
                self.assertEqual(sorted(found_dists), sorted(fake_dists))

    @requires_zlib
    def test_get_distribution(self):
        # Test for looking up a distribution by name.
        # Test the lookup of the towel-stuff distribution
        name = 'towel-stuff'  # Note: This is different from the directory name

        d = DistributionPath()
        ed = DistributionPath(include_egg=True)

        # Lookup the distribution
        dist = d.get_distribution(name)
        self.assertIsInstance(dist, InstalledDistribution)
        self.assertEqual(dist.name, name)

        # Verify that an unknown distribution returns None
        self.assertIsNone(d.get_distribution('bogus'))

        # Verify partial name matching doesn't work
        self.assertIsNone(d.get_distribution('towel'))

        # Verify that it does not find egg-info distributions, when not
        # instructed to
        self.assertIsNone(d.get_distribution('bacon'))
        self.assertIsNone(d.get_distribution('cheese'))
        self.assertIsNone(d.get_distribution('strawberry'))
        self.assertIsNone(d.get_distribution('banana'))

        # Now check that it works well in both situations, when egg-info
        # is a file and directory respectively.

        for name in ('cheese', 'bacon', 'banana', 'strawberry'):
            dist = ed.get_distribution(name)
            self.assertIsInstance(dist, EggInfoDistribution)
            self.assertEqual(dist.name, name)

    @requires_zlib
    def test_provides(self):
        # Test for looking up distributions by what they provide
        checkLists = lambda x, y: self.assertEqual(sorted(x), sorted(y))

        d = DistributionPath()
        ed = DistributionPath(include_egg=True)

        test_list = [dist.name for dist in d.provides_distribution('truffles')]
        checkLists(test_list, ['choxie', 'towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '1.0')]
        checkLists(test_list, ['choxie', 'towel-stuff'])

        test_list = [dist.name for dist in ed.provides_distribution('truffles', '1.0')]
        checkLists(test_list, ['choxie', 'cheese', 'towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '1.1.2')]
        checkLists(test_list, ['towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '1.1')]
        checkLists(test_list, ['towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '!=1.1,<=2.0')]
        checkLists(test_list, ['choxie', 'towel-stuff'])

        test_list = [dist.name for dist in ed.provides_distribution('truffles', '!=1.1,<=2.0')]
        checkLists(test_list, ['choxie', 'bacon', 'cheese', 'towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '>1.0')]
        checkLists(test_list, ['towel-stuff'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '>1.5')]
        checkLists(test_list, [])

        test_list = [dist.name for dist in ed.provides_distribution('truffles', '>1.5')]
        checkLists(test_list, ['bacon', 'truffles'])

        test_list = [dist.name for dist in d.provides_distribution('truffles', '>=1.0')]
        checkLists(test_list, ['choxie', 'towel-stuff'])

        test_list = [dist.name for dist in ed.provides_distribution('strawberry', '0.6')]
        checkLists(test_list, ['coconuts-aster', 'strawberry'])

        test_list = [dist.name for dist in ed.provides_distribution('strawberry', '>=0.5')]
        checkLists(test_list, ['coconuts-aster', 'strawberry'])

        test_list = [dist.name for dist in ed.provides_distribution('strawberry', '>0.6')]
        checkLists(test_list, [])

        test_list = [dist.name for dist in ed.provides_distribution('banana', '0.4')]
        checkLists(test_list, ['banana', 'coconuts-aster'])

        test_list = [dist.name for dist in ed.provides_distribution('banana', '>=0.3')]
        checkLists(test_list, ['banana', 'coconuts-aster'])

        test_list = [dist.name for dist in ed.provides_distribution('banana', '!=0.4')]
        checkLists(test_list, [])

    @requires_zlib
    def test_yield_distribution(self):
        # tests the internal function _yield_distributions
        checkLists = lambda x, y: self.assertEqual(sorted(x), sorted(y))

        eggs = [('bacon', '0.1'), ('banana', '0.4'), ('strawberry', '0.6'), ('truffles', '5.0'), ('cheese', '2.0.2'),
                ('coconuts-aster', '10.3'), ('nut', 'funkyversion')]
        dists = [('choxie', '2.0.0.9'), ('grammar', '1.0a4'), ('towel-stuff', '0.1'), ('babar', '0.1')]

        d = DistributionPath(include_egg=False)
        d._include_dist = False
        checkLists([], d._yield_distributions())

        d = DistributionPath(include_egg=True)
        d._include_dist = False
        found = [(dist.name, dist.version) for dist in d._yield_distributions()
                 if dist.path.startswith(self.fake_dists_path)]
        checkLists(eggs, found)

        d = DistributionPath()
        found = [(dist.name, dist.version) for dist in d._yield_distributions()
                 if dist.path.startswith(self.fake_dists_path)]
        checkLists(dists, found)

        d = DistributionPath(include_egg=True)
        found = [(dist.name, dist.version) for dist in d._yield_distributions()
                 if dist.path.startswith(self.fake_dists_path)]
        checkLists(dists + eggs, found)

    def check_entry(self, entry, name, prefix, suffix, flags):
        self.assertEqual(entry.name, name)
        self.assertEqual(entry.prefix, prefix)
        self.assertEqual(entry.suffix, suffix)
        self.assertEqual(entry.flags, flags)

    def test_read_exports(self):
        d = DistributionPath().get_distribution('babar')
        r = d.exports
        self.assertIn('foo', r)
        d = r['foo']
        self.assertIn('bar', d)
        self.check_entry(d['bar'], 'bar', 'baz', 'barbaz', ['a=10', 'b'])
        self.assertIn('bar.baz', r)
        d = r['bar.baz']
        self.assertIn('foofoo', d)
        self.check_entry(d['foofoo'], 'foofoo', 'baz.foo', 'bazbar', [])
        self.assertIn('real', d)
        e = d['real']
        self.check_entry(e, 'real', 'cgi', 'print_directory', [])
        if sys.version_info[:2] < (3, 12):
            import cgi
            self.assertIs(e.value, cgi.print_directory)

        # See issue #78. Test reading an entry_points.txt with leading spaces

        TEST_EXPORTS = b"""
        [paste.server_runner]
        main = waitress:serve_paste
        [console_scripts]
        waitress-serve = waitress.runner:run
        """
        with io.BytesIO(TEST_EXPORTS) as f:
            exports = read_exports(f)
        self.assertEqual(set(exports.keys()), set(['paste.server_runner', 'console_scripts']))

    def test_exports_iteration(self):
        d = DistributionPath()
        expected = set((
            ('bar', 'baz', 'barbaz', ('a=10', 'b')),
            ('bar', 'crunchie', None, ()),
            ('bar', 'towel', 'towel', ()),
            ('baz', 'towel', 'beach_towel', ()),
        ))
        entries = list(d.get_exported_entries('foo'))
        for e in entries:
            t = e.name, e.prefix, e.suffix, tuple(e.flags)
            self.assertIn(t, expected)
            expected.remove(t)
        self.assertFalse(expected)  # nothing left
        expected = set((
            ('bar', 'baz', 'barbaz', ('a=10', 'b')),
            ('bar', 'crunchie', None, ()),
            ('bar', 'towel', 'towel', ()),
        ))
        entries = list(d.get_exported_entries('foo', 'bar'))
        for e in entries:
            t = e.name, e.prefix, e.suffix, tuple(e.flags)
            self.assertIn(t, expected)
            expected.remove(t)
        self.assertFalse(expected)  # nothing left

        expected = set((
            ('foofoo', 'baz.foo', 'bazbar', ()),
            ('real', 'cgi', 'print_directory', ()),
            ('foofoo', 'ferrero', 'rocher', ()),
            ('foobar', 'hoopy', 'frood', ('dent', )),
        ))
        entries = list(d.get_exported_entries('bar.baz'))
        for e in entries:
            t = e.name, e.prefix, e.suffix, tuple(e.flags)
            self.assertIn(t, expected)
            expected.remove(t)
        self.assertFalse(expected)  # nothing left

    def test_modules(self):
        dp = DistributionPath(include_egg=True)
        dist = dp.get_distribution('banana')
        self.assertIsInstance(dist, EggInfoDistribution)
        self.assertEqual(dist.modules, ['banana', 'cavendish'])


class DataFilesTestCase(GlobTestCaseBase):

    def assertRulesMatch(self, rules, spec):
        tempdir = self.build_files_tree(spec)
        expected = self.clean_tree(spec)
        result = get_resources_dests(tempdir, rules)
        self.assertEqual(expected, result)

    def clean_tree(self, spec):
        files = {}
        for path, value in spec.items():
            if value is not None:
                files[path] = value
        return files

    def test_simple_glob(self):
        rules = [('', '*.tpl', '{data}')]
        spec = {'coucou.tpl': '{data}/coucou.tpl', 'Donotwant': None}
        self.assertRulesMatch(rules, spec)

    def test_multiple_match(self):
        rules = [('scripts', '*.bin', '{appdata}'), ('scripts', '*', '{appscript}')]
        spec = {'scripts/script.bin': '{appscript}/script.bin', 'Babarlikestrawberry': None}
        self.assertRulesMatch(rules, spec)

    def test_set_match(self):
        rules = [('scripts', '*.{bin,sh}', '{appscript}')]
        spec = {
            'scripts/script.bin': '{appscript}/script.bin',
            'scripts/babar.sh': '{appscript}/babar.sh',
            'Babarlikestrawberry': None
        }
        self.assertRulesMatch(rules, spec)

    def test_set_match_multiple(self):
        rules = [('scripts', 'script{s,}.{bin,sh}', '{appscript}')]
        spec = {
            'scripts/scripts.bin': '{appscript}/scripts.bin',
            'scripts/script.sh': '{appscript}/script.sh',
            'Babarlikestrawberry': None
        }
        self.assertRulesMatch(rules, spec)

    def test_set_match_exclude(self):
        rules = [('scripts', '*', '{appscript}'), ('', os.path.join('**', '*.sh'), None)]
        spec = {
            'scripts/scripts.bin': '{appscript}/scripts.bin',
            'scripts/script.sh': None,
            'Babarlikestrawberry': None
        }
        self.assertRulesMatch(rules, spec)

    def test_glob_in_base(self):
        rules = [('scrip*', '*.bin', '{appscript}')]
        spec = {
            'scripts/scripts.bin': '{appscript}/scripts.bin',
            'scripouille/babar.bin': '{appscript}/babar.bin',
            'scriptortu/lotus.bin': '{appscript}/lotus.bin',
            'Babarlikestrawberry': None
        }
        self.assertRulesMatch(rules, spec)

    def test_recursive_glob(self):
        rules = [('', os.path.join('**', '*.bin'), '{binary}')]
        spec = {
            'binary0.bin': '{binary}/binary0.bin',
            'scripts/binary1.bin': '{binary}/scripts/binary1.bin',
            'scripts/bin/binary2.bin': '{binary}/scripts/bin/binary2.bin',
            'you/kill/pandabear.guy': None
        }
        self.assertRulesMatch(rules, spec)

    def test_final_example_glob(self):
        rules = [
            ('mailman/database/schemas/', '*', '{appdata}/schemas'),
            ('', os.path.join('**', '*.tpl'), '{appdata}/templates'),
            ('', os.path.join('developer-docs', '**', '*.txt'), '{doc}'),
            ('', 'README', '{doc}'),
            ('mailman/etc/', '*', '{config}'),
            ('mailman/foo/', os.path.join('**', 'bar', '*.cfg'), '{config}/baz'),
            ('mailman/foo/', os.path.join('**', '*.cfg'), '{config}/hmm'),
            ('', 'some-new-semantic.sns', '{funky-crazy-category}'),
        ]
        spec = {
            'README': '{doc}/README',
            'some.tpl': '{appdata}/templates/some.tpl',
            'some-new-semantic.sns': '{funky-crazy-category}/some-new-semantic.sns',
            'mailman/database/mailman.db': None,
            'mailman/database/schemas/blah.schema': '{appdata}/schemas/blah.schema',
            'mailman/etc/my.cnf': '{config}/my.cnf',
            'mailman/foo/some/path/bar/my.cfg': '{config}/hmm/some/path/bar/my.cfg',
            'mailman/foo/some/path/other.cfg': '{config}/hmm/some/path/other.cfg',
            'developer-docs/index.txt': '{doc}/developer-docs/index.txt',
            'developer-docs/api/toc.txt': '{doc}/developer-docs/api/toc.txt',
        }
        self.maxDiff = None
        self.assertRulesMatch(rules, spec)

    def test_get_file(self):
        # Create a fake dist
        temp_site_packages = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_site_packages)

        dist_name = 'test'
        dist_info = os.path.join(temp_site_packages, 'test-0.1.dist-info')
        os.mkdir(dist_info)

        metadata_path = os.path.join(dist_info, 'pydist.json')
        resources_path = os.path.join(dist_info, 'RESOURCES')
        md = Metadata()
        md.name = 'test'
        md.version = '0.1'
        md.summary = 'test'
        md.write(path=metadata_path)
        test_path = 'test.cfg'

        fd, test_resource_path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.remove, test_resource_path)

        fp = open(test_resource_path, 'w')
        try:
            fp.write('Config')
        finally:
            fp.close()

        fp = open(resources_path, 'w')
        try:
            fp.write('%s,%s' % (test_path, test_resource_path))
        finally:
            fp.close()

        # Add fake site-packages to sys.path to retrieve fake dist
        self.addCleanup(sys.path.remove, temp_site_packages)
        sys.path.insert(0, temp_site_packages)

        # Try to retrieve resources paths and files
        d = DistributionPath()
        self.assertEqual(d.get_file_path(dist_name, test_path), test_resource_path)
        self.assertRaises(KeyError, d.get_file_path, dist_name, 'i-dont-exist')


class DepGraphTestCase(LoggingCatcher, DistlibTestCase):

    DISTROS_DIST = ('choxie', 'grammar', 'towel-stuff')
    DISTROS_EGG = ('bacon', 'banana', 'strawberry', 'cheese')
    BAD_EGGS = ('nut', )

    EDGE = re.compile(r'"(?P<from>.*)" -> "(?P<to>.*)" \[label="(?P<label>.*)"\]')

    def checkLists(self, l1, l2):
        """ Compare two lists without taking the order into consideration """
        self.assertListEqual(sorted(l1), sorted(l2))

    def setUp(self):
        super(DepGraphTestCase, self).setUp()
        path = os.path.join(os.path.dirname(__file__), 'fake_dists')
        path = os.path.abspath(path)
        sys.path.insert(0, path)
        self.addCleanup(sys.path.remove, path)

    def get_dists(self, names, include_egg=False):
        dists = []
        d = DistributionPath(include_egg=include_egg)
        for name in names:
            dist = d.get_distribution(name)
            self.assertNotEqual(dist, None)
            dists.append(dist)
        return dists

    def test_make_graph(self):
        dists = self.get_dists(self.DISTROS_DIST)

        choxie, grammar, towel = dists

        graph = make_graph(dists)

        deps = [(x.name, y) for x, y in graph.adjacency_list[choxie]]
        self.checkLists([('towel-stuff', 'towel-stuff (0.1)')], deps)
        self.assertIn(choxie, graph.reverse_list[towel])
        self.checkLists(graph.missing[choxie], ['nut'])

        deps = [(x.name, y) for x, y in graph.adjacency_list[grammar]]
        self.checkLists([], deps)
        self.checkLists(graph.missing[grammar], ['truffles (>=1.2)'])

        deps = [(x.name, y) for x, y in graph.adjacency_list[towel]]
        self.checkLists([], deps)
        self.checkLists(graph.missing[towel], ['bacon (<=0.2)'])

    @requires_zlib
    def test_make_graph_egg(self):
        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG, True)

        choxie, grammar, towel, bacon, banana, strawberry, cheese = dists

        graph = make_graph(dists)

        deps = [(x.name, y) for x, y in graph.adjacency_list[choxie]]
        self.checkLists([('towel-stuff', 'towel-stuff (0.1)')], deps)
        self.assertIn(choxie, graph.reverse_list[towel])
        self.checkLists(graph.missing[choxie], ['nut'])

        deps = [(x.name, y) for x, y in graph.adjacency_list[grammar]]
        self.checkLists([('bacon', 'truffles (>=1.2)')], deps)
        self.checkLists(graph.missing.get(grammar, []), [])
        self.assertIn(grammar, graph.reverse_list[bacon])

        deps = [(x.name, y) for x, y in graph.adjacency_list[towel]]
        self.checkLists([('bacon', 'bacon (<=0.2)')], deps)
        self.checkLists(graph.missing.get(towel, []), [])
        self.assertIn(towel, graph.reverse_list[bacon])

        deps = [(x.name, y) for x, y in graph.adjacency_list[bacon]]
        self.checkLists([], deps)
        self.checkLists(graph.missing.get(bacon, []), [])

        deps = [(x.name, y) for x, y in graph.adjacency_list[banana]]
        self.checkLists([('strawberry', 'strawberry (>=0.5)')], deps)
        self.checkLists(graph.missing.get(banana, []), [])
        self.assertIn(banana, graph.reverse_list[strawberry])

        deps = [(x.name, y) for x, y in graph.adjacency_list[strawberry]]
        self.checkLists([], deps)
        self.checkLists(graph.missing.get(strawberry, []), [])

        deps = [(x.name, y) for x, y in graph.adjacency_list[cheese]]
        self.checkLists([], deps)
        self.checkLists(graph.missing.get(cheese, []), [])

    def test_dependent_dists(self):
        # import pdb; pdb.set_trace()
        dists = self.get_dists(self.DISTROS_DIST)

        choxie, grammar, towel = dists

        deps = [d.name for d in get_dependent_dists(dists, choxie)]
        self.checkLists([], deps)

        deps = [d.name for d in get_dependent_dists(dists, grammar)]
        self.checkLists([], deps)

        deps = [d.name for d in get_dependent_dists(dists, towel)]
        self.checkLists(['choxie'], deps)

    def test_required_dists(self):
        dists = self.get_dists(self.DISTROS_DIST + ('truffles', 'bacon', 'banana', 'coconuts-aster'), True)

        choxie, grammar, towel, truffles, bacon, banana, coco = dists

        reqs = [d.name for d in get_required_dists(dists, choxie)]
        self.checkLists(['bacon', 'towel-stuff'], reqs)

        reqs = [d.name for d in get_required_dists(dists, grammar)]
        self.checkLists(['truffles'], reqs)

        reqs = [d.name for d in get_required_dists(dists, banana)]
        self.checkLists(['coconuts-aster'], reqs)

        reqs = [d.name for d in get_required_dists(dists, towel)]
        self.checkLists(['bacon'], reqs)

        # Check the invalid case: pass a dist not in the list
        dists = dists[:-1]
        self.assertRaises(DistlibException, get_required_dists, dists, coco)

    @requires_zlib
    def test_dependent_dists_egg(self):
        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG, True)

        choxie, grammar, towel, bacon, banana, strawberry, cheese = dists

        deps = [d.name for d in get_dependent_dists(dists, choxie)]
        self.checkLists([], deps)

        deps = [d.name for d in get_dependent_dists(dists, grammar)]
        self.checkLists([], deps)

        deps = [d.name for d in get_dependent_dists(dists, towel)]
        self.checkLists(['choxie'], deps)

        deps = [d.name for d in get_dependent_dists(dists, bacon)]
        self.checkLists(['choxie', 'towel-stuff', 'grammar'], deps)

        deps = [d.name for d in get_dependent_dists(dists, strawberry)]
        self.checkLists(['banana'], deps)

        deps = [d.name for d in get_dependent_dists(dists, cheese)]
        self.checkLists([], deps)

        # Check the invalid case: pass a dist not in the list
        dists = dists[:-1]
        self.assertRaises(DistlibException, get_dependent_dists, dists, cheese)

    @requires_zlib
    def test_graph_to_dot(self):
        expected = (
            ('towel-stuff', 'bacon', 'bacon (<=0.2)'),
            ('grammar', 'bacon', 'truffles (>=1.2)'),
            ('choxie', 'towel-stuff', 'towel-stuff (0.1)'),
            ('banana', 'strawberry', 'strawberry (>=0.5)'),
        )

        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG, True)

        graph = make_graph(dists)
        buf = StringIO()
        graph.to_dot(buf)
        buf.seek(0)
        matches = []
        lines = buf.readlines()
        for line in lines[1:-1]:  # skip the first and the last lines
            if line[-1] == '\n':
                line = line[:-1]
            match = self.EDGE.match(line.strip())
            self.assertIsNot(match, None)
            matches.append(match.groups())

        self.checkLists(matches, expected)

    @requires_zlib
    def test_graph_disconnected_to_dot(self):
        dependencies_expected = (
            ('towel-stuff', 'bacon', 'bacon (<=0.2)'),
            ('grammar', 'bacon', 'truffles (>=1.2)'),
            ('choxie', 'towel-stuff', 'towel-stuff (0.1)'),
            ('banana', 'strawberry', 'strawberry (>=0.5)'),
        )
        disconnected_expected = ('cheese', 'bacon', 'strawberry')

        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG, True)

        graph = make_graph(dists)
        buf = StringIO()
        graph.to_dot(buf, skip_disconnected=False)
        buf.seek(0)
        lines = buf.readlines()

        dependencies_lines = []
        disconnected_lines = []

        # First sort output lines into dependencies and disconnected lines.
        # We also skip the attribute lines, and don't include the "{" and "}"
        # lines.
        disconnected_active = False
        for line in lines[1:-1]:  # Skip first and last line
            if line.startswith('subgraph disconnected'):
                disconnected_active = True
                continue
            if line.startswith('}') and disconnected_active:
                disconnected_active = False
                continue

            if disconnected_active:
                # Skip the 'label = "Disconnected"', etc. attribute lines.
                if ' = ' not in line:
                    disconnected_lines.append(line)
            else:
                dependencies_lines.append(line)

        dependencies_matches = []
        for line in dependencies_lines:
            if line[-1] == '\n':
                line = line[:-1]
            match = self.EDGE.match(line.strip())
            self.assertIsNot(match, None)
            dependencies_matches.append(match.groups())

        disconnected_matches = []
        for line in disconnected_lines:
            if line[-1] == '\n':
                line = line[:-1]
            line = line.strip('"')
            disconnected_matches.append(line)

        self.checkLists(dependencies_matches, dependencies_expected)
        self.checkLists(disconnected_matches, disconnected_expected)

    @requires_zlib
    def test_graph_bad_version_to_dot(self):
        expected = (
            ('towel-stuff', 'bacon', 'bacon (<=0.2)'),
            ('grammar', 'bacon', 'truffles (>=1.2)'),
            ('choxie', 'towel-stuff', 'towel-stuff (0.1)'),
            ('banana', 'strawberry', 'strawberry (>=0.5)'),
        )

        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG + self.BAD_EGGS, True)

        graph = make_graph(dists)
        buf = StringIO()
        graph.to_dot(buf)
        buf.seek(0)
        matches = []
        lines = buf.readlines()
        for line in lines[1:-1]:  # skip the first and the last lines
            if line[-1] == '\n':
                line = line[:-1]
            match = self.EDGE.match(line.strip())
            self.assertIsNot(match, None)
            matches.append(match.groups())

        self.checkLists(matches, expected)

    @requires_zlib
    def test_repr(self):
        dists = self.get_dists(self.DISTROS_DIST + self.DISTROS_EGG + self.BAD_EGGS, True)

        graph = make_graph(dists)
        self.assertTrue(repr(graph))


class RestrictedAuditTestCase(DistlibTestCase):
    """Tests for the restricted, root-bounded audit of RECORD entries."""

    def setUp(self):
        super(RestrictedAuditTestCase, self).setUp()
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)

        # A fake environment: an install root containing a package and a
        # separate, sibling script directory.
        self.prefix = os.path.join(self.tmpdir, 'env')
        self.install_root = os.path.join(self.prefix, 'lib', 'site-packages')
        self.script_dir = os.path.join(self.prefix, 'bin')
        self.outside_dir = os.path.join(self.tmpdir, 'elsewhere')
        for d in (self.install_root, self.script_dir, self.outside_dir):
            os.makedirs(d)

        self.pkg_dir = os.path.join(self.install_root, 'auditedpkg')
        os.makedirs(self.pkg_dir)
        self.module_path = os.path.join(self.pkg_dir, '__init__.py')
        with open(self.module_path, 'w') as f:
            f.write('# audited package\n')
        self.extra_path = os.path.join(self.install_root, 'data.txt')
        with open(self.extra_path, 'w') as f:
            f.write('payload\n')

        self.dist_info = os.path.join(self.install_root, 'auditedpkg-1.0.dist-info')
        os.makedirs(self.dist_info)
        with open(os.path.join(self.dist_info, METADATA_FILENAME), 'w') as f:
            f.write('Metadata-Version: 1.2\nName: auditedpkg\nVersion: 1.0\n')
        self.record_path = os.path.join(self.dist_info, 'RECORD')
        self.dist = InstalledDistribution(self.dist_info)
        self.base = self.install_root

        self.script_path = os.path.join(self.script_dir, 'audited-tool')
        with open(self.script_path, 'w') as f:
            f.write('#!/bin/sh\necho ok\n')
        os.chmod(self.script_path, 0o755)

        self.outside_path = os.path.join(self.outside_dir, 'secret.txt')
        with open(self.outside_path, 'w') as f:
            f.write('not part of any authorised root\n')

    # -- helpers ---------------------------------------------------------

    def _hash(self, data, algorithm='sha256'):
        digest = hashlib.new(algorithm, data).digest()
        return '%s=%s' % (algorithm, base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii'))

    def _record_row(self, absolute_path):
        with open(absolute_path, 'rb') as f:
            data = f.read()
        return self._rel(absolute_path), self._hash(data), str(len(data))

    def _rel(self, absolute_path):
        return os.path.relpath(absolute_path, self.base).replace(os.sep, '/')

    def _write_record(self, rows):
        with open(self.record_path, 'w') as f:
            for row in rows:
                f.write(','.join(row) + '\n')
            f.write('%s,,\n' % self._rel(self.record_path))

    def _valid_rows(self):
        return [self._record_row(self.module_path), self._record_row(self.extra_path),
                self._record_row(self.script_path)]

    def _audit(self, rows=None, **kwargs):
        if rows is None:
            rows = self._valid_rows()
        self._write_record(rows)
        options = dict(install_roots=[self.install_root], script_dirs=[self.script_dir])
        options.update(kwargs)
        return self.dist.audit_installed_files(**options)

    def _result_for(self, results, path):
        matches = [r for r in results if r.path == path]
        self.assertEqual(len(matches), 1, 'expected one result for %r, got %r' % (path, results))
        result = matches[0]
        self.assertIsInstance(result, FileAuditResult)
        return result

    # -- happy path ------------------------------------------------------

    def test_matching_entries_including_relative_script(self):
        results = self._audit()
        # the script entry uses '..' to reach the sibling bin directory
        script_entry = self._rel(self.script_path)
        self.assertIn('..', script_entry.split('/'))
        statuses = {r.path: r.status for r in results}
        self.assertEqual(set(statuses.values()), {AUDIT_MATCHED})
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertEqual(result.detail, 'ok')
            self.assertNotEqual(result.actual, None)

    def test_script_directory_must_be_authorised(self):
        # Without the script directory, the '..' reference escapes the root.
        results = self._audit(script_dirs=[])
        result = self._result_for(results, self.script_path)
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        # nothing outside an authorised root may have been read
        self.assertEqual(result.actual, os.path.realpath(self.script_path))

    def test_roots_are_required(self):
        self.assertRaises(ValueError, self.dist.audit_installed_files, install_roots=[])
        self.assertRaises(ValueError, self.dist.audit_installed_files, install_roots=[], script_dirs=[])

    def test_bad_policy_and_chunk_size(self):
        self.assertRaises(ValueError, self.dist.audit_installed_files,
                          install_roots=[self.install_root], weak_hash_policy='nope')
        self.assertRaises(ValueError, self.dist.audit_installed_files,
                          install_roots=[self.install_root], chunk_size=0)

    # -- outside-roots rejection ----------------------------------------

    def test_absolute_outside_entry_rejected_before_read(self):
        row = (self.outside_path,) + self._record_row(self.outside_path)[1:]
        results = self._audit(rows=self._valid_rows() + [row])
        result = self._result_for(results, self.outside_path)
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        self.assertEqual(result.detail, 'absolute-path')

    def test_relative_traversal_escape_rejected(self):
        outside_rel = os.path.relpath(self.outside_path, self.base).replace(os.sep, '/')
        self.assertTrue(outside_rel.startswith('../'))
        row = (outside_rel,) + self._record_row(self.outside_path)[1:]
        results = self._audit(rows=self._valid_rows() + [row])
        result = self._result_for(results, os.path.abspath(os.path.join(self.base, outside_rel)))
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        self.assertEqual(result.detail, 'outside-roots')

    def test_escaping_symlink_rejected_before_read(self):
        link_path = os.path.join(self.pkg_dir, 'sneaky-link')
        os.symlink(self.outside_path, link_path)
        row = (self._rel(link_path), '', '')
        results = self._audit(rows=self._valid_rows() + [row])
        result = self._result_for(results, link_path)
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        self.assertEqual(result.detail, 'symlink-target')
        self.assertEqual(result.actual, os.path.realpath(self.outside_path))

    def test_symlink_inside_roots_is_audited(self):
        target = os.path.join(self.pkg_dir, 'real.txt')
        with open(target, 'wb') as f:
            f.write(b'link target contents')
        link_path = os.path.join(self.pkg_dir, 'safe-link')
        os.symlink(target, link_path)
        results = self._audit(rows=self._valid_rows() + [self._record_row(link_path)])
        result = self._result_for(results, link_path)
        self.assertEqual(result.status, AUDIT_MATCHED)

    def test_dangling_symlink_inside_roots_is_tampered(self):
        link_path = os.path.join(self.pkg_dir, 'dangling')
        inside_missing = os.path.join(self.install_root, 'gone')
        os.symlink(inside_missing, link_path)
        results = self._audit(rows=self._valid_rows() + [(self._rel(link_path), '', '')])
        result = self._result_for(results, link_path)
        self.assertEqual(result.status, AUDIT_TAMPERED)
        self.assertEqual(result.detail, 'exists')

    def test_dangling_symlink_outside_roots_is_rejected(self):
        link_path = os.path.join(self.pkg_dir, 'dangling-out')
        os.symlink(os.path.join(self.outside_dir, 'missing'), link_path)
        results = self._audit(rows=self._valid_rows() + [(self._rel(link_path), '', '')])
        result = self._result_for(results, link_path)
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        self.assertEqual(result.detail, 'symlink-target')

    # -- non-regular files ----------------------------------------------

    def test_fifo_is_not_read(self):
        fifo = os.path.join(self.pkg_dir, 'pipe')
        os.mkfifo(fifo)
        results = self._audit(rows=self._valid_rows() + [(self._rel(fifo), '', '')])
        result = self._result_for(results, fifo)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'not-regular')
        # the FIFO must still be present, proving it was never opened
        self.assertTrue(stat.S_ISFIFO(os.lstat(fifo).st_mode))

    def test_fifo_read_does_not_block(self):
        fifo = os.path.join(self.pkg_dir, 'pipe')
        os.mkfifo(fifo)
        self._write_record([(self._rel(fifo), '', '')])

        def run():
            self.dist.audit_installed_files(install_roots=[self.install_root])

        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive(), 'audit blocked while opening a FIFO')

    def test_directory_member_is_unverified(self):
        directory = os.path.join(self.pkg_dir, 'subpkg')
        os.makedirs(directory)
        results = self._audit(rows=self._valid_rows() + [(self._rel(directory), '', '')])
        result = self._result_for(results, directory)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'directory')

    def test_device_link_is_not_read_as_package_file(self):
        device = os.path.join(self.pkg_dir, 'device-link')
        os.symlink('/dev/null', device)
        results = self._audit(rows=self._valid_rows() + [(self._rel(device), '', '')])
        result = self._result_for(results, device)
        self.assertEqual(result.status, AUDIT_OUTSIDE_ROOTS)
        self.assertEqual(result.detail, 'symlink-target')

    @unittest.skipIf(not (hasattr(os, 'geteuid') and os.geteuid() == 0), 'mknod requires root')
    def test_device_node_inside_roots_is_unverified(self):
        device = os.path.join(self.pkg_dir, 'null-device')
        os.mknod(device, stat.S_IFCHR | 0o644, os.makedev(3, 0))
        results = self._audit(rows=self._valid_rows() + [(self._rel(device), '', '')])
        result = self._result_for(results, device)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'not-regular')

    # -- missing / tampered files ---------------------------------------

    def test_missing_file_is_tampered(self):
        missing = os.path.join(self.pkg_dir, 'removed.py')
        row = ('auditedpkg/removed.py', self._hash(b'data'), '4')
        results = self._audit(rows=self._valid_rows() + [row])
        result = self._result_for(results, missing)
        self.assertEqual(result.status, AUDIT_TAMPERED)
        self.assertEqual(result.detail, 'exists')
        self.assertEqual(result.expected, True)
        self.assertEqual(result.actual, False)

    def test_size_mismatch_is_tampered(self):
        rows = self._valid_rows()
        good_hash = self._record_row(self.extra_path)[1]
        idx = [r[0] for r in rows].index(self._rel(self.extra_path))
        rows[idx] = (rows[idx][0], good_hash, '999')
        results = self._audit(rows=rows)
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_TAMPERED)
        self.assertEqual(result.detail, 'size')
        self.assertEqual(result.expected, 999)

    def test_hash_mismatch_is_tampered(self):
        rows = self._valid_rows()
        idx = [r[0] for r in rows].index(self._rel(self.module_path))
        rows[idx] = (rows[idx][0], self._hash(b'different content'), rows[idx][2])
        results = self._audit(rows=rows)
        result = self._result_for(results, self.module_path)
        self.assertEqual(result.status, AUDIT_TAMPERED)
        self.assertEqual(result.detail, 'hash')

    def test_same_size_change_still_detected(self):
        original = b'audited payload here'
        replacement = b'AUDITED PAYLOAD HERE'
        self.assertEqual(len(replacement), len(original))
        with open(self.module_path, 'wb') as f:
            f.write(replacement)
        rows = self._valid_rows()
        idx = [r[0] for r in rows].index(self._rel(self.module_path))
        rows[idx] = (rows[idx][0], self._hash(original), str(len(original)))
        results = self._audit(rows=rows)
        result = self._result_for(results, self.module_path)
        self.assertEqual(result.status, AUDIT_TAMPERED)
        self.assertEqual(result.detail, 'hash')

    # -- digest policies -------------------------------------------------

    def test_empty_digest_is_never_matched(self):
        rows = self._valid_rows()
        idx = [r[0] for r in rows].index(self._rel(self.extra_path))
        rows[idx] = (rows[idx][0], '', rows[idx][2])
        results = self._audit(rows=rows)
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'no-digest')
        self.assertEqual(result.actual, os.path.getsize(self.extra_path))

    def test_weak_algorithm_reported_then_allowed(self):
        with open(self.extra_path, 'rb') as f:
            data = f.read()
        weak_row = (self._rel(self.extra_path), self._hash(data, 'md5'), str(len(data)))
        rows = [r for r in self._valid_rows() if r[0] != self._rel(self.extra_path)] + [weak_row]
        results = self._audit(rows=rows)
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'weak-algorithm')
        self.assertEqual(result.expected, 'md5')

        results = self._audit(rows=rows, weak_hash_policy='allow')
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_MATCHED)

    def test_unknown_algorithm_is_unverified_even_when_weak_allowed(self):
        weird_row = (self._rel(self.extra_path), 'rot13=abcdef', '8')
        rows = [r for r in self._valid_rows() if r[0] != self._rel(self.extra_path)] + [weird_row]
        results = self._audit(rows=rows, weak_hash_policy='allow')
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'unknown-algorithm')

    def test_malformed_hash_is_unverified(self):
        weird_row = (self._rel(self.extra_path), 'noequalsign', '8')
        rows = [r for r in self._valid_rows() if r[0] != self._rel(self.extra_path)] + [weird_row]
        results = self._audit(rows=rows)
        result = self._result_for(results, self.extra_path)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'malformed-hash')

    # -- read-time failures ---------------------------------------------

    def test_file_changed_during_read_is_unverified(self):
        # A large file, rewritten with a different size after the audit's
        # initial fstat but before reading completes. The post-read fstat
        # detects the mid-audit change, so the computed hash can never be
        # trusted. The entry deliberately records no size, so the result has
        # to come from the read-time change detection rather than a size
        # comparison.
        target = os.path.join(self.pkg_dir, 'large.bin')
        original = b'a' * (65536 * 2 + 17)
        with open(target, 'wb') as f:
            f.write(original)
        target_ino = os.stat(target).st_ino
        target_row = (self._rel(target), self._hash(original), '')
        real_fstat = os.fstat
        mutated = {'done': False}

        def fstat(fd):
            result = real_fstat(fd)
            if not mutated['done'] and result.st_ino == target_ino:
                mutated['done'] = True
                before = result
                with open(target, 'wb') as f:
                    f.write(b'b' * 10)
                # Keep returning the pre-mutation stat for this descriptor,
                # mimicking the real timing where pre_stat is captured first.
                return before
            return result

        with mock.patch('distlib.database.os.fstat', side_effect=fstat):
            results = self._audit(rows=self._valid_rows() + [target_row])
        result = self._result_for(results, target)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'changed-during-read')

    def test_file_vanished_during_read_is_unverified(self):
        target = self.module_path
        target_ino = os.stat(target).st_ino
        real_fdopen = os.fdopen

        def fdopen(fd, mode='r', *args, **kwargs):
            wrapped = real_fdopen(fd, mode, *args, **kwargs)
            if os.fstat(fd).st_ino == target_ino:
                os.unlink(target)
            return wrapped

        with mock.patch('distlib.database.os.fdopen', side_effect=fdopen):
            results = self._audit()
        result = self._result_for(results, target)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'vanished')

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0, 'root bypasses permission checks')
    def test_permission_error_is_unverified(self):
        target = self.extra_path
        rows = self._valid_rows()
        real_open = os.open
        opening = {'done': False}

        def opener(path, flags, *args):
            if not opening['done'] and path == target:
                opening['done'] = True
                raise OSError(errno.EACCES, 'permission denied')
            return real_open(path, flags, *args)

        with mock.patch('distlib.database.os.open', side_effect=opener):
            results = self._audit(rows=rows)
        result = self._result_for(results, target)
        self.assertEqual(result.status, AUDIT_UNVERIFIED)
        self.assertEqual(result.detail, 'permission')

    # -- compatibility ---------------------------------------------------

    def test_legacy_interface_return_shape_unchanged(self):
        # The lightweight interface keeps returning plain mismatch tuples
        # and reports an empty list for a healthy tree.
        self._write_record(self._valid_rows())
        mismatches = self.dist.check_installed_files()
        self.assertEqual(mismatches, [])
        with open(self.module_path, 'wb') as f:
            f.write(b'tampered')
        mismatches = self.dist.check_installed_files()
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(len(mismatches[0]), 4)
        self.assertEqual(mismatches[0][1], 'size')


def test_suite():
    suite = unittest.TestSuite()
    load = unittest.defaultTestLoader.loadTestsFromTestCase
    suite.addTest(load(TestDistribution))
    suite.addTest(load(TestEggInfoDistribution))
    suite.addTest(load(TestDatabase))
    suite.addTest(load(DataFilesTestCase))
    suite.addTest(load(DepGraphTestCase))
    suite.addTest(load(RestrictedAuditTestCase))
    return suite


if __name__ == "__main__":  # pragma: no cover
    unittest.main(defaultTest='test_suite')
