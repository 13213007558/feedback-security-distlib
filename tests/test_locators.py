# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2026 Vinay Sajip.
# Licensed to the Python Software Foundation under a contributor agreement.
# See LICENSE.txt and CONTRIBUTORS.txt.
#
from __future__ import unicode_literals
import gzip
import io
import os
import posixpath
try:
    import ssl
except ImportError:
    ssl = None
import sys
import zlib

from compat import unittest
from support import DistlibTestCase

from distlib import DistlibException
from distlib.compat import url2pathname, urlparse
from distlib.database import (Distribution, DistributionPath, make_graph, make_dist)
from distlib.locators import (SimpleScrapingLocator, PyPIRPCLocator, PyPIJSONLocator, DirectoryLocator, DistPathLocator,
                              AggregatingLocator, JSONLocator, DependencyFinder, Locator, SourceRoutingPolicy, locate,
                              get_all_distribution_names, default_locator)

HERE = os.path.abspath(os.path.dirname(__file__))

PYPI_RPC_HOST = 'http://python.org/pypi'

PYPI_WEB_HOST = os.environ.get('PYPI_WEB_HOST', 'https://pypi.org/simple/')


class LocatorTestCase(DistlibTestCase):

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_xmlrpc(self):
        locator = PyPIRPCLocator(PYPI_RPC_HOST)
        try:
            try:
                result = locator.get_project('sarge')
            except Exception:  # pragma: no cover
                raise unittest.SkipTest('PyPI XML-RPC not available')
            self.assertIn('0.1', result)
            dist = result['0.1']
            self.assertEqual(dist.name, 'sarge')
            self.assertEqual(dist.version, '0.1')
            possible = ('https://pypi.org/packages/source/s/sarge/'
                        'sarge-0.1.tar.gz', 'http://pypi.org/packages/source/s/sarge/'
                        'sarge-0.1.tar.gz')
            self.assertIn(dist.source_url, possible)
            self.assertEqual(dist.digest, ('md5', '961ddd9bc085fdd8b248c6dd96ceb1c8'))
            try:
                names = locator.get_distribution_names()
            except Exception:  # pragma: no cover
                raise unittest.SkipTest('PyPI XML-RPC not available')
            self.assertGreater(len(names), 25000)
        finally:
            locator.client('close')()

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_json(self):
        locator = PyPIJSONLocator(PYPI_RPC_HOST)
        result = locator.get_project('sarge')
        LATEST_SARGE_VERSION = '0.1.4'
        LATEST_SARGE_HASHES = (
            ('md5', '285013875aa908ef1417055d3e74a00a'),
            ('sha256', '59f93216723ddd9062d17cbbb90ed9e69267b84825cf0bde0b7f8d934c424823'),
        )
        self.assertIn(LATEST_SARGE_VERSION, result)
        dist = result[LATEST_SARGE_VERSION]
        self.assertEqual(dist.name, 'sarge')
        self.assertEqual(dist.version, LATEST_SARGE_VERSION)
        path = '/sarge-%s.tar.gz' % LATEST_SARGE_VERSION
        for url in dist.download_urls:
            self.assertTrue(url.endswith(path))
        self.assertIn(dist.digests[url], LATEST_SARGE_HASHES)
        self.assertRaises(NotImplementedError, locator.get_distribution_names)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_scraper(self):
        locator = SimpleScrapingLocator('https://pypi.org/simple/')
        for name in ('sarge', 'Sarge'):
            result = locator.get_project(name)
            self.assertIn('0.1', result)
            dist = result['0.1']
            self.assertEqual(dist.name, 'sarge')
            self.assertEqual(dist.version, '0.1')
            self.assertTrue(dist.source_url.endswith('/sarge-0.1.tar.gz'))
            SARGE_HASHES = (
                ('md5', '961ddd9bc085fdd8b248c6dd96ceb1c8'),
                ('sha256', 'ec2ec0b1c9ed9a77f9b4322c16e4954c93aa00d974a1af931b18eb751e377dfe'),
            )
            self.assertIn(dist.digest, SARGE_HASHES)
        # Test to check issue #112 fix.
        locator.wheel_tags = [('cp27', 'cp27m', 'win_amd64'), ('cp35', 'cp35m', 'win32')]
        result = locator.get_project('simplejson')
        urls = result['urls'].get('3.16.0')
        self.assertTrue(urls)
        self.assertEqual(3, len(urls))
        expected = set([
            'simplejson-3.16.0-cp27-cp27m-win_amd64.whl', 'simplejson-3.16.0-cp35-cp35m-win32.whl',
            'simplejson-3.16.0.tar.gz'
        ])
        for u in urls:
            p = posixpath.split(urlparse(u).path)[-1]
            self.assertIn(p, expected)
        return
        # The following is too slow
        names = locator.get_distribution_names()
        self.assertGreater(len(names), 25000)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_unicode_project_name(self):
        # Just checking to see that no exceptions are raised.
        NAME = '\u2603'
        locator = SimpleScrapingLocator('https://pypi.org/simple/')
        result = locator.get_project(NAME)
        expected = {'urls': {}, 'digests': {}}
        self.assertEqual(result, expected)
        locator = PyPIJSONLocator('https://pypi.org/pypi/')
        result = locator.get_project(NAME)
        self.assertEqual(result, expected)

    def test_dir(self):
        d = os.path.join(HERE, 'fake_archives')
        locator = DirectoryLocator(d)
        expected = os.path.join(HERE, 'fake_archives', 'subdir', 'subsubdir', 'Flask-0.9.tar.gz')

        def get_path(url):
            t = urlparse(url)
            return url2pathname(t.path)

        for name in ('flask', 'Flask'):
            result = locator.get_project(name)
            self.assertIn('0.9', result)
            dist = result['0.9']
            self.assertEqual(dist.name, 'Flask')
            self.assertEqual(dist.version, '0.9')
            self.assertEqual(os.path.normcase(get_path(dist.source_url)), os.path.normcase(expected))
        names = locator.get_distribution_names()
        expected = set(['Flask', 'python-gnupg', 'coverage', 'Django'])
        if sys.version_info[:2] == (2, 7):
            expected.add('config')
        self.assertEqual(names, expected)

    def test_dir_nonrecursive(self):
        d = os.path.join(HERE, 'fake_archives')
        locator = DirectoryLocator(d, recursive=False)
        expected = os.path.join(HERE, 'fake_archives', 'subdir', 'subsubdir', 'Flask-0.9.tar.gz')

        def get_path(url):
            t = urlparse(url)
            return url2pathname(t.path)

        for name in ('flask', 'Flask'):
            result = locator.get_project(name)
            self.assertEqual(result, {'urls': {}, 'digests': {}})
        names = locator.get_distribution_names()
        expected = set(['coverage'])
        self.assertEqual(names, expected)

    def test_path(self):
        fakes = os.path.join(HERE, 'fake_dists')
        sys.path.insert(0, fakes)
        try:
            edp = DistributionPath(include_egg=True)
            locator = DistPathLocator(edp)
            cases = ('babar', 'choxie', 'strawberry', 'towel-stuff', 'coconuts-aster', 'bacon', 'grammar', 'truffles',
                     'banana', 'cheese')
            for name in cases:
                d = locator.locate(name, True)
                self.assertIsNotNone(d)
                r = locator.get_project(name)
                expected = {d.version: d, 'urls': {d.version: set([d.source_url])}, 'digests': {d.version: set([None])}}
                self.assertEqual(r, expected)
            d = locator.locate('nonexistent')
            self.assertIsNone(d)
            r = locator.get_project('nonexistent')
            self.assertTrue(len(r) == 2)

        finally:
            sys.path.pop(0)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_aggregation(self):
        d = os.path.join(HERE, 'fake_archives')
        loc1 = DirectoryLocator(d)
        loc2 = SimpleScrapingLocator('https://pypi.org/simple/', timeout=5.0)
        locator = AggregatingLocator(loc1, loc2)
        exp1 = os.path.join(HERE, 'fake_archives', 'subdir', 'subsubdir', 'Flask-0.9.tar.gz')
        exp2 = '/Flask-0.9.tar.gz'
        result = locator.get_project('flask')
        self.assertEqual(len(result), 3)
        self.assertIn('0.9', result)
        dist = result['0.9']
        self.assertEqual(dist.name, 'Flask')
        self.assertEqual(dist.version, '0.9')
        scheme, _, path, _, _, _ = urlparse(dist.source_url)
        self.assertEqual(scheme, 'file')
        self.assertEqual(os.path.normcase(url2pathname(path)), os.path.normcase(exp1))
        locator.merge = True
        locator._cache.clear()
        result = locator.get_project('flask')
        self.assertGreater(len(result), 3)
        self.assertIn('0.9', result)
        dist = result['0.9']
        self.assertEqual(dist.name, 'Flask')
        self.assertEqual(dist.version, '0.9')
        self.assertTrue(dist.source_url.endswith(exp2))
        return
        # The following code is slow because it has
        # to get all the dist names by scraping :-(
        n1 = loc1.get_distribution_names()
        n2 = loc2.get_distribution_names()
        self.assertEqual(locator.get_distribution_names(), n1 | n2)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    @unittest.skipIf(True, 'Optimised metadata is not up-to-date')
    def test_dependency_finder(self):
        locator = AggregatingLocator(JSONLocator(),
                                     SimpleScrapingLocator('https://pypi.org/simple/', timeout=3.0),
                                     scheme='legacy')
        finder = DependencyFinder(locator)
        dists, problems = finder.find('irc (== 5.0.1)')
        self.assertFalse(problems)
        actual = sorted([d.name for d in dists])
        self.assertEqual(actual, ['hgtools', 'irc', 'pytest-runner', 'setuptools_scm'])
        dists, problems = finder.find('irc (== 5.0.1)', meta_extras=[':test:'])
        self.assertFalse(problems)
        actual = sorted([d.name for d in dists])
        # expected = [
        # 'atomicwrites',
        # 'attrs',
        # 'colorama',
        # 'hgtools',
        # 'importlib-metadata',
        # 'irc',
        # 'more-itertools',
        # 'packaging',
        # 'pathlib2',
        # 'pluggy',
        # 'py',
        # 'pyparsing',
        # 'pytest',
        # 'pytest-runner',
        # 'setuptools',
        # 'setuptools-scm',
        # 'setuptools_scm',
        # 'six',
        # 'wcwidth'
        # ]
        expected = ['hgtools', 'irc', 'pytest', 'pytest-runner', 'setuptools_scm']
        self.assertEqual(actual, expected)
        g = make_graph(dists)
        slist, cycle = g.topological_sort()
        self.assertFalse(cycle)
        names = [d.name for d in slist]
        expected = set([
            ('atomicwrites', 'six', 'importlib-metadata', 'more-itertools', 'attrs', 'pyparsing', 'setuptools',
             'setuptools_scm', 'setuptools-scm', 'wcwidth', 'colorama', 'py', 'pathlib2', 'pluggy', 'hgtools',
             'pytest-runner', 'packaging', 'irc', 'pytest'),
            ('atomicwrites', 'setuptools', 'importlib-metadata', 'more-itertools', 'attrs', 'wcwidth', 'pyparsing',
             'colorama', 'six', 'setuptools_scm', 'setuptools-scm', 'pluggy', 'packaging', 'py', 'hgtools',
             'pytest-runner', 'pathlib2', 'irc', 'pytest'),
            ('wcwidth', 'setuptools_scm', 'colorama', 'six', 'importlib-metadata', 'setuptools', 'setuptools-scm',
             'pyparsing', 'more-itertools', 'attrs', 'atomicwrites', 'pathlib2', 'packaging', 'pytest-runner',
             'hgtools', 'py', 'pluggy', 'irc', 'pytest'),
            ('setuptools', 'setuptools-scm', 'wcwidth', 'importlib-metadata', 'colorama', 'six', 'atomicwrites',
             'more-itertools', 'attrs', 'pyparsing', 'setuptools_scm', 'pluggy', 'pathlib2', 'packaging', 'py',
             'pytest-runner', 'hgtools', 'irc', 'pytest'),
            ('atomicwrites', 'setuptools', 'importlib-metadata', 'attrs', 'wcwidth', 'more-itertools', 'pyparsing',
             'colorama', 'six', 'setuptools_scm', 'setuptools-scm', 'pluggy', 'packaging', 'hgtools', 'pytest-runner',
             'pathlib2', 'py', 'irc', 'pytest'),
            ('wcwidth', 'setuptools_scm', 'more-itertools', 'colorama', 'six', 'importlib-metadata', 'setuptools',
             'setuptools-scm', 'atomicwrites', 'pyparsing', 'attrs', 'pathlib2', 'packaging', 'pytest-runner', 'py',
             'pluggy', 'hgtools', 'irc', 'pytest'),
            ('six', 'atomicwrites', 'setuptools', 'setuptools-scm', 'attrs', 'importlib-metadata', 'more-itertools',
             'wcwidth', 'colorama', 'pyparsing', 'setuptools_scm', 'pluggy', 'packaging', 'hgtools', 'py',
             'pytest-runner', 'pathlib2', 'irc', 'pytest'),
            ('wcwidth', 'setuptools_scm', 'more-itertools', 'six', 'setuptools', 'importlib-metadata', 'pyparsing',
             'setuptools-scm', 'atomicwrites', 'colorama', 'attrs', 'pathlib2', 'packaging', 'pytest-runner', 'hgtools',
             'py', 'pluggy', 'pytest', 'irc'),
            ('atomicwrites', 'importlib-metadata', 'attrs', 'pyparsing', 'wcwidth', 'colorama', 'setuptools',
             'more-itertools', 'six', 'setuptools_scm', 'setuptools-scm', 'pluggy', 'packaging', 'hgtools',
             'pytest-runner', 'pathlib2', 'py', 'irc', 'pytest'),
            ('atomicwrites', 'pyparsing', 'six', 'setuptools', 'importlib-metadata', 'more-itertools', 'attrs',
             'setuptools_scm', 'setuptools-scm', 'wcwidth', 'colorama', 'py', 'pathlib2', 'pluggy', 'hgtools',
             'pytest-runner', 'packaging', 'irc', 'pytest'),
            ('atomicwrites', 'setuptools', 'importlib-metadata', 'more-itertools', 'attrs', 'pyparsing', 'wcwidth',
             'colorama', 'six', 'setuptools_scm', 'setuptools-scm', 'pluggy', 'packaging', 'py', 'hgtools',
             'pytest-runner', 'pathlib2', 'irc', 'pytest'),
            ('wcwidth', 'setuptools_scm', 'more-itertools', 'six', 'setuptools', 'importlib-metadata', 'pyparsing',
             'setuptools-scm', 'atomicwrites', 'attrs', 'colorama', 'pathlib2', 'packaging', 'pytest-runner', 'hgtools',
             'py', 'pluggy', 'pytest', 'irc'),
            ('six', 'atomicwrites', 'setuptools', 'setuptools-scm', 'attrs', 'importlib-metadata', 'more-itertools',
             'wcwidth', 'pyparsing', 'colorama', 'setuptools_scm', 'pluggy', 'packaging', 'hgtools', 'py',
             'pytest-runner', 'pathlib2', 'irc', 'pytest'),
            ('pytest', 'setuptools_scm', 'hgtools', 'pytest-runner', 'irc'),
            ('pytest', 'setuptools_scm', 'pytest-runner', 'hgtools', 'irc'),
            ('setuptools_scm', 'pytest', 'hgtools', 'pytest-runner', 'irc'),
        ])
        self.assertIn(tuple(names), expected)

        # Test with extras
        dists, problems = finder.find('Jinja2 (== 2.6)')
        self.assertFalse(problems)
        actual = sorted([d.name_and_version for d in dists])
        self.assertEqual(actual, ['Jinja2 (2.6)'])
        dists, problems = finder.find('Jinja2 [i18n] (== 2.6)')
        self.assertFalse(problems)
        actual = sorted([d.name_and_version for d in dists])
        self.assertEqual(actual[-2], 'Jinja2 (2.6)')
        self.assertTrue(actual[-1].startswith('pytz ('))
        self.assertTrue(actual[0].startswith('Babel ('))
        actual = [d.build_time_dependency for d in dists]
        self.assertEqual(actual, [False, False, False])

        # Now test with extra in dependency
        locator.clear_cache()
        dummy = make_dist('dummy', '0.1')
        dummy.metadata.run_requires = [{'requires': ['Jinja2 [i18n] (<2.8)']}]
        dists, problems = finder.find(dummy)
        self.assertFalse(problems)
        actual = sorted([d.name_and_version for d in dists])
        self.assertTrue(actual[0].startswith('Babel ('))
        locator.clear_cache()
        dummy.metadata.run_requires = [{'requires': ['Jinja2']}]
        dists, problems = finder.find(dummy)
        self.assertFalse(problems)
        actual = sorted([d.name_and_version for d in dists])
        self.assertTrue(actual[0].startswith('Jinja2 ('))

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_get_all_dist_names(self):
        for url in (None, PYPI_RPC_HOST):
            try:
                all_dists = get_all_distribution_names(url)
            except Exception:  # pragma: no cover
                raise unittest.SkipTest('PyPI XML-RPC not available')
            self.assertGreater(len(all_dists), 0)

    def test_url_preference(self):
        cases = (('https://netloc/path', 'http://netloc/path'), ('http://pypi.org/path', 'http://netloc/path'),
                 ('http://netloc/B', 'http://netloc/A'))
        for url1, url2 in cases:
            self.assertEqual(default_locator.prefer_url(url1, url2), url1)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_prereleases(self):
        locator = AggregatingLocator(JSONLocator(),
                                     SimpleScrapingLocator('https://pypi.org/simple/', timeout=3.0),
                                     scheme='legacy')
        REQT = 'SQLAlchemy (>0.5.8, < 0.6)'
        finder = DependencyFinder(locator)
        d = locator.locate(REQT)
        self.assertIsNone(d)
        d = locator.locate(REQT, True)
        self.assertIsNotNone(d)
        self.assertEqual(d.name_and_version, 'SQLAlchemy (0.6beta3)')
        dist = make_dist('dummy', '0.1')
        dist.metadata.run_requires = [{'requires': [REQT]}]
        dists, problems = finder.find(dist, prereleases=True)
        self.assertFalse(problems)
        actual = sorted(dists, key=lambda o: o.name_and_version)
        self.assertEqual(actual[0].name_and_version, 'SQLAlchemy (0.6beta3)')
        dists, problems = finder.find(dist)
        # Test changed since now prereleases as found as a last resort.
        # self.assertEqual(dists, set([dist]))
        # self.assertEqual(len(problems), 1)
        # problem = problems.pop()
        # self.assertEqual(problem, ('unsatisfied', REQT))
        self.assertEqual(dists, set([actual[0], dist]))
        self.assertFalse(problems)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_dist_reqts(self):
        r = 'config <=0.3.9'
        dist = default_locator.locate(r)
        self.assertIsNotNone(dist)
        self.assertIsNone(dist.extras)
        self.assertTrue(dist.matches_requirement(r))
        self.assertFalse(dist.matches_requirement('config == 0.4.0'))

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_dist_reqts_extras(self):
        r = 'config[doc,test](<=0.3.9)'
        dist = default_locator.locate(r)
        self.assertIsNotNone(dist)
        self.assertTrue(dist.matches_requirement(r))
        self.assertEqual(dist.extras, ['doc', 'test'])

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_all_versions(self):
        d = default_locator.get_project('setuptools')
        self.assertTrue('urls' in d)
        d = d['urls']
        expected = set([
            'setuptools-0.6b1.zip',
            'setuptools-0.6b2.zip',
            'setuptools-0.6b3.zip',
            'setuptools-0.6b4.zip',
            'setuptools-0.6c10.tar.gz',
            'setuptools-0.6c11.tar.gz',
            # 'setuptools-0.6c12dev-r88997.tar.gz',
            # 'setuptools-0.6c12dev-r88998.tar.gz',
            # 'setuptools-0.6c12dev-r89000.tar.gz',
            'setuptools-0.6c1.zip',
            'setuptools-0.6c2.zip',
            'setuptools-0.6c3.tar.gz',
            'setuptools-0.6c4.tar.gz',
            'setuptools-0.6c5.tar.gz',
            'setuptools-0.6c6.tar.gz',
            'setuptools-0.6c7.tar.gz',
            'setuptools-0.6c8.tar.gz',
            'setuptools-0.6c9.tar.gz',
            'setuptools-0.7.2.tar.gz',
            'setuptools-0.7.3.tar.gz',
            'setuptools-0.7.4.tar.gz',
            'setuptools-0.7.5.tar.gz',
            'setuptools-0.7.6.tar.gz',
            'setuptools-0.7.7.tar.gz',
            'setuptools-0.7.8.tar.gz',
            'setuptools-0.8.tar.gz',
            'setuptools-0.9.1.tar.gz',
            'setuptools-0.9.2.tar.gz',
            'setuptools-0.9.3.tar.gz',
            'setuptools-0.9.4.tar.gz',
            'setuptools-0.9.5.tar.gz',
            'setuptools-0.9.6.tar.gz',
            'setuptools-0.9.7.tar.gz',
            'setuptools-0.9.8.tar.gz',
            'setuptools-0.9.tar.gz',
            'setuptools-1.0.tar.gz',
            'setuptools-1.1.1.tar.gz',
            'setuptools-1.1.2.tar.gz',
            'setuptools-1.1.3.tar.gz',
            'setuptools-1.1.4.tar.gz',
            'setuptools-1.1.5.tar.gz',
            'setuptools-1.1.6.tar.gz',
            'setuptools-1.1.7.tar.gz',
            'setuptools-1.1.tar.gz',
            'setuptools-1.2.tar.gz',
            'setuptools-1.3.1.tar.gz',
            'setuptools-1.3.2.tar.gz',
            'setuptools-1.3.tar.gz',
            'setuptools-1.4.1.tar.gz',
            'setuptools-1.4.2.tar.gz',
            'setuptools-1.4.tar.gz',
            'setuptools-2.0.1.tar.gz',
            'setuptools-2.0.2.tar.gz',
            'setuptools-2.0.tar.gz',
            'setuptools-2.1.1.tar.gz',
            'setuptools-2.1.2.tar.gz',
            'setuptools-2.1.tar.gz',
            'setuptools-2.2.tar.gz',
            'setuptools-3.0.1.tar.gz',
            'setuptools-3.0.1.zip',
            'setuptools-3.0.2.tar.gz',
            'setuptools-3.0.2.zip',
            'setuptools-3.0.tar.gz',
            'setuptools-3.0.zip',
            'setuptools-3.1.tar.gz',
            'setuptools-3.1.zip',
            'setuptools-3.2.tar.gz',
            'setuptools-3.2.zip',
            'setuptools-3.3.tar.gz',
            'setuptools-3.3.zip',
            'setuptools-3.4.1.tar.gz',
            'setuptools-3.4.1.zip',
            'setuptools-3.4.2.tar.gz',
            'setuptools-3.4.2.zip',
            'setuptools-3.4.3.tar.gz',
            'setuptools-3.4.3.zip',
            'setuptools-3.4.4.tar.gz',
            'setuptools-3.4.4.zip',
            'setuptools-3.4.tar.gz',
            'setuptools-3.4.zip',
            'setuptools-3.5.1.tar.gz',
            'setuptools-3.5.1.zip',
            'setuptools-3.5.2.tar.gz',
            'setuptools-3.5.2.zip',
            'setuptools-3.5.tar.gz',
            'setuptools-3.5.zip',
            'setuptools-3.6.tar.gz',
            'setuptools-3.6.zip',
            'setuptools-3.7.1.tar.gz',
            'setuptools-3.7.1.zip',
            'setuptools-3.7.tar.gz',
            'setuptools-3.7.zip',
            'setuptools-3.8.1.tar.gz',
            'setuptools-3.8.1.zip',
            'setuptools-3.8.tar.gz',
            'setuptools-3.8.zip',
            'setuptools-4.0.1.tar.gz',
            'setuptools-4.0.1.zip',
            'setuptools-4.0.tar.gz',
            'setuptools-4.0.zip',
            'setuptools-5.0.1.tar.gz',
            'setuptools-5.0.1.zip',
            'setuptools-5.0.2.tar.gz',
            'setuptools-5.0.2.zip',
            'setuptools-5.0.tar.gz',
            'setuptools-5.0.zip',
            'setuptools-5.1.tar.gz',
            'setuptools-5.1.zip',
            'setuptools-5.2.tar.gz',
            'setuptools-5.2.zip',
            'setuptools-5.3.tar.gz',
            'setuptools-5.3.zip',
            'setuptools-5.4.1.tar.gz',
            'setuptools-5.4.1.zip',
            'setuptools-5.4.2.tar.gz',
            'setuptools-5.4.2.zip',
            'setuptools-5.4.tar.gz',
            'setuptools-5.4.zip',
            'setuptools-5.5.1.tar.gz',
            'setuptools-5.5.1.zip',
            'setuptools-5.5.tar.gz',
            'setuptools-5.5.zip',
            'setuptools-5.6.tar.gz',
            'setuptools-5.6.zip',
            'setuptools-5.7.tar.gz',
            'setuptools-5.7.zip',
            'setuptools-5.8.tar.gz',
            'setuptools-5.8.zip',
            'setuptools-6.0.1.tar.gz',
            'setuptools-6.0.1.zip',
            'setuptools-6.0.2.tar.gz',
            'setuptools-6.0.2.zip',
        ])
        actual = set()
        for k, v in d.items():
            for url in v:
                _, _, path, _, _, _ = urlparse(url)
                filename = path.rsplit('/', 1)[-1]
                actual.add(filename)
        self.assertEqual(actual & expected, expected)

    @unittest.skipIf('SKIP_ONLINE' in os.environ, 'Skipping online test')
    @unittest.skipUnless(ssl, 'SSL required for this test.')
    def test_nonexistent(self):
        # See Issue #58
        d = locate('foobarbazbishboshboo')
        self.assertTrue(d is None or isinstance(d, Distribution))

    def test_decompression_limit(self):
        """
        Test that decompression doesn't use too much memory
        """

        def make_data(payload):
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9) as f:
                f.write(payload)
            gzipped_data = buf.getvalue()
            buf = io.BytesIO()
            deflated_data = zlib.compress(payload, 9)
            return (gzipped_data, deflated_data)

        locator = SimpleScrapingLocator('https://pypi.org/simple/')
        locator.decode_size_limit = 25000
        # Deterministic, moderately compressible test data
        block = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345abcdefghijklmnopqrstuvwxyz6789+/'
        size = locator.decode_size_limit + 1  # just bigger than limit
        repetitions = (size + len(block) - 1) // len(block)
        payload = (block * repetitions)[:size]
        gzipped_data, deflated_data = make_data(payload)
        for encoding, data in (('gzip', gzipped_data), ('deflate', deflated_data)):
            decoder = locator.decoders[encoding]
            with self.assertRaises(DistlibException) as ctx:
                decoder(data)
            self.assertIn('Decompressed index response exceeds ', str(ctx.exception))

        payload = payload[:-1]  # at limit
        gzipped_data, deflated_data = make_data(payload)
        for encoding, data in (('gzip', gzipped_data), ('deflate', deflated_data), ('none', payload)):
            decoder = locator.decoders[encoding]
            actual = decoder(data)
            self.assertEqual(actual, payload)


class MemoryLocator(Locator):
    """
    An in-memory locator for routing tests. It holds an explicit mapping of
    normalized project name to a list of (version, requirements) tuples,
    counts every project query, and can be told to fail a name to simulate
    an index error.
    """

    def __init__(self, source_id, projects=None, fail_for=(), **kwargs):
        super(MemoryLocator, self).__init__(source_id=source_id, **kwargs)
        self.source_id = source_id
        self.projects = projects or {}
        self.fail_for = set(fail_for)
        self.query_counts = {}

    def _make_dist(self, name, version, requirements=()):
        dist = make_dist(name, version, scheme=self.scheme)
        dist.metadata.source_url = '%s/%s-%s.tar.gz' % (self.source_id, name, version)
        if requirements:
            dist.metadata.run_requires = [{'requires': list(requirements)}]
        dist.locator = self
        return dist

    def _get_project(self, name):
        from distlib.util import normalize_name
        key = normalize_name(name)
        self.query_counts[key] = self.query_counts.get(key, 0) + 1
        if key in self.fail_for:
            raise DistlibException('Simulated fetch failure for %r' % name)
        result = {'urls': {}, 'digests': {}}
        for project_name, version, requirements in self.projects.get(key, ()):
            dist = self._make_dist(project_name, version, requirements)
            result[version] = dist
            result['urls'].setdefault(version, set()).add(dist.source_url)
        return result

    def get_distribution_names(self):
        return set(self.projects)


class ImpersonatingLocator(MemoryLocator):
    """
    A hostile locator which returns distributions stamped with another
    locator's identity, as external metadata might self-report a trusted
    URL. Such candidates must never be accepted as coming from the trusted
    locator.
    """

    def __init__(self, source_id, stolen_identity, projects=None, **kwargs):
        super(ImpersonatingLocator, self).__init__(source_id, projects, **kwargs)
        self.stolen_identity = stolen_identity

    def _make_dist(self, name, version, requirements=()):
        dist = super(ImpersonatingLocator, self)._make_dist(name, version, requirements)
        dist.locator = self.stolen_identity
        return dist


class SourceRoutingTestCase(DistlibTestCase):

    def setUp(self):
        super(SourceRoutingTestCase, self).setUp()
        # Private index: low versions of shared names and a private-only
        # package with a transitive dependency.
        self.private = MemoryLocator('https://private.example/simple', projects={
            'shared': [('shared', '1.0', ())],
            'private-only': [('private-only', '2.0', ('shared (>=1.0)',))],
            'acme-widget': [('acme-widget', '1.0', ())],
            'acme-gadget': [('acme-gadget', '1.0', ())],
            'acme': [('acme', '1.0', ())],
            'preonly': [('preonly', '1.0a1', ())],
        })
        # Public index: higher versions of the same names, which must never
        # backfill results bound to the private index.
        self.public = MemoryLocator('https://public.example/simple', projects={
            'shared': [('shared', '9.0', ())],
            'private-only': [('private-only', '9.0', ())],
            'missing-private': [('missing-private', '9.0', ())],
            'acme-gadget': [('acme-gadget', '9.0', ())],
            'evilpkg': [('evilpkg', '9.0', ())],
            'free': [('free', '3.0', ())],
        })
        self.policy = SourceRoutingPolicy()
        self.policy.add_exact_rule('shared', self.private)
        self.policy.add_exact_rule('missing-private', self.private)
        self.policy.add_exact_rule('preonly', self.private)
        self.policy.add_prefix_rule('acme', self.private)
        self.locator = AggregatingLocator(self.private, self.public, routing_policy=self.policy)

    def test_bound_name_uses_only_bound_locator(self):
        # The private index has shared 1.0 while the public one has 9.0.
        dist = self.locator.locate('shared')
        self.assertIsNotNone(dist)
        self.assertEqual(dist.version, '1.0')
        self.assertIs(dist.locator, self.private)
        self.assertEqual(self.private.query_counts['shared'], 1)
        # The public index must never have been queried for this name.
        self.assertNotIn('shared', self.public.query_counts)
        # Normalization differences still hit the same bound rule.
        self.locator.clear_cache()
        dist = self.locator.locate('SHARED')
        self.assertEqual(dist.version, '1.0')
        self.assertNotIn('shared', self.public.query_counts)

    def test_bound_name_without_matching_version_does_not_fall_back(self):
        # The private index has shared 1.0 only; the constraint cannot be
        # met there, even though public shared 9.0 would satisfy it.
        dist = self.locator.locate('shared (>=2.0)')
        self.assertIsNone(dist)
        self.assertEqual(self.private.query_counts['shared'], 1)
        self.assertNotIn('shared', self.public.query_counts)

    def test_bound_name_missing_in_bound_locator_does_not_fall_back(self):
        # The bound private locator has no such project, while the public
        # locator does. The empty private result must be reported as-is.
        dist = self.locator.locate('missing-private')
        self.assertIsNone(dist)
        self.assertEqual(self.private.query_counts['missing-private'], 1)
        self.assertNotIn('missing-private', self.public.query_counts)

    def test_bound_name_fetch_failure_preserves_reason(self):
        failing = MemoryLocator('https://failing.example/simple', projects={},
                                fail_for=('broken',))
        policy = SourceRoutingPolicy()
        policy.add_exact_rule('broken', failing)
        locator = AggregatingLocator(failing, self.public, routing_policy=policy)
        with self.assertRaises(DistlibException) as cm:
            locator.locate('broken')
        self.assertIn('Simulated fetch failure', str(cm.exception))
        self.assertNotIn('broken', self.public.query_counts)

    def test_prefix_rules_match_normalized_names_with_priority(self):
        for name in ('acme-widget', 'ACME_Widget', 'acme.gadget', 'acme'):
            self.locator.clear_cache()
            dist = self.locator.locate(name)
            self.assertIsNotNone(dist, name)
            self.assertIs(dist.locator, self.private, name)
        self.assertNotIn('acme-widget', self.public.query_counts)
        self.assertNotIn('acme-gadget', self.public.query_counts)
        # Exact rules take precedence over prefix rules.
        other = MemoryLocator('https://other.example/simple', projects={
            'acme-widget': [('acme-widget', '5.0', ())],
        })
        policy = SourceRoutingPolicy()
        policy.add_prefix_rule('acme', self.private)
        policy.add_exact_rule('acme-widget', other)
        locator = AggregatingLocator(self.private, other, routing_policy=policy)
        dist = locator.locate('acme-widget')
        self.assertEqual(dist.version, '5.0')
        self.assertIs(dist.locator, other)
        # A more specific prefix wins over a shorter one.
        policy = SourceRoutingPolicy()
        policy.add_prefix_rule('acme', self.public)
        policy.add_prefix_rule('acme-widget', self.private)
        locator = AggregatingLocator(self.private, self.public, routing_policy=policy)
        dist = locator.locate('acme-widget')
        self.assertIs(dist.locator, self.private)
        dist = locator.locate('acme-gadget')
        self.assertIs(dist.locator, self.public)

    def test_unbound_name_keeps_aggregation_behavior(self):
        # Nothing binds 'free', so the ordinary first-success aggregation
        # path applies (the private locator has nothing for it).
        dist = self.locator.locate('free')
        self.assertIsNotNone(dist)
        self.assertEqual(dist.version, '3.0')
        self.assertIs(dist.locator, self.public)
        self.assertEqual(self.public.query_counts['free'], 1)

    def test_merge_mode_still_scoped_to_bound_locator(self):
        locator = AggregatingLocator(self.private, self.public, merge=True,
                                     routing_policy=self.policy)
        result = locator.get_project('shared')
        versions = [k for k in result if k not in ('urls', 'digests')]
        self.assertEqual(versions, ['1.0'])
        self.assertNotIn('shared', self.public.query_counts)
        # Unbound names still merge across locators.
        self.private.projects['free'] = [('free', '1.0', ())]
        locator.clear_cache()
        result = locator.get_project('free')
        self.assertIn('1.0', result)
        self.assertIn('3.0', result)

    def test_carried_source_identity_is_verifiable(self):
        dist = self.locator.locate('shared')
        self.assertTrue(self.locator.is_candidate_from(dist, self.private))
        self.assertFalse(self.locator.is_candidate_from(dist, self.public))
        # The source_id label is caller-assigned, not taken from metadata.
        self.assertEqual(dist.locator.source_id, 'https://private.example/simple')

    def test_metadata_reported_identity_cannot_impersonate_locator(self):
        hostile = ImpersonatingLocator('https://hostile.example/simple',
                                       self.private,
                                       projects={'evilpkg': [('evilpkg', '1.0', ())]})
        # Hostile is *not* part of the locator chain but is bound to the
        # name; its candidates claim the private locator's identity.
        policy = SourceRoutingPolicy()
        policy.add_exact_rule('evilpkg', hostile)
        locator = AggregatingLocator(self.private, self.public, routing_policy=policy)
        dist = locator.locate('evilpkg')
        self.assertIsNone(dist)
        self.assertTrue(locator.get_errors())
        # A hostile locator inside the chain cannot inject a shared-name
        # candidate either, and no fallback to public happens.
        hostile2 = ImpersonatingLocator('https://hostile2.example/simple',
                                        self.public,
                                        projects={'shared': [('shared', '8.0', ())]})
        policy2 = SourceRoutingPolicy()
        policy2.add_exact_rule('shared', hostile2)
        locator2 = AggregatingLocator(hostile2, self.public, routing_policy=policy2)
        dist = locator2.locate('shared')
        self.assertIsNone(dist)
        self.assertNotIn('shared', self.public.query_counts)

    def test_policy_change_invalidates_cache(self):
        policy = SourceRoutingPolicy()
        policy.add_exact_rule('shared', self.private)
        locator = AggregatingLocator(self.private, self.public, routing_policy=policy)
        dist = locator.locate('shared')
        self.assertEqual(dist.version, '1.0')
        # Rebind 'shared' to the public locator. The old private cached
        # result must not be reused.
        policy.add_exact_rule('shared', self.public)
        dist = locator.locate('shared')
        self.assertEqual(dist.version, '9.0')
        self.assertIs(dist.locator, self.public)
        # Removing routing entirely also invalidates, restoring
        # aggregation for a previously bound name.
        locator.routing_policy = None
        locator.clear_cache()
        self.private.query_counts.clear()
        self.public.query_counts.clear()
        dist = locator.locate('missing-private')
        self.assertEqual(dist.version, '9.0')

    def test_dependency_finder_direct_and_transitive_routing(self):
        finder = DependencyFinder(self.locator)
        dists, problems = finder.find('private-only (==2.0)')
        self.assertFalse(problems)
        names = dict((d.key, d) for d in dists)
        self.assertEqual(names['private-only'].version, '2.0')
        # The transitive 'shared' requirement resolves from the private
        # locator, never the public 9.0.
        self.assertEqual(names['shared'].version, '1.0')
        self.assertIs(names['shared'].locator, self.private)
        self.assertNotIn('shared', self.public.query_counts)
        self.assertNotIn('private-only', self.public.query_counts)

    def test_dependency_finder_prerelease_retry_stays_bound(self):
        finder = DependencyFinder(self.locator)
        # Only a pre-release exists, in the private locator. The
        # prerelease retry must hit the same bound locator, not public.
        dummy = make_dist('dummy', '0.1', scheme=self.locator.scheme)
        dummy.metadata.run_requires = [{'requires': ['preonly']}]
        dists, problems = finder.find(dummy)
        self.assertFalse(problems)
        names = dict((d.key, d) for d in dists)
        self.assertEqual(names['preonly'].version, '1.0a1')
        self.assertIs(names['preonly'].locator, self.private)
        # The prerelease retry re-queries the same bound locator rather
        # than falling back to the public one.
        self.assertGreaterEqual(self.private.query_counts['preonly'], 1)
        self.assertNotIn('preonly', self.public.query_counts)

    def test_dependency_finder_reuses_only_same_source_provider(self):
        finder = DependencyFinder(self.locator)
        # First satisfy 'shared' from the private locator.
        first = make_dist('root-a', '1.0', scheme=self.locator.scheme)
        first.metadata.run_requires = [{'requires': ['shared']}]
        dists, problems = finder.find(first)
        self.assertFalse(problems)
        provider = dict((d.key, d) for d in dists)['shared']
        self.assertIs(provider.locator, self.private)
        # A fresh finder with a policy binding the name to public must not
        # reuse the old private provider for a new requirement.
        policy = SourceRoutingPolicy()
        policy.add_exact_rule('shared', self.public)
        public_locator = AggregatingLocator(self.private, self.public, routing_policy=policy)
        finder2 = DependencyFinder(public_locator)
        finder2.provided = {'shared': set([(provider.version, provider)])}
        reused = finder2.find_providers('shared (>=1.0)')
        self.assertEqual(reused, set())
        # And with no policy, an existing provider is reused as before.
        unbound = AggregatingLocator(self.private, self.public)
        finder3 = DependencyFinder(unbound)
        finder3.provided = {'shared': set([(provider.version, provider)])}
        reused = finder3.find_providers('shared (>=1.0)')
        self.assertEqual(reused, set([provider]))
        # A bound policy whose locator is the provider's source still
        # allows reuse, while a different bound source rejects it.
        bound_ok = AggregatingLocator(self.private, self.public, routing_policy=self.policy)
        finder4 = DependencyFinder(bound_ok)
        finder4.provided = {'shared': set([(provider.version, provider)])}
        self.assertEqual(finder4.find_providers('shared (>=1.0)'), set([provider]))
        policy_bad = SourceRoutingPolicy()
        policy_bad.add_exact_rule('shared', self.public)
        bound_bad = AggregatingLocator(self.private, self.public, routing_policy=policy_bad)
        finder5 = DependencyFinder(bound_bad)
        finder5.provided = {'shared': set([(provider.version, provider)])}
        self.assertEqual(finder5.find_providers('shared (>=1.0)'), set())

    def test_policy_rejects_non_locator_and_empty_prefix(self):
        policy = SourceRoutingPolicy()
        with self.assertRaises(DistlibException):
            policy.add_exact_rule('foo', object())
        with self.assertRaises(DistlibException):
            policy.add_prefix_rule('foo', object())
        with self.assertRaises(DistlibException):
            policy.add_prefix_rule('', self.private)

    def test_policy_direct_matching_semantics(self):
        policy = SourceRoutingPolicy()
        policy.add_exact_rule('Exact.Name', self.private)
        policy.add_prefix_rule('acme', self.private)
        self.assertIs(policy.route('exact-name'), self.private)
        self.assertIs(policy.route('EXACT_NAME'), self.private)
        self.assertIs(policy.route('acme-widget'), self.private)
        # Prefix boundaries are whole name segments, not arbitrary strings.
        self.assertIsNone(policy.route('acmewidget'))
        self.assertIsNone(policy.route('other'))


if __name__ == '__main__':  # pragma: no cover
    import logging
    logging.basicConfig(level=logging.DEBUG, filename='run/test_locators.log', filemode='w', format='%(message)s')
    unittest.main()
