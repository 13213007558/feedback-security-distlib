# -*- coding: utf-8 -*-
#
# Copyright (C) 2012-2026 Vinay Sajip.
# Licensed to the Python Software Foundation under a contributor agreement.
# See LICENSE.txt and CONTRIBUTORS.txt.
#
from __future__ import unicode_literals

import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import warnings
try:
    import venv
except ImportError:
    venv = None

from compat import unittest
from support import DistlibTestCase

from distlib import DistlibException
from distlib.compat import fsencode, sysconfig
from distlib.scripts import ScriptMaker, enquote_executable
from distlib.util import get_executable

HERE = os.path.abspath(os.path.dirname(__file__))

COPIED_SCRIPT = '''#!python
# This is a copied script
'''

MADE_SCRIPT = 'made = dummy.module:main'


class ScriptTestCase(DistlibTestCase):

    def setUp(self):
        source_dir = os.path.join(HERE, 'scripts')
        target_dir = tempfile.mkdtemp(prefix='distlib-test-')
        self.maker = ScriptMaker(source_dir, target_dir, add_launchers=False)

    def tearDown(self):
        shutil.rmtree(self.maker.target_dir)

    @unittest.skipIf(sysconfig.is_python_build(), 'Test not appropriate for '
                     'Python source builds')
    def test_shebangs(self):
        executable = fsencode(get_executable())
        for fn in ('foo.py', 'script1.py', 'script2.py', 'script3.py', 'shell.sh'):
            files = self.maker.make(fn)
            self.assertEqual(len(files), 1)
            d, f = os.path.split(files[0])
            self.assertEqual(f, fn)
            self.assertEqual(d, self.maker.target_dir)
            if fn.endswith('.py') and fn != 'foo.py':  # no shebang in foo.py
                with open(files[0], 'rb') as f:
                    first_line = f.readline()
                self.assertIn(executable, first_line)

    def test_shebangs_custom_executable(self):
        srcdir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, srcdir)
        dstdir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, dstdir)
        maker = ScriptMaker(srcdir, dstdir, add_launchers=False)
        maker.executable = 'this_should_appear_in_the_shebang_line(中文)'
        # let's create the script to be copied. It has a vanilla shebang line,
        # with some Unicode in it.
        fn = os.path.join(srcdir, 'copied')
        with open(fn, 'w') as f:
            f.write(COPIED_SCRIPT)
        # Let's ask the maker to copy the script, and see what the shebang is
        # in the copy.
        filenames = maker.make('copied')
        with open(filenames[0], 'rb') as f:
            actual = f.readline().decode('utf-8')
        self.assertIn(maker.executable, actual)
        # Now let's make a script from a callable
        filenames = maker.make(MADE_SCRIPT)
        with open(filenames[0], 'rb') as f:
            actual = f.readline().decode('utf-8')
        self.assertIn(maker.executable, actual)

    @unittest.skipIf(os.name != 'posix', 'Test only appropriate for '
                     'POSIX systems')
    def test_custom_shebang(self):
        # Construct an executable with a space in it
        self.maker.executable = 'an executable with spaces'
        filenames = self.maker.make('script1.py')
        with open(filenames[0], 'rb') as f:
            first_line = f.readline()
            second_line = f.readline()
            third_line = f.readline()
        self.assertEqual(first_line, b'#!/bin/sh\n')
        self.assertEqual(second_line, b"'''exec' 'an executable with "
                         b"spaces' \"$0\" \"$@\"\n")
        self.assertEqual(third_line, b"' '''\n")
        # Python 3.3 cannot create a venv in an existing directory
        if venv and sys.version_info[:2] >= (3, 4):
            if sys.platform == 'darwin':
                # Supposedly 512, but various symlinks mean that temp folder
                # names get larger than you'd expect ... might vary on different
                # OS versions, too
                dlen = 220
            else:
                dlen = 127
            dstdir = tempfile.mkdtemp(suffix='cataaaaaa' + 'a' * dlen)
            self.addCleanup(shutil.rmtree, dstdir)
            bindir = os.path.join(dstdir, 'bin')
            maker = ScriptMaker(self.maker.source_dir, bindir, add_launchers=False)
            # See issue #204. Changed to use symlinks on POSIX
            venv.create(dstdir, symlinks=(os.name != 'nt'))
            maker.executable = os.path.join(bindir, 'python')
            filenames = maker.make('script8.py')
            p = subprocess.Popen(filenames[0], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            self.assertEqual(p.returncode, 0)
            self.assertEqual(stderr, b'')
            expected = os.path.realpath(maker.executable)  # symlinks on OS X
            actual = os.path.realpath(stdout.strip())
            self.assertEqual(actual, expected.encode('utf-8'))

    @unittest.skipIf(os.name != 'posix', 'Test only appropriate for '
                     'POSIX systems')
    def test_cross_env_shebang(self):
        # Construct an executable with a path that wouldn't ordinarily be a problem
        self.maker.executable = '/path/to/python3'

        # Set the cross-compiling marker attribute, then clean up.
        try:
            sys.cross_compiling = True
            filenames = self.maker.make('script1.py')
        finally:
            delattr(sys, "cross_compiling")

        with open(filenames[0], 'rb') as f:
            first_line = f.readline()
            second_line = f.readline()
            third_line = f.readline()
        self.assertEqual(first_line, b'#!/bin/sh\n')
        self.assertEqual(second_line, b"'''exec' '/path/to/python3' "
                         b'"$0" "$@"\n')
        self.assertEqual(third_line, b"' '''\n")

    @unittest.skipIf(os.name != 'posix', 'Test only appropriate for '
                     'POSIX systems')
    def test_shell_script_executable_shebang(self):
        srcdir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, srcdir)
        fake_python = os.path.join(srcdir, 'nix-python')
        with open(fake_python, 'w') as f:
            f.write('#!/bin/sh\n')
            f.write('export NIX_PYTHONPREFIX=/tmp/fake-nix-env\n')
            f.write('exec "%s" "$@"\n' % sys.executable)
        os.chmod(fake_python, 0o755)

        self.assertTrue(self.maker._is_shell(fake_python))
        self.assertFalse(self.maker._is_shell(sys.executable))
        self.assertFalse(self.maker._is_shell(os.path.join(srcdir, 'missing')))

        self.maker.executable = fake_python
        filenames = self.maker.make('script8.py')
        with open(filenames[0], 'rb') as f:
            first_line = f.readline()
            second_line = f.readline()
            third_line = f.readline()
        self.assertEqual(first_line, b'#!/bin/sh\n')
        expected_second = (b"'''exec' '" + fake_python.encode('utf-8') +
                           b"' \"$0\" \"$@\"\n")
        self.assertEqual(second_line, expected_second)
        self.assertEqual(third_line, b"' '''\n")
        p = subprocess.Popen([filenames[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        self.assertEqual(p.returncode, 0)
        self.assertEqual(stderr, b'')
        self.assertEqual(os.path.realpath(stdout.strip()),
                         os.path.realpath(sys.executable).encode('utf-8'))

    def test_multiple(self):
        specs = ('foo.py', 'script1.py', 'script2.py', 'script3.py', 'shell.sh', 'uwsgi_part')
        files = self.maker.make_multiple(specs)
        self.assertEqual(len(specs), len(files))
        expected = set(specs)
        self.assertEqual(expected, set([os.path.basename(f) for f in files]))
        ofiles = os.listdir(self.maker.target_dir)
        self.assertEqual(expected, set(ofiles))

    def test_generation(self):
        self.maker.clobber = True

        def do_test(maker, version_info):
            for name in ('main', 'other_main'):
                for options in (None, {}, {'gui': False}, {'gui': True}):
                    gui = options and options.get('gui', False)
                    spec = 'foo = foo:' + name
                    files = maker.make(spec, options)
                    self.assertEqual(len(files), 2)
                    actual = set()
                    for f in files:
                        d, f = os.path.split(f)
                        actual.add(f)
                    if os.name == 'nt':  # pragma: no cover
                        if gui:
                            ext = 'pyw'
                        else:
                            ext = 'py'
                        expected = set(['foo.%s' % ext, 'foo-%s.%s.%s' % (version_info[0], version_info[1], ext)])
                    else:
                        expected = set(['foo', 'foo-%s.%s' % (version_info[0], version_info[1])])
                    self.assertEqual(actual, expected)
                    self.assertEqual(d, maker.target_dir)
                    for fn in files:
                        with open(fn, 'r') as f:
                            text = f.read()
                        # self.assertIn("_resolve('foo', '%s')" % name, text)
                        if options and options['gui'] and os.name == 'nt':  # pragma: no cover
                            first_line, rest = text.split('\n', 1)
                            self.assertIn('pythonw', first_line)

        do_test(self.maker, sys.version_info)
        # See issue 134. Test for specifying the target Python version
        self.maker.version_info = version_info = (4, 4)  # just any other Python version
        do_test(self.maker, version_info)

    def test_clobber(self):
        files = self.maker.make('foo = foo:main')
        saved_files = files
        self.assertGreaterEqual(len(files), 2)  # foo, foo-X.Y
        files = self.maker.make('foo = foo:main')
        self.assertFalse(files)
        self.maker.clobber = True
        files = self.maker.make('foo = foo:main')
        self.assertEqual(files, saved_files)

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_launchers(self):  # pragma: no cover
        tlauncher = self.maker._get_launcher('t')
        self.maker.add_launchers = True
        specs = ('foo.py', 'script1.py', 'script2.py', 'script3.py', 'shell.sh')
        files = self.maker.make_multiple(specs)
        self.assertEqual(len(specs), len(files))
        filenames = set([os.path.basename(f) for f in files])
        self.assertEqual(filenames, set(('foo.py', 'script1.exe', 'script2.exe', 'script3.exe', 'shell.sh')))
        for fn in files:
            if not fn.endswith('.exe'):
                continue
            with open(fn, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(tlauncher))

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_launcher_write_error(self):  # pragma: no cover
        # With no existing executable to move aside, the original error must
        # be raised, not a confusing one from the .deleteme logic.
        self.maker.add_launchers = True
        error = OSError(errno.EACCES, 'Permission denied')

        def write_binary_file(path, data):
            raise error

        self.maker._fileop.write_binary_file = write_binary_file
        with self.assertRaises(OSError) as cm:
            self.maker.make('foo = foo:main')
        self.assertIs(cm.exception, error)
        self.assertEqual(os.listdir(self.maker.target_dir), [])

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_launcher_in_use(self):  # pragma: no cover
        # An existing executable that can't be overwritten (e.g. because it's
        # running) is moved aside and replaced.
        self.maker.add_launchers = True
        files = self.maker.make('foo = foo:main')
        write = self.maker._fileop.write_binary_file
        failed = []

        def write_binary_file(path, data):
            if not failed:
                failed.append(path)
                raise OSError(errno.EACCES, 'Permission denied')
            write(path, data)

        self.maker._fileop.write_binary_file = write_binary_file
        self.assertEqual(self.maker.make('foo = foo:main'), files)
        self.assertEqual(failed, files[:1])
        self.assertEqual(sorted(os.listdir(self.maker.target_dir)),
                         sorted(os.path.basename(f) for f in files))

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_launcher_run(self):
        self.maker.add_launchers = True
        files = self.maker.make('script6.py')
        self.assertEqual(len(files), 1)
        p = subprocess.Popen([files[0], 'Test Argument'],
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        stdout, stderr = p.communicate('input'.encode('ascii'))
        actual = stdout.decode('ascii').replace('\r\n', '\n')
        expected = textwrap.dedent("""
            script6.exe
            ['Test Argument']
            'input'
            non-optimized
            """).lstrip()
        self.assertEqual(actual, expected)

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_launcher_run_with_interpreter_args(self):
        srcdir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, srcdir)
        dstdir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, dstdir)
        maker = ScriptMaker(srcdir, dstdir, add_launchers=True)

        # add '-O' option to shebang to run in optimized mode
        with open(os.path.join(HERE, 'scripts', 'script6.py'), 'r') as src:
            with open(os.path.join(srcdir, 'script6-optimized.py'), 'w') as dst:
                shebang = src.readline().rstrip()
                dst.write(shebang + " -O\n")
                dst.write(src.read())

        files = maker.make('script6-optimized.py')
        self.assertEqual(len(files), 1)
        p = subprocess.Popen([files[0], 'Test Argument'],
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        stdout, stderr = p.communicate('input'.encode('ascii'))
        actual = stdout.decode('ascii').replace('\r\n', '\n')
        expected = textwrap.dedent("""
            script6-optimized.exe
            ['Test Argument']
            'input'
            """).lstrip()  # 'non-optimized' is not printed this time
        self.assertEqual(actual, expected)

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_windows(self):  # pragma: no cover
        wlauncher = self.maker._get_launcher('w')
        tlauncher = self.maker._get_launcher('t')
        self.maker.add_launchers = True
        # executable = os.path.normcase(sys.executable).encode('utf-8')
        executable = sys.executable.encode('utf-8')
        if b'python3.' in executable:
            wexecutable = executable.replace(b'python3.', b'pythonw3.')
        else:
            wexecutable = executable.replace(b'python.', b'pythonw.')
        files = self.maker.make('script4.py')
        self.assertEqual(len(files), 1)
        filenames = set([os.path.basename(f) for f in files])
        self.assertEqual(filenames, set(['script4.exe']))
        for fn in files:
            with open(fn, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(wlauncher))
            self.assertIn(executable, data)
        # Now test making scripts gui and console
        files = self.maker.make('foo = foo:main', {'gui': True})
        self.assertEqual(len(files), 2)
        filenames = set([os.path.basename(f) for f in files])
        specific = '%s.%s' % sys.version_info[:2]
        self.assertEqual(filenames, set(('foo.exe', 'foo-%s.exe' % specific)))
        for fn in files:
            with open(fn, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(wlauncher))
            self.assertIn(wexecutable, data)

        files = self.maker.make('foo = foo:main')
        self.assertEqual(len(files), 2)
        filenames = set([os.path.basename(f) for f in files])
        self.assertEqual(filenames, set(('foo.exe', 'foo-%s.exe' % specific)))
        for fn in files:
            with open(fn, 'rb') as f:
                data = f.read()
            self.assertTrue(data.startswith(tlauncher))
            self.assertIn(executable, data)

    @unittest.skipIf(os.name != 'nt', 'Test is Windows-specific')
    def test_windows_run(self):
        self.maker.add_launchers = True
        files = self.maker.make('script7.pyw')
        self.assertEqual(len(files), 1)

        test_output = os.path.join(self.maker.target_dir, 'test_output.txt')
        p = subprocess.Popen([files[0], test_output, 'Test Argument'],
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        stdout, stderr = p.communicate()
        self.assertFalse(stdout)
        self.assertFalse(stderr)
        with open(test_output, 'rb') as f:
            actual = f.read().decode('ascii')
        self.assertEqual(actual, 'Test Argument')

    def test_dry_run(self):
        self.maker.dry_run = True
        self.maker.variants = set([''])
        specs = ('foo.py', 'bar = foo:main')
        files = self.maker.make_multiple(specs)
        self.assertEqual(len(specs), len(files))
        if os.name == 'nt':  # pragma: no cover
            bar = 'bar.py'
        else:
            bar = 'bar'
        self.assertEqual(set(('foo.py', bar)), set([os.path.basename(f) for f in files]))
        ofiles = os.listdir(self.maker.target_dir)
        self.assertFalse(ofiles)

    def test_script_run(self):
        if sys.version_info[:2] < (3, 13):
            target = 'cgi:print_directory'
        else:
            target = 'logging:getHandlerNames'
        files = self.maker.make('test = %s' % target)
        self.assertEqual(len(files), 2)
        p = subprocess.Popen([sys.executable, files[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if sys.version_info[:2] < (3, 13):
            self.assertIn(b'<H3>Current Working Directory:</H3>', stdout)
            self.assertIn(os.getcwd().encode('utf-8'), stdout)
        else:
            self.assertIn(b'frozenset(', stderr)
            self.assertEqual(p.returncode, 1)

    @unittest.skipUnless(os.name == 'posix', 'Test only valid for POSIX')
    def test_mode(self):
        # save test runner's original umask and ensure default 022
        saved_umask = os.umask(0o022)
        try:
            self.maker.set_mode = False
            files = self.maker.make('foo = foo:main')
            self.assertEqual(len(files), 2)
            for f in files:
                self.assertIn(os.stat(f).st_mode & 0o7777, (0o644, 0o664))
            self.maker.set_mode = True
            files = self.maker.make('bar = bar:main')
            self.assertEqual(len(files), 2)
            for f in files:
                self.assertIn(os.stat(f).st_mode & 0o7777, (0o755, 0o775))
        finally:
            # restore the test runner's original umask
            os.umask(saved_umask)

    def test_interpreter_args(self):
        executable = fsencode(get_executable())
        options = {'interpreter_args': ['-E', '"foo bar"', 'baz frobozz']}
        self.maker.variants = set([''])
        files = self.maker.make('foo = bar:baz', options=options)
        self.assertEqual(len(files), 1)
        with open(files[0], 'rb') as f:
            shebang_line = f.readline()
        if not sysconfig.is_python_build():
            self.assertIn(executable, shebang_line)
        self.assertIn(b' -E "foo bar" baz frobozz', shebang_line)

    def test_args_on_copy(self):
        self.maker.variants = set([''])
        self.maker.executable = 'mypython'
        files = self.maker.make('script5.py')
        with open(files[0]) as f:
            actual = f.readline().strip()
        self.assertEqual(actual, '#!mypython -mzippy.activate')
        if not sysconfig.is_python_build():
            self.maker.executable = None
            os.remove(files[0])
            files = self.maker.make('script5.py')
            with open(files[0]) as f:
                actual = f.readline().strip()
            expected = '#!%s -mzippy.activate' % get_executable()
            self.assertEqual(actual, expected)

    def test_enquote_executable(self):
        for executable, expected in (('/no/spaces', '/no/spaces'), ('/i have/space', '"/i have/space"'),
                                     ('"/space prequoted"', '"/space prequoted"'),
                                     ('/usr/bin/env nospaces', '/usr/bin/env nospaces'), ('/usr/bin/env with spaces',
                                                                                          '/usr/bin/env "with spaces"'),
                                     ('/usr/bin/env "pre spaced"', '/usr/bin/env "pre spaced"')):
            self.assertEqual(enquote_executable(executable), expected)

    def test_variant_configuration(self):
        spec = 'foo = foo:main'
        files = self.maker.make(spec)
        if os.name == 'nt':
            ext = '.py'
        else:
            ext = ''
        basenames = ('foo%s' % ext, 'foo-%s.%s%s' % (self.maker.version_info[:2] + (ext, )))
        expected = set([os.path.join(self.maker.target_dir, s) for s in basenames])
        self.assertEqual(expected, set(files))
        self.maker.variant_separator = ''
        self.maker.clobber = True
        files = self.maker.make(spec)
        basenames = ('foo%s' % ext, 'foo%s.%s%s' % (self.maker.version_info[:2] + (ext, )))
        expected = set([os.path.join(self.maker.target_dir, s) for s in basenames])
        self.assertEqual(expected, set(files))

        class CustomMaker(ScriptMaker):

            def get_script_filenames(self, name):
                result = super(CustomMaker, self).get_script_filenames(name)
                if 'X.Y' in self.variants:
                    result.add('%s%s.%s' % ((name, ) + self.version_info[:2]))
                return result

        maker = CustomMaker(self.maker.source_dir, self.maker.target_dir, add_launchers=False)
        maker.clobber = True
        files = maker.make(spec)
        basenames = ('foo%s' % ext, 'foo%s.%s%s' % (self.maker.version_info[:2] + (ext, )),
                     'foo-%s.%s%s' % (self.maker.version_info[:2] + (ext, )))
        expected = set([os.path.join(self.maker.target_dir, s) for s in basenames])
        self.assertEqual(expected, set(files))
        if os.name == 'nt':
            maker.add_launchers = True
            files = maker.make(spec)
            expected = set([e.replace('.py', '.exe') for e in expected])
            self.assertEqual(expected, set(files))

    def test_path_doesnt_escape_script_dir(self):
        """
        Check that a crafted entry point name doesn't escape the scripts directory.
        """
        # First, create a directory unconnected to any script being installed and put
        # a known good script in it. Then make a script from an entry point crafted to overwrite it
        # and see if it's caught.
        known_good_dir = tempfile.mkdtemp(prefix='distlib-test-')
        self.addCleanup(shutil.rmtree, known_good_dir)
        fn = os.path.join(known_good_dir, 'known_good')
        with open(fn, 'w') as f:
            f.write('KNOWN GOOD')
        self.maker.clobber = True
        self.maker.variants = set(('',))
        specs = (
            os.path.join('..', os.path.basename(known_good_dir), 'known_good') + '=foo:bar',
            os.path.join('..', '..', os.path.basename(known_good_dir), 'known_good') + '=foo:bar',
        )
        for spec in specs:
            with self.assertRaises(DistlibException) as ctx:
                self.maker.make(spec)
            self.assertEqual(str(ctx.exception), 'Attempt to escape script directory')

class SpecialPathShebangTestCase(DistlibTestCase):
    """
    Regression tests for entry scripts whose interpreter lives in a directory
    containing spaces or other shell-sensitive characters.

    Two layers are checked:

    * the generated bytes (shebang shape and quoting) on every platform;
    * actual execution on POSIX, where the polyglot header is interpreted by
      /bin/sh. On other platforms launchers cannot be executed here, so only
      format validation is performed and nothing is claimed to have run.

    A small payload package only reports ``sys.executable`` and ``sys.argv``;
    no network or external service is involved. Shell metacharacters in the
    path are proven inert by looking for a harmless marker file that would
    only appear if a command substitution were evaluated.
    """

    entry_spec = 'specialpath_tool = specialpath_echo:main'

    # Payload written into a package on sys.path of the launched interpreter.
    payload = textwrap.dedent('''
        import json
        import sys

        def main():
            print(json.dumps({
                'executable': sys.executable,
                'argv': sys.argv,
                'optimize': sys.flags.optimize,
            }))
            return 0
    ''').lstrip()

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix='distlib-special-')
        self.target_dir = os.path.join(self.workdir, 'scripts')
        self.pkg_dir = os.path.join(self.workdir, 'pkg')
        os.makedirs(self.target_dir)
        os.makedirs(self.pkg_dir)
        with open(os.path.join(self.pkg_dir, 'specialpath_echo.py'), 'w') as f:
            f.write(self.payload)
        self.marker = os.path.join(self.workdir, 'marker-touched')
        self.maker = ScriptMaker(self.workdir, self.target_dir, add_launchers=False)
        self.maker.variants = set([''])

    def tearDown(self):
        shutil.rmtree(self.workdir, ignore_errors=True)

    # -- helpers ---------------------------------------------------------

    def make_wrapper_python(self, venv_dir):
        """
        Create a #!-script "interpreter" (which forces the /bin/sh fallback,
        because _is_shell() detects it) that delegates to the real Python.
        """
        python = os.path.join(venv_dir, 'bin', 'python')
        os.makedirs(os.path.dirname(python))
        with open(python, 'w') as f:
            f.write('#!/bin/sh\nexec "$DISTLIB_REAL_PYTHON" "$@"\n')
        os.chmod(python, 0o755)
        return python

    def make_real_python_symlink(self, venv_dir):
        """
        Create a binary symlink to the real interpreter. It is not itself a
        #!-script, so a short enough path yields the plain (non-fallback)
        shebang.
        """
        python = os.path.join(venv_dir, 'bin', 'python')
        os.makedirs(os.path.dirname(python))
        os.symlink(sys.executable, python)
        return python

    def make_deep_venv(self, leaf):
        """
        Build a venv directory whose total path exceeds the kernel shebang
        limit while keeping every individual path component short enough for
        the file system (a single >255 byte component cannot be created).
        """
        limit = 512 if sys.platform == 'darwin' else 127
        venv_dir = self.workdir
        while len(fsencode(os.path.join(venv_dir, leaf, 'bin', 'python'))) <= limit:
            venv_dir = os.path.join(venv_dir, 'd' * 100)
        venv_dir = os.path.join(venv_dir, leaf)
        return venv_dir

    def read_header(self, path, lines=3):
        with open(path, 'rb') as f:
            return [f.readline() for _ in range(lines)]

    def assert_fallback_header(self, path, executable, post_interp=b''):
        first, second, third = self.read_header(path)
        self.assertEqual(first, b'#!/bin/sh\n')
        # The executable must appear single-quoted, so no shell evaluation or
        # word splitting can touch it.
        quoted = b"'" + fsencode(executable).replace(b"'", b"'\\''") + b"'"
        self.assertEqual(second, b"'''exec' " + quoted + post_interp +
                         b' "$0" "$@"\n')
        self.assertEqual(third, b"' '''\n")
        # The whole generated file must still be valid, warning-free Python.
        with open(path, 'rb') as f:
            source = f.read()
        with warnings.catch_warnings():
            warnings.simplefilter('error', SyntaxWarning)
            compile(source, path, 'exec')

    def assert_simple_header(self, path, executable, post_interp=b''):
        first = self.read_header(path, 1)[0]
        self.assertEqual(first, b'#!' + fsencode(executable) + post_interp + b'\n')

    def run_entry(self, script, *args):
        """
        Execute a generated entry script on POSIX and decode its JSON report.
        Fails the test if the marker shows up, proving no extra command ran.
        """
        env = dict(os.environ)
        env['DISTLIB_REAL_PYTHON'] = sys.executable
        # Make the payload package importable to the delegated interpreter.
        env['PYTHONPATH'] = self.pkg_dir + os.pathsep + env.get('PYTHONPATH', '')
        # A value that must never be substituted into a path.
        env['DISTLIB_DOLLAR_VAR'] = 'MUST-NOT-EXPAND'
        proc = subprocess.Popen([script] + list(args),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=self.workdir, env=env)
        stdout, stderr = proc.communicate()
        self.assertEqual(proc.returncode, 0, stderr.decode('utf-8', 'replace'))
        self.assertEqual(stderr, b'', stderr.decode('utf-8', 'replace'))
        self.assertFalse(os.path.exists(self.marker),
                         'a shell command substitution was evaluated: marker '
                         'file %r was created' % self.marker)
        return json.loads(stdout.decode('utf-8'))

    def special_venv(self, name):
        venv_dir = os.path.join(self.workdir, name)
        return venv_dir

    # -- byte-level generation (runs on every platform) ------------------

    def test_fallback_bytes_with_spaces_and_quotes(self):
        # Spaces force the fallback; embedded quotes must be escaped, not
        # allowed to terminate the shell word.
        venv_dir = self.special_venv("venv with spaces 'quote' \"dquote\"")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        files = self.maker.make(self.entry_spec)
        self.assertEqual(len(files), 1)
        self.assert_fallback_header(files[0], python)

    def test_fallback_bytes_dollar_and_backtick_are_literal(self):
        # $ and backticks are the dangerous metacharacters: inside double
        # quotes they still expand. Single quoting must neutralise them.
        name = "venv $DISTLIB_DOLLAR_VAR `touch marker-touched` 中文"
        venv_dir = self.special_venv(name)
        python = self.make_wrapper_python(venv_dir)
        # Both code paths: explicit executable ...
        self.maker.executable = python
        files = self.maker.make(self.entry_spec)
        self.assert_fallback_header(files[0], python)
        # ... and the auto-enquoting path used by real installations, which
        # pre-wraps the path in double quotes. Both must converge on the same
        # single-quoted, expansion-proof bytes.
        os.remove(files[0])
        self.maker.executable = enquote_executable(python)
        files = self.maker.make(self.entry_spec)
        self.assert_fallback_header(files[0], python)
        with open(files[0], 'rb') as f:
            f.readline()
            second = f.readline()
        # The interpreter word is single-quoted and keeps the metacharacters
        # verbatim; the only double quotes on the line belong to "$0"/"$@".
        word = second.split(b"'''exec' ", 1)[1].split(b' "$0"', 1)[0]
        self.assertEqual(word, b"'" + fsencode(python) + b"'")
        self.assertIn(b'$DISTLIB_DOLLAR_VAR', word)
        self.assertIn(b'`touch marker-touched`', word)
        self.assertNotIn(b'"', word)

    def test_fallback_bytes_unicode_path(self):
        venv_dir = self.special_venv('虚拟环境-καλημέρα-日本語')
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        files = self.maker.make(self.entry_spec)
        self.assert_fallback_header(files[0], python)
        with open(files[0], 'rb') as f:
            self.assertIn(fsencode(python), f.read())

    def test_fallback_bytes_overlong_path(self):
        # Exceed the platform shebang limit even though the path has no
        # spaces: the length trigger must select the /bin/sh fallback too.
        limit = 512 if sys.platform == 'darwin' else 127
        venv_dir = self.make_deep_venv('long-venv')
        python = self.make_real_python_symlink(venv_dir)
        self.assertGreater(len(fsencode(python)) + 3, limit)
        self.maker.executable = python
        files = self.maker.make(self.entry_spec)
        self.assert_fallback_header(files[0], python)

    def test_simple_shebang_bytes_for_plain_short_path(self):
        venv_dir = self.special_venv('plain-venv-中文')
        python = self.make_real_python_symlink(venv_dir)
        self.maker.executable = python
        files = self.maker.make(self.entry_spec)
        self.assert_simple_header(files[0], python)

    def test_fallback_bytes_keep_interpreter_arguments(self):
        venv_dir = self.special_venv("venv with spaces")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        files = self.maker.make(self.entry_spec,
                                {'interpreter_args': ['-E', '-O']})
        # post_interp is authored argument text and stays outside the quotes.
        self.assert_fallback_header(files[0], python, b' -E -O')

    def test_entry_point_contract_unchanged(self):
        # Module/attribute names, console vs gui choice and generated file
        # names must keep their existing contract on special paths.
        venv_dir = self.special_venv("venv with spaces")
        self.make_wrapper_python(venv_dir)
        self.maker.executable = os.path.join(venv_dir, 'bin', 'python')
        self.maker.variants = set(('', 'X.Y'))
        versioned = 'foo-%s.%s' % sys.version_info[:2]
        console = self.maker.make('foo = specialpath_echo:main')
        gui = self.maker.make('foo = specialpath_echo:main', {'gui': True})
        if os.name == 'nt':  # pragma: no cover
            expected = sorted(['foo.py', versioned + '.py',
                               'foo.pyw', versioned + '.pyw'])
        else:
            # On POSIX the console/gui choice doesn't change the file name, so
            # the two calls converge on the same two entry scripts.
            expected = sorted(['foo', versioned])
        names = sorted(set(os.path.basename(p) for p in console + gui))
        self.assertEqual(names, expected)
        with open(console[0], 'rb') as f:
            text = f.read().decode('utf-8')
        self.assertIn('from specialpath_echo import main', text)
        self.assertIn('sys.exit(main())', text)

    # -- real execution (POSIX only) -------------------------------------

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_simple_shebang_preserves_argv(self):
        venv_dir = self.special_venv('plain-venv-中文')
        python = self.make_real_python_symlink(venv_dir)
        self.maker.executable = python
        script = self.maker.make(self.entry_spec)[0]
        report = self.run_entry(script, 'arg1', 'two words', '$x', '`t`')
        self.assertEqual(os.path.realpath(report['executable']),
                         os.path.realpath(sys.executable))
        self.assertEqual(report['argv'][1:],
                         ['arg1', 'two words', '$x', '`t`'])

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_spaces_quoted_and_unicode_path(self):
        venv_dir = self.special_venv("venv with spaces 'q' 中文")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        script = self.maker.make(self.entry_spec)[0]
        report = self.run_entry(script, 'hello', 'a b c')
        self.assertEqual(os.path.realpath(report['executable']),
                         os.path.realpath(sys.executable))
        self.assertEqual(report['argv'][1:], ['hello', 'a b c'])

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_dollar_backtick_are_not_evaluated(self):
        # If quoting were wrong, the backtick command would create the marker
        # and the $ variable would be expanded in the interpreter path.
        venv_dir = self.special_venv(
            "venv $DISTLIB_DOLLAR_VAR `touch marker-touched` 中文")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        script = self.maker.make(self.entry_spec)[0]
        report = self.run_entry(script, '$DISTLIB_DOLLAR_VAR',
                                '`touch marker-touched`')
        self.assertEqual(report['argv'][1:],
                         ['$DISTLIB_DOLLAR_VAR', '`touch marker-touched`'])
        self.assertFalse(os.path.exists(self.marker))

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_overlong_path_uses_shell_fallback(self):
        limit = 512 if sys.platform == 'darwin' else 127
        venv_dir = self.make_deep_venv('long-venv')
        python = self.make_real_python_symlink(venv_dir)
        self.assertGreater(len(fsencode(python)) + 3, limit)
        self.maker.executable = python
        script = self.maker.make(self.entry_spec)[0]
        self.assertEqual(self.read_header(script, 1)[0], b'#!/bin/sh\n')
        report = self.run_entry(script, 'kept-arg')
        self.assertEqual(report['argv'][1:], ['kept-arg'])

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_interpreter_arguments_reach_python(self):
        venv_dir = self.special_venv("venv with spaces")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = python
        script = self.maker.make(
            self.entry_spec, {'interpreter_args': ['-O']})[0]
        report = self.run_entry(script, 'x')
        self.assertEqual(report['optimize'], 1)
        self.assertEqual(report['argv'][1:], ['x'])

    @unittest.skipUnless(os.name == 'posix', 'real launch only runs on POSIX')
    def test_run_auto_enquoted_executable_path(self):
        # Mirrors a real installation where ScriptMaker picks sys.executable
        # and enquote_executable() wraps a path containing spaces.
        venv_dir = self.special_venv("venv $DISTLIB_DOLLAR_VAR 中文 spaces here")
        python = self.make_wrapper_python(venv_dir)
        self.maker.executable = enquote_executable(python)
        script = self.maker.make(self.entry_spec)[0]
        report = self.run_entry(script, 'one', 'two three')
        self.assertEqual(report['argv'][1:], ['one', 'two three'])


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
