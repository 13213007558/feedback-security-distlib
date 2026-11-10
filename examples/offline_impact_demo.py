# -*- coding: utf-8 -*-
"""
Runnable demonstration of the offline dependency impact analysis.

The script builds a synthetic, purely metadata-only installation inside a
temporary directory (nothing is installed into the running interpreter and no
network is used), then traces which top-level packages indirectly depend on a
watched package.

Scenario layout:

* two top-level packages: ``webportal`` and ``batchworker``
* a dependency cycle: ``cyclic-a`` <-> ``cyclic-b``
* a platform conditional branch: ``pywin32`` only on Windows markers
* an extras branch and a diamond merge through ``shared-core``
* one missing dependency and one unsatisfiable version pin, to show that
  gaps are reported as uncertainties rather than as "not affected"
"""
from __future__ import print_function

import os
import shutil
import tempfile

from distlib.impact import (analyze_impact, make_target_environment,
                            render_text_report)


def write_distinfo(site, name, version, requirements=(), provides_extra=()):
    distinfo = os.path.join(
        site, '%s-%s.dist-info' % (name.replace('-', '_'), version))
    os.makedirs(distinfo)
    lines = [
        'Metadata-Version: 2.1',
        'Name: %s' % name,
        'Version: %s' % version,
        'Summary: synthetic fixture for offline impact analysis',
    ]
    for extra in provides_extra:
        lines.append('Provides-Extra: %s' % extra)
    for requirement in requirements:
        lines.append('Requires-Dist: %s' % requirement)
    with open(os.path.join(distinfo, 'METADATA'), 'w') as f:
        f.write('\n'.join(lines) + '\n')


def build_fixture(root):
    primary = os.path.join(root, 'primary-site')
    shadow = os.path.join(root, 'shadow-site')
    os.makedirs(primary)
    os.makedirs(shadow)

    write_distinfo(primary, 'webportal', '1.0', requirements=[
        'shared-core>=1.0',
        'pywin32; sys_platform == "win32"',
        'vuln-lib[fastjson]<2; python_version < "3.12"',
    ], provides_extra=['cache'])
    write_distinfo(primary, 'batchworker', '2.0', requirements=[
        'shared-core>=1.0',
        'redis; extra == "cache"',
    ], provides_extra=['cache'])
    write_distinfo(primary, 'job-runner', '4.0',
                   requirements=['batchworker[cache]'])

    # Diamond: shared-core and redis both lead to the watched package.
    write_distinfo(primary, 'shared-core', '1.5',
                   requirements=['cyclic-a', 'vuln-lib>=1,<2'])
    write_distinfo(primary, 'cyclic-a', '0.9', requirements=['cyclic-b>=0.9'])
    write_distinfo(primary, 'cyclic-b', '0.9', requirements=['cyclic-a'])
    write_distinfo(primary, 'redis', '5.0', requirements=['vuln-lib>=1.0'])

    # The watched package itself, plus a dependency that is not installed.
    write_distinfo(primary, 'vuln-lib', '1.2.3',
                   requirements=['gone-package'],
                   provides_extra=['fastjson'])
    write_distinfo(primary, 'pywin32', '306')

    # A top-level package whose pin cannot be satisfied by what is installed.
    write_distinfo(primary, 'telemetry', '3.1',
                   requirements=['vuln-lib==2.0'])

    # A second copy of the watched name on a lower-priority path entry, to
    # force an explicit ambiguity instead of a silent choice.
    write_distinfo(shadow, 'vuln-lib', '2.5.0')
    return [primary, shadow]


def main():
    root = tempfile.mkdtemp(prefix='offline-impact-demo-')
    scan_path = build_fixture(root)
    try:
        target = make_target_environment(
            python_version='3.11', python_full_version='3.11.6',
            sys_platform='linux', os_name='posix', platform_system='Linux',
            platform_machine='x86_64', platform_release='6.5.0',
            platform_version='#1 SMP',
            platform_python_implementation='CPython',
            implementation_name='cpython',
            implementation_version='3.11.6')

        report = analyze_impact(
            scan_path, 'vuln-lib', target, watched_constraints='<2')
        print(render_text_report(report))
        print()
        print('Fixture root (deleted on exit): %s' % root)
        print('Re-run with the module CLI against a retained path, e.g.:')
        print('  python -m distlib.impact --path <primary-site> '
              '--path <shadow-site> --watched vuln-lib '
              '--constraint "<2" --python-version 3.11 '
              '--sys-platform linux')
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
