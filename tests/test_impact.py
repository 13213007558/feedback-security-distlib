# -*- coding: utf-8 -*-
#
# Tests for offline dependency impact analysis (distlib.impact).
#
from __future__ import unicode_literals

import os
import shutil
import tempfile

from compat import unittest

from distlib.impact import (
    ACTIVE, INACTIVE, UNKNOWN, AMBIGUOUS_WATCHED, BAD_MARKER, BAD_METADATA,
    MISSING_DISTRIBUTION, NAME_AMBIGUITY, UNKNOWN_EXTRA,
    UNKNOWN_MARKER_VARIABLE, UNMATCHED_WATCHED, VERSION_CONFLICT,
    ImpactException, analyze_impact, build_graph, make_target_environment,
    render_text_report,
)


class ImpactTestCase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.site = os.path.join(self.tmpdir, 'site-packages')
        os.makedirs(self.site)

    def make_dist(self, name, version, requirements=(), extras=(),
                 base=None, metadata_body=None, omit_metadata=False):
        base = base or self.site
        dirname = '%s-%s.dist-info' % (name.replace('-', '_'), version)
        distinfo = os.path.join(base, dirname)
        os.makedirs(distinfo)
        if omit_metadata:
            return distinfo
        lines = [
            'Metadata-Version: 2.1',
            'Name: %s' % name,
            'Version: %s' % version,
            'Summary: fixture for impact tests',
        ]
        for extra in extras:
            lines.append('Provides-Extra: %s' % extra)
        for requirement in requirements:
            lines.append('Requires-Dist: %s' % requirement)
        if metadata_body is not None:
            lines = metadata_body
        with open(os.path.join(distinfo, 'METADATA'), 'w') as f:
            f.write('\n'.join(lines) + '\n')
        return distinfo

    def linux_context(self, **overrides):
        context = make_target_environment(
            python_version='3.11', python_full_version='3.11.6',
            sys_platform='linux', os_name='posix', platform_system='Linux',
            platform_machine='x86_64', platform_release='6.5.0',
            platform_version='#1 SMP', platform_python_implementation='CPython',
            implementation_name='cpython', implementation_version='3.11.6')
        context.update(overrides)
        return context

    def build_fixture(self):
        # Two top-level packages.
        self.make_dist(
            'webportal', '1.0',
            [
                'shared-core>=1.0',
                'pywin32; sys_platform == "win32"',
                'vuln-lib[fastjson]<2; python_version < "3.12"',
            ],
            extras=['cache'],
        )
        self.make_dist(
            'batchworker', '2.0',
            [
                'shared-core>=1.0',
                'redis; extra == "cache"',
            ],
            extras=['cache'],
        )
        # Diamond: both top-level packages converge on shared-core, which
        # reaches the watched package through two different middlemen.
        self.make_dist('shared-core', '1.5',
                       ['cyclic-a', 'vuln-lib>=1,<2'])
        self.make_dist('cyclic-a', '0.9', ['cyclic-b>=0.9'])
        self.make_dist('cyclic-b', '0.9', ['cyclic-a'])
        self.make_dist('redis', '5.0', ['vuln-lib>=1.0'])
        self.make_dist('vuln-lib', '1.2.3', ['gone-package'],
                       extras=['fastjson'])
        self.make_dist('telemetry', '3.1', ['vuln-lib==2.0'])
        # Present but only reachable via a sys_platform marker branch.
        self.make_dist('pywin32', '306', [])
        # telemetry is a second top-level package whose pin cannot be met.
        return self.site

    def test_target_environment_rejects_host_leakage_and_unknown_vars(self):
        context = make_target_environment(python_version='3.10')
        self.assertEqual(context['python_version'], '3.10')
        self.assertNotIn('extra', context)
        self.assertNotIn('sys_platform', context)
        self.assertRaises(ImpactException, make_target_environment,
                          {'not_a_marker': 'x'})

    def test_scan_uses_metadata_without_importing_modules(self):
        self.build_fixture()
        graph = build_graph([self.site], self.linux_context())
        self.assertEqual(
            sorted(graph.by_name),
            sorted(['webportal', 'batchworker', 'shared-core', 'cyclic-a',
                    'cyclic-b', 'redis', 'vuln-lib', 'telemetry',
                    'pywin32']))
        # gone-package is a requirement only, never installed/scanned.
        self.assertNotIn('gone-package', graph.by_name)
        self.assertIn('vuln-lib', graph.by_name)

    def test_impact_finds_both_top_level_packages_and_paths(self):
        self.build_fixture()
        report = analyze_impact(
            [self.site], 'Vuln_Lib', self.linux_context(),
            watched_constraints='<2')
        roots = report.affected_roots()
        self.assertIn('webportal==1.0', roots)
        self.assertIn('batchworker==2.0', roots)
        self.assertNotIn('telemetry==3.1', roots)
        # Every reported root carries at least one complete chain of edges.
        for root in roots:
            chains = report.paths[root]
            self.assertTrue(chains)
            for chain in chains:
                self.assertTrue(all(edge.marker_verdict == ACTIVE
                                    for _key, edge in chain))
                self.assertTrue(all(edge.targets
                                    for _key, edge in chain))
        # Diamond: webportal reaches vuln-lib directly and via shared-core.
        webportal_routes = report.paths['webportal==1.0']
        lengths = sorted(len(chain) for chain in webportal_routes)
        self.assertEqual(lengths[0], 1)
        self.assertGreaterEqual(lengths[-1], 2)

    def test_markers_evaluated_against_supplied_target_only(self):
        self.build_fixture()
        linux = analyze_impact([self.site], 'pywin32',
                               self.linux_context())
        # The win32-only edge is inactive on Linux: nothing is affected.
        self.assertEqual(linux.affected_roots(), [])
        edge = linux.graph.base_edges['webportal==1.0']
        win_edge = [e for e in edge if e.req_name == 'pywin32'][0]
        self.assertEqual(win_edge.marker_verdict, INACTIVE)

        windows = self.linux_context(sys_platform='win32', os_name='nt',
                                     platform_system='Windows')
        win_report = analyze_impact([self.site], 'pywin32', windows)
        self.assertIn('webportal==1.0', win_report.affected_roots())
        edge = win_report.paths['webportal==1.0'][0][0][1]
        self.assertEqual(edge.marker_verdict, ACTIVE)
        self.assertIn('sys_platform', edge.marker_text)

    def test_python_version_marker_branch(self):
        self.build_fixture()
        py311 = analyze_impact(
            [self.site], 'vuln-lib',
            self.linux_context(python_version='3.11'),
            watched_constraints='<2')
        self.assertIn('webportal==1.0', py311.affected_roots())
        py312 = analyze_impact(
            [self.site], 'vuln-lib',
            self.linux_context(python_version='3.12',
                               python_full_version='3.12.1'))
        # webportal still reaches vuln-lib through shared-core on 3.12.
        self.assertIn('webportal==1.0', py312.affected_roots())
        direct_edges = [
            edge for chain in py312.paths.get('webportal==1.0', [])
            for _key, edge in chain
            if edge.req_name == 'vuln-lib' and len(chain) == 1
        ]
        # The direct requirement is gated on python_version < 3.12 and cannot
        # be the first edge of a proven path on a 3.12 target.
        self.assertFalse(direct_edges)
        graph = py312.graph
        inactive = [
            edge for edge in graph.base_edges['webportal==1.0']
            if edge.req_name == 'vuln-lib'
        ]
        self.assertTrue(all(edge.marker_verdict == INACTIVE
                            for edge in inactive))

    def test_cycle_terminates_and_keeps_impact_relationship(self):
        self.build_fixture()
        report = analyze_impact([self.site], 'cyclic-b',
                                self.linux_context())
        roots = report.affected_roots()
        self.assertIn('webportal==1.0', roots)
        self.assertIn('batchworker==2.0', roots)
        # No edge is repeated infinitely inside a recorded chain.
        for root in roots:
            for chain in report.paths[root]:
                raws = [edge.raw_requirement for _key, edge in chain]
                self.assertEqual(len(raws), len(set(raws)))

    def test_missing_dependency_is_uncertain_not_clean(self):
        self.build_fixture()
        report = analyze_impact([self.site], 'gone-package',
                                self.linux_context())
        kinds = [u.kind for u in report.all_uncertainties()]
        self.assertIn(MISSING_DISTRIBUTION, kinds)
        self.assertEqual(report.affected_roots(), [])

    def test_unreadable_metadata_is_reported(self):
        self.build_fixture()
        bad_dir = os.path.join(self.site, 'broken-9.9.dist-info')
        os.makedirs(bad_dir)
        with open(os.path.join(bad_dir, 'METADATA'), 'w') as f:
            f.write('Metadata-Version: 2.1\nName: broken\n')
        # A dist-info directory with no metadata file at all.
        self.make_dist('ghost', '0.1', omit_metadata=True)
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context())
        bad = [u for u in report.all_uncertainties()
               if u.kind == BAD_METADATA]
        subjects = '\n'.join(u.subject for u in bad)
        self.assertIn('broken-9.9.dist-info', subjects)
        self.assertIn('ghost-0.1.dist-info', subjects)

    def test_duplicate_name_versions_reported_as_ambiguous(self):
        self.build_fixture()
        second = os.path.join(self.tmpdir, 'later-site')
        os.makedirs(second)
        self.make_dist('vuln-lib', '2.5.0', base=second)
        report = analyze_impact([self.site, second], 'vuln-lib',
                                self.linux_context(),
                                watched_constraints='<2')
        ambiguity = [u for u in report.all_uncertainties()
                     if u.kind == NAME_AMBIGUITY and u.subject == 'vuln-lib']
        self.assertTrue(ambiguity)
        watched = [u for u in report.uncertainties
                   if u.kind == AMBIGUOUS_WATCHED]
        self.assertTrue(watched)
        # Both versions stay visible; the <2 constraint selects the 1.x line
        # without pretending 2.5.0 does not exist.
        self.assertIn('vuln-lib==1.2.3', report.watched_keys)
        self.assertNotIn('vuln-lib==2.5.0', report.watched_keys)
        self.assertIn('vuln-lib==2.5.0',
                      [u.detail for u in report.uncertainties
                       if u.kind == AMBIGUOUS_WATCHED][0])

    def test_version_conflict_is_uncertain_not_ignored(self):
        self.build_fixture()
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context(),
                                watched_constraints='==2.0')
        conflicts = [u for u in report.all_uncertainties()
                     if u.kind == VERSION_CONFLICT]
        self.assertTrue(conflicts)
        unmatched = [u for u in report.uncertainties
                     if u.kind == UNMATCHED_WATCHED]
        self.assertTrue(unmatched)

    def test_extra_gated_dependency(self):
        self.build_fixture()
        report = analyze_impact([self.site], 'redis',
                                self.linux_context())
        # redis is only required when the cache extra is active; no path
        # requests it, so it must remain a top-level package with no impact.
        self.assertEqual(report.affected_roots(), [])
        # Now request the cache extra on batchworker via an extra-aware root.
        self.make_dist(
            'job-runner', '4.0',
            ['batchworker[cache]'],
        )
        report = analyze_impact([self.site], 'redis',
                                self.linux_context())
        self.assertIn('job-runner==4.0', report.affected_roots())
        chain = report.paths['job-runner==4.0'][0]
        self.assertEqual(chain[0][1].extras, ('cache',))

    def test_unknown_extra_is_flagged(self):
        self.make_dist('app', '1.0', ['vuln-lib[nope]'])
        self.make_dist('vuln-lib', '1.0', [])
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context())
        flagged = [u for u in report.all_uncertainties()
                   if u.kind == UNKNOWN_EXTRA]
        self.assertTrue(flagged)

    def test_undeclared_extra_marker_becomes_unknown_verdict(self):
        # redis is gated on an extra the distribution never declares, so the
        # marker variable ``extra`` cannot take that value during analysis.
        self.make_dist('app', '1.0', ['redis; extra == "cache"'])
        self.make_dist('redis', '7.0', [])
        graph = build_graph([self.site], self.linux_context())
        edges = graph.all_edges()
        redis_edges = [e for e in edges if e.req_name == 'redis']
        self.assertTrue(redis_edges)
        self.assertTrue(all(e.marker_verdict == UNKNOWN
                            for e in redis_edges))
        report = analyze_impact([self.site], 'redis',
                                self.linux_context())
        self.assertTrue(any(u.kind == UNKNOWN_MARKER_VARIABLE
                            for u in report.all_uncertainties()))

    def test_malformed_marker_is_an_uncertainty_but_keeps_the_dist(self):
        # A bad marker parses lazily, so the distribution itself stays
        # scannable and the single broken edge is what becomes uncertain.
        self.make_dist('app', '1.0', [
            'vuln-lib',
            'other-pkg; python_version ~~ "3"',
        ])
        self.make_dist('vuln-lib', '1.0', [])
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context())
        kinds = [u.kind for u in report.all_uncertainties()]
        self.assertIn(BAD_MARKER, kinds)
        self.assertIn('app==1.0', report.affected_roots())

    def test_unparseable_requirement_marks_distribution_unreadable(self):
        # DistributionPath rejects metadata containing an unparseable
        # Requires-Dist line; the analysis must report it, not drop it.
        self.make_dist('app', '1.0', [
            'vuln-lib',
            'not a valid requirement !!!',
        ])
        self.make_dist('vuln-lib', '1.0', [])
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context())
        bad = [u for u in report.all_uncertainties()
               if u.kind == BAD_METADATA and 'app-1.0.dist-info' in u.subject]
        self.assertTrue(bad)

    def test_report_is_renderable_and_json_serializable(self):
        import json
        self.build_fixture()
        report = analyze_impact([self.site], 'vuln-lib',
                                self.linux_context(),
                                watched_constraints='<2')
        text = render_text_report(report)
        self.assertIn('webportal', text)
        self.assertIn('requirement :', text)
        self.assertIn('marker      :', text)
        payload = report.as_dict()
        json.dumps(payload)
        self.assertEqual(
            payload['target_environment']['python_version'], '3.11')

    def test_watched_package_absent(self):
        self.build_fixture()
        report = analyze_impact([self.site], 'never-heard-of-it',
                                self.linux_context())
        self.assertEqual(report.watched_keys, [])
        self.assertTrue(any(u.kind == UNMATCHED_WATCHED
                            for u in report.uncertainties))

    def test_cli_text_and_json_output(self):
        import contextlib
        import json
        from distlib.compat import StringIO
        from distlib import impact

        self.make_dist('app', '1.0',
                       ['lib; python_version < "3.12"'])
        self.make_dist('lib', '0.9', [])
        argv = ['--path', self.site, '--watched', 'lib',
                '--python-version', '3.11', '--sys-platform', 'linux']

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = impact.main(argv)
        self.assertEqual(rc, 0)
        self.assertIn('app (1.0)', buffer.getvalue())

        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = impact.main(argv + ['--json'])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(payload['affected_top_level_packages'],
                         ['app==1.0'])
        self.assertEqual(payload['target_environment']['python_version'],
                         '3.11')

    def test_cli_requires_path_and_rejects_unknown_marker(self):
        from distlib import impact
        self.assertRaises(SystemExit, impact.main,
                          ['--watched', 'lib'])
        self.assertRaises(ImpactException, make_target_environment,
                          {'no_such_marker': 'value'})

    def test_self_loop_is_a_root_and_a_cycle(self):
        self.make_dist('loopy', '1.0', ['loopy>=1.0'])
        report = analyze_impact([self.site], 'loopy',
                                self.linux_context())
        self.assertEqual(report.affected_roots(), ['loopy==1.0'])
        self.assertIn('loopy==1.0', report.cyclic_roots)

    def test_nonexistent_scan_path_is_an_uncertainty(self):
        missing = os.path.join(self.tmpdir, 'does-not-exist')
        report = analyze_impact([missing], 'vuln-lib',
                                self.linux_context())
        self.assertTrue(any(u.kind == BAD_METADATA
                            and u.subject == missing
                            for u in report.all_uncertainties()))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
