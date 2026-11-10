# -*- coding: utf-8 -*-
#
# Offline dependency impact analysis built on DistributionPath.
#
# This module never imports project code and never contacts a package index or
# a vulnerability database. All relationships are derived solely from the
# distribution metadata (``METADATA`` / ``Requires-Dist``) found on a scanned
# path, and all markers are evaluated against a caller-supplied target
# environment rather than the machine doing the analysis.
#
from __future__ import print_function

import logging
import os
import posixpath

from . import DistlibException, resources
from .database import DistributionPath, DISTINFO_EXT
from .markers import Evaluator
from .metadata import (Metadata, METADATA_FILENAME, WHEEL_METADATA_FILENAME,
                       LEGACY_METADATA_FILENAME)
from .util import normalize_name, parse_requirement
from .version import get_scheme, UnsupportedVersionError

logger = logging.getLogger(__name__)

# Marker verdicts
ACTIVE = 'active'
INACTIVE = 'inactive'
UNKNOWN = 'unknown'

# Uncertainty categories
BAD_METADATA = 'unreadable-metadata'
BAD_REQUIREMENT = 'unparseable-requirement'
BAD_MARKER = 'unparseable-marker'
UNKNOWN_MARKER_VARIABLE = 'unknown-marker-variable'
MISSING_DISTRIBUTION = 'missing-distribution'
VERSION_CONFLICT = 'version-conflict'
NAME_AMBIGUITY = 'ambiguous-distribution-name'
UNKNOWN_EXTRA = 'unknown-extra'
UNMATCHED_WATCHED = 'watched-not-installed'
AMBIGUOUS_WATCHED = 'watched-ambiguous'

# The complete set of PEP 508 marker variables, so a target environment can be
# validated up front instead of silently mixing in the analyser host's values.
MARKER_VARIABLES = frozenset((
    'implementation_name', 'implementation_version', 'os_name',
    'platform_machine', 'platform_python_implementation', 'platform_release',
    'platform_system', 'platform_version', 'python_full_version',
    'python_version', 'sys_platform', 'extra',
))

DEFAULT_SCHEME = 'default'


class ImpactException(DistlibException):
    """Raised for usage errors (bad arguments) rather than scan uncertainty."""


class Uncertainty(object):
    """
    Something that prevents an exact, machine-provable answer.

    Uncertainties are never treated as evidence of *not* being affected: they
    are reported separately so a human can follow them up.
    """

    __slots__ = ('kind', 'subject', 'detail')

    def __init__(self, kind, subject, detail=''):
        self.kind = kind
        # subject is typically a distribution key or a requirement string
        self.subject = subject
        self.detail = detail

    def __repr__(self):
        return 'Uncertainty(%s, %r, %r)' % (self.kind, self.subject, self.detail)

    def as_dict(self):
        return {'kind': self.kind, 'subject': self.subject, 'detail': self.detail}


class Edge(object):
    """
    A single evaluated requirement edge.

    ``raw_requirement`` is the verbatim ``Requires-Dist`` line.
    ``marker_verdict`` says whether the edge applies in the supplied target
    environment, and ``marker_reason`` carries the failing comparison or the
    missing marker variable.
    """

    __slots__ = ('source_key', 'raw_requirement', 'req_name', 'extras',
                 'constraints', 'marker_text', 'marker_verdict',
                 'marker_reason', 'extra_context', 'targets')

    def __init__(self, source_key, raw_requirement, req_name, extras,
                 constraints, marker_text, marker_verdict, marker_reason,
                 extra_context, targets):
        self.source_key = source_key
        self.raw_requirement = raw_requirement
        self.req_name = req_name
        self.extras = extras
        self.constraints = constraints
        self.marker_text = marker_text
        self.marker_verdict = marker_verdict
        self.marker_reason = marker_reason
        # The value of the marker ``extra`` variable under which this edge is
        # active (None for base requirements).
        self.extra_context = extra_context
        # List of (distribution key, version-matches) for active edges.
        self.targets = targets

    def as_dict(self):
        return {
            'raw_requirement': self.raw_requirement,
            'requirement_name': self.req_name,
            'extras': list(self.extras),
            'constraints': list(self.constraints),
            'marker': self.marker_text,
            'marker_verdict': self.marker_verdict,
            'marker_reason': self.marker_reason,
            'extra_context': self.extra_context,
            'targets': [{'key': key, 'version_matches': matches}
                       for key, matches in self.targets],
        }


class ScannedDistribution(object):
    """Metadata snapshot of one distribution on the scanned path."""

    __slots__ = ('key', 'name', 'normalized_name', 'version', 'path',
                 'provides_extra', 'raw_requirements')

    def __init__(self, name, version, path, provides_extra, raw_requirements):
        self.name = name
        self.normalized_name = normalize_name(name)
        self.version = version
        self.path = path
        self.provides_extra = sorted(provides_extra)
        self.raw_requirements = raw_requirements
        self.key = '%s==%s' % (self.normalized_name, version)

    def label(self):
        return '%s (%s)' % (self.name, self.version)

    def as_dict(self):
        return {
            'key': self.key,
            'name': self.name,
            'normalized_name': self.normalized_name,
            'version': self.version,
            'path': self.path,
            'provides_extra': list(self.provides_extra),
            'raw_requirements': list(self.raw_requirements),
        }


class _ParsedRequirement(object):
    """A parsed Requires-Dist line ready for marker evaluation."""

    __slots__ = ('raw', 'parsed', 'marker_text', 'uses_extra')

    def __init__(self, raw, parsed, marker_text, uses_extra):
        self.raw = raw
        self.parsed = parsed
        self.marker_text = marker_text
        self.uses_extra = uses_extra


class DependencyGraph(object):
    """
    A dependency graph built from scanned metadata.

    Nodes are distribution keys (normalized name plus version). Every
    ``Requires-Dist`` line is materialized into :class:`Edge` objects when the
    graph is built, so missing dependencies and version conflicts are reported
    even when they are not reachable from a particular traversal. Base edges
    are evaluated with no ``extra`` variable; extra-gated edges are evaluated
    once per extra the distribution declares, and traversal selects the ones
    whose extra is active on the current route. The graph is traversal-safe
    with cycles and diamond dependencies.
    """

    def __init__(self):
        self.distributions = {}            # key -> ScannedDistribution
        self.by_name = {}                  # normalized name -> list of keys
        self.base_edges = {}               # key -> list of Edge (no extra var)
        self.extra_edges = {}              # key -> extra name -> list of Edge
        self.uncertainties = []
        self.ambiguous_names = set()
        self.path_order = {}               # key -> index on the scanned path

    def add_distribution(self, scanned):
        self.distributions[scanned.key] = scanned
        self.by_name.setdefault(scanned.normalized_name, []).append(scanned.key)
        self.base_edges.setdefault(scanned.key, [])
        self.extra_edges.setdefault(scanned.key, {})

    def add_uncertainty(self, uncertainty):
        """Record a graph-level uncertainty, suppressing exact duplicates."""
        signature = (uncertainty.kind, uncertainty.subject,
                     uncertainty.detail)
        for existing in self.uncertainties:
            if (existing.kind, existing.subject, existing.detail) == \
                    signature:
                return
        self.uncertainties.append(uncertainty)

    def add_edge(self, edge):
        if edge.extra_context is None:
            self.base_edges[edge.source_key].append(edge)
        else:
            bucket = self.extra_edges[edge.source_key]
            bucket.setdefault(edge.extra_context, []).append(edge)

    def edges_for(self, key, activated_extras):
        """Base edges plus extra edges for extras active on a route."""
        result = list(self.base_edges.get(key, ()))
        buckets = self.extra_edges.get(key, {})
        for extra in sorted(frozenset(activated_extras or ())):
            if extra in buckets:
                result.extend(buckets[extra])
        return result

    def all_edges(self):
        for edges in self.base_edges.values():
            for edge in edges:
                yield edge
        for buckets in self.extra_edges.values():
            for edges in buckets.values():
                for edge in edges:
                    yield edge

    def roots(self):
        """
        Top-level distributions: no *other* scanned distribution requires them.

        Self references (a package requiring itself) do not disqualify a
        distribution from being a root; otherwise a self-looping package
        would vanish from the report entirely.
        """
        pointed_to = set()
        for edge in self.all_edges():
            for key, _matches in edge.targets:
                if key != edge.source_key:
                    pointed_to.add(key)
        return sorted((key for key in self.distributions if key not in
                       pointed_to),
                      key=lambda key: (self.path_order.get(key, 0), key))

    def as_dict(self):
        edges = dict((key, [edge.as_dict() for edge in base])
                     for key, base in self.base_edges.items())
        for key, buckets in self.extra_edges.items():
            edges.setdefault(key, [])
            for extra, extra_edges in buckets.items():
                for edge in extra_edges:
                    edges[key].append(edge.as_dict())
        return {
            'distributions': [d.as_dict() for d in self.distributions.values()],
            'edges': edges,
            'ambiguous_names': sorted(self.ambiguous_names),
            'uncertainties': [u.as_dict() for u in self.uncertainties],
        }


def make_target_environment(context=None, python_version=None,
                            python_full_version=None, sys_platform=None,
                            os_name=None, platform_system=None,
                            platform_machine=None, platform_release=None,
                            platform_version=None,
                            platform_python_implementation=None,
                            implementation_name=None,
                            implementation_version=None):
    """
    Build the marker context for the *target* environment.

    Only the values explicitly supplied are used: the analyser machine's
    interpreter and platform are never consulted. Passing an unknown marker
    variable raises :class:`ImpactException` so typos don't disappear silently.
    """
    context = dict(context or {})
    explicit = {
        'python_version': python_version,
        'python_full_version': python_full_version,
        'sys_platform': sys_platform,
        'os_name': os_name,
        'platform_system': platform_system,
        'platform_machine': platform_machine,
        'platform_release': platform_release,
        'platform_version': platform_version,
        'platform_python_implementation': platform_python_implementation,
        'implementation_name': implementation_name,
        'implementation_version': implementation_version,
    }
    for marker_name, value in explicit.items():
        if value is not None:
            context[marker_name] = value
    unknown = sorted(set(context) - MARKER_VARIABLES)
    if unknown:
        raise ImpactException('unknown marker variable(s): %s'
                              % ', '.join(unknown))
    # ``extra`` is supplied per-evaluation during traversal, never globally.
    context.pop('extra', None)
    return context


def _marker_text(ast):
    """Render a marker AST back to text, for display in reports."""
    if ast is None:
        return None
    if isinstance(ast, str):
        return ast.strip("'\"") if ast[:1] in ("'", '"') else ast
    op = ast['op']
    if op in ('and', 'or'):
        return '(%s %s %s)' % (_marker_text(ast['lhs']), op,
                               _marker_text(ast['rhs']))
    return '%s %s %s' % (_marker_text(ast['lhs']), op,
                         _marker_text(ast['rhs']))


def _evaluate_marker(ast, context, extra):
    """
    Evaluate a marker AST in the target context.

    Returns ``(verdict, reason)``. ``extra`` is the value exposed as the marker
    ``extra`` variable (``None`` for base requirements).
    """
    if ast is None:
        return ACTIVE, None
    eval_context = dict(context)
    if extra is not None:
        eval_context['extra'] = extra
    try:
        result = Evaluator().evaluate(ast, eval_context)
    except SyntaxError as e:
        return UNKNOWN, str(e)
    except Exception as e:  # defensive: marker expressions are small
        return UNKNOWN, '%s: %s' % (type(e).__name__, e)
    if result:
        return ACTIVE, None
    return INACTIVE, 'marker evaluated false in target environment'


def _marker_uses_variable(ast, variable):
    if ast is None or isinstance(ast, str):
        return False
    if ast.get('lhs') == variable or ast.get('rhs') == variable:
        return True
    return (_marker_uses_variable(ast.get('lhs'), variable)
            or _marker_uses_variable(ast.get('rhs'), variable))


def _probe_unreadable_distinfo(path):
    """
    Identify ``.dist-info`` directories whose metadata cannot be parsed.

    DistributionPath logs and skips these; the impact analysis must surface
    them as uncertainties instead of pretending they do not exist.
    """
    uncertainties = []
    for base in path:
        if not os.path.isdir(base):
            uncertainties.append(Uncertainty(
                BAD_METADATA, base, 'scan path is not a directory'))
            continue
        finder = resources.finder_for_path(base)
        if finder is None:
            continue
        root = finder.find('')
        if not root or not root.is_container:
            continue
        for entry in sorted(root.resources):
            if not entry.endswith(DISTINFO_EXT):
                continue
            metadata_resource = None
            for metadata_filename in (METADATA_FILENAME,
                                      WHEEL_METADATA_FILENAME,
                                      LEGACY_METADATA_FILENAME):
                metadata_resource = finder.find(
                    posixpath.join(entry, metadata_filename))
                if metadata_resource:
                    break
            distinfo_path = posixpath.join(base, entry)
            if metadata_resource is None:
                uncertainties.append(Uncertainty(
                    BAD_METADATA, distinfo_path,
                    'no METADATA/pydist.json/metadata.json present'))
                continue
            try:
                stream = metadata_resource.as_stream()
                try:
                    metadata = Metadata(fileobj=stream, scheme='legacy')
                finally:
                    stream.close()
                if not metadata.name or not metadata.version:
                    raise ValueError('metadata missing Name or Version')
            except Exception as e:
                uncertainties.append(Uncertainty(
                    BAD_METADATA, distinfo_path,
                    '%s: %s' % (type(e).__name__, e)))
    return uncertainties


def build_graph(path, target_context, include_egg=False,
                scheme=DEFAULT_SCHEME):
    """
    Build a :class:`DependencyGraph` from the metadata found on *path*.

    :param path: iterable of directories to scan (as for
                 :class:`~distlib.database.DistributionPath`).
    :param target_context: marker context produced by
                           :func:`make_target_environment`.
    :returns: :class:`DependencyGraph`.
    """
    graph = DependencyGraph()
    graph.uncertainties.extend(
        _probe_unreadable_distinfo([entry for entry in path]))

    distribution_path = DistributionPath(path=list(path),
                                         include_egg=include_egg)
    for order, dist in enumerate(distribution_path.get_distributions()):
        raw_requirements = list(dist.run_requires or [])
        provides_extra = list(getattr(dist.metadata, 'extras', None) or [])
        item = ScannedDistribution(dist.name, dist.version, dist.path,
                                   provides_extra, raw_requirements)
        if item.key in graph.distributions:
            graph.add_uncertainty(Uncertainty(
                NAME_AMBIGUITY, item.normalized_name,
                'duplicate distribution %s also at %s'
                % (item.key, item.path)))
            continue
        graph.add_distribution(item)
        graph.path_order[item.key] = order

    for normalized_name, keys in graph.by_name.items():
        if len(keys) > 1:
            graph.ambiguous_names.add(normalized_name)
            graph.add_uncertainty(Uncertainty(
                NAME_AMBIGUITY, normalized_name,
                'multiple distributions share this name: %s'
                % ', '.join(sorted(keys))))

    graph.target_context = target_context
    graph.scheme = scheme
    graph.version_scheme = get_scheme(scheme)
    for item in list(graph.distributions.values()):
        for entry in _parse_requirements(item, graph):
            _materialize_edges(item, entry, graph)
    return graph


def _parse_requirements(item, graph):
    """Parse all Requires-Dist lines of one scanned distribution."""
    entries = []
    for raw in item.raw_requirements:
        try:
            parsed = parse_requirement(raw)
        except SyntaxError as e:
            # A syntactically invalid marker (or requirement) makes the edge's
            # applicability undecidable, rather than simply malformed.
            kind = BAD_MARKER if ';' in raw else BAD_REQUIREMENT
            graph.add_uncertainty(Uncertainty(
                kind, item.key,
                '%r could not be parsed: %s' % (raw, e)))
            continue
        except Exception as e:
            graph.add_uncertainty(Uncertainty(
                BAD_REQUIREMENT, item.key,
                '%r could not be parsed: %s: %s'
                % (raw, type(e).__name__, e)))
            continue
        if parsed is None:
            continue

        marker_text = _marker_text(parsed.marker)
        uses_extra = _marker_uses_variable(parsed.marker, 'extra')
        # An extra requested on the requirement but undeclared by the target
        # distribution can never activate conditional dependencies there.
        for requested_extra in (parsed.extras or ()):
            for key in graph.by_name.get(normalize_name(parsed.name), []):
                target_dist = graph.distributions[key]
                if requested_extra not in target_dist.provides_extra:
                    graph.add_uncertainty(Uncertainty(
                        UNKNOWN_EXTRA, key,
                        'requirement %r requests extra %r which is not declared'
                        % (raw, requested_extra)))
        entries.append(_ParsedRequirement(
            raw, parsed, marker_text, uses_extra))
    return entries


def _make_edge(item, entry, extra, graph):
    """Evaluate one parsed requirement for a specific ``extra`` value."""
    parsed = entry.parsed
    if entry.uses_extra:
        verdict, reason = _evaluate_marker(
            parsed.marker, graph.target_context, extra)
        chosen_extra = extra
    else:
        verdict, reason = _evaluate_marker(
            parsed.marker, graph.target_context, None)
        chosen_extra = None

    targets = []
    if verdict == ACTIVE:
        targets = _resolve_targets(parsed, graph, entry.raw)
    return Edge(
        item.key, entry.raw, normalize_name(parsed.name),
        tuple(parsed.extras or ()),
        tuple((op, value) for op, value in (parsed.constraints or ())),
        entry.marker_text, verdict, reason, chosen_extra, targets)


def _materialize_edges(item, entry, graph):
    """
    Evaluate a requirement once for the base context and once per declared
    extra when the marker references ``extra``. All edges, including inactive
    and unresolved ones, are retained so the report can show every verdict.
    """
    if entry.uses_extra:
        extras = item.provides_extra or [None]
        for extra in extras:
            graph.add_edge(_make_edge(item, entry, extra, graph))
    else:
        graph.add_edge(_make_edge(item, entry, None, graph))


def _resolve_targets(parsed, graph, raw):
    """
    Match an active requirement against scanned distributions.

    Every resolution problem (missing name, version mismatch, unparseable
    specifier) is registered directly on the graph so it remains visible even
    when the requiring distribution is itself unreachable from a root.
    """
    req_normalized = normalize_name(parsed.name)
    candidate_keys = graph.by_name.get(req_normalized, [])
    if not candidate_keys:
        graph.add_uncertainty(Uncertainty(
            MISSING_DISTRIBUTION, req_normalized,
            'required by %r but no distribution with that name was scanned'
            % raw))
        return []

    matcher = None
    if parsed.constraints:
        try:
            matcher = graph.version_scheme.matcher(parsed.requirement)
        except UnsupportedVersionError as e:
            graph.add_uncertainty(Uncertainty(
                BAD_REQUIREMENT, req_normalized,
                'unsupported version specifier in %r: %s' % (raw, e)))

    targets = []
    for key in candidate_keys:
        candidate = graph.distributions[key]
        if matcher is None:
            matches = True
        else:
            try:
                matches = matcher.match(candidate.version)
            except UnsupportedVersionError:
                matches = False
                graph.add_uncertainty(Uncertainty(
                    VERSION_CONFLICT, key,
                    'installed version cannot be compared against %r' % raw))
        targets.append((key, matches))
        if not matches:
            graph.add_uncertainty(Uncertainty(
                VERSION_CONFLICT, key,
                'version %s does not satisfy %r' % (candidate.version, raw)))
    return targets


def analyze_impact(path, watched_name, target_context,
                   watched_constraints=None, include_egg=False,
                   scheme=DEFAULT_SCHEME):
    """
    Find every top-level distribution that can reach a watched distribution.

    :param path: directories to scan.
    :param watched_name: distribution name to trace (normalized per PEP 503).
    :param target_context: output of :func:`make_target_environment`.
    :param watched_constraints: optional version specifier string such as
                                ``'<2.0'`` applied to the watched package.
    :returns: :class:`ImpactReport`.
    """
    graph = build_graph(path, target_context, include_egg=include_egg,
                        scheme=scheme)
    watched_normalized = normalize_name(watched_name)
    report = ImpactReport(watched_name, watched_normalized,
                          watched_constraints, target_context, graph)

    candidate_keys = graph.by_name.get(watched_normalized, [])
    if not candidate_keys:
        report.add_uncertainty(Uncertainty(
            UNMATCHED_WATCHED, watched_normalized,
            'no distribution with this name was scanned'))
        return report

    if len(candidate_keys) > 1:
        report.add_uncertainty(Uncertainty(
            AMBIGUOUS_WATCHED, watched_normalized,
            'multiple installed versions: %s'
            % ', '.join(sorted(candidate_keys))))

    watched_matcher = None
    if watched_constraints:
        try:
            watched_matcher = graph.version_scheme.matcher(
                '%s %s' % (watched_name, watched_constraints))
        except Exception as e:
            raise ImpactException(
                'invalid watched version constraint %r: %s'
                % (watched_constraints, e))

    matching_keys = []
    for key in candidate_keys:
        version = graph.distributions[key].version
        if watched_matcher is None:
            matching_keys.append(key)
            continue
        try:
            if watched_matcher.match(version):
                matching_keys.append(key)
        except UnsupportedVersionError:
            report.add_uncertainty(Uncertainty(
                VERSION_CONFLICT, key,
                'cannot evaluate watched constraint against version %s'
                % version))

    if not matching_keys:
        report.add_uncertainty(Uncertainty(
            UNMATCHED_WATCHED, watched_normalized,
            'no installed version satisfies %s' % watched_constraints))
        return report

    report.watched_keys = sorted(matching_keys)
    for root_key in graph.roots():
        _walk_from_root(graph, root_key, frozenset(), [], frozenset(),
                        report)
    return report


def _walk_from_root(graph, node_key, activated_extras, chain, visited,
                    report):
    """
    Depth-first walk from a top-level package.

    ``visited`` holds (node key, activated extras) states so cycles terminate
    without losing the back-edge relationship. Each edge records the raw
    requirement and the marker verdict for the target environment.
    """
    state = (node_key, activated_extras)
    if state in visited:
        return
    visited = visited | {state}
    for edge in graph.edges_for(node_key, activated_extras):
        next_chain = chain + [(node_key, edge)]
        if edge.marker_verdict == UNKNOWN:
            report.add_uncertainty(Uncertainty(
                UNKNOWN_MARKER_VARIABLE, node_key,
                'edge %r cannot be evaluated in the target environment; '
                'downstream reachability is undetermined'
                % edge.raw_requirement))
            continue
        if edge.marker_verdict != ACTIVE:
            continue
        requested_extras = frozenset(edge.extras)
        if not edge.targets:
            # Missing distribution already recorded on the edge; the route
            # stops here but does not prove the watched package is unreachable.
            continue
        for target_key, version_matches in edge.targets:
            if not version_matches:
                report.add_uncertainty(Uncertainty(
                    VERSION_CONFLICT, target_key,
                    'requirement %r from %s does not match the installed '
                    'version' % (edge.raw_requirement, node_key)))
                continue
            if target_key in report.watched_keys:
                root_key = chain[0][0] if chain else node_key
                cyclic = target_key in {key for key, _edge in chain} \
                    or target_key == node_key
                report.record_path(root_key, next_chain, cyclic=cyclic)
                continue
            # Even if a route already proved reachability, keep walking so
            # diamond branches and cycles are both represented.
            _walk_from_root(graph, target_key,
                            activated_extras | requested_extras,
                            next_chain, visited, report)


class ImpactReport(object):
    """Structured result of :func:`analyze_impact`."""

    def __init__(self, watched_name, watched_normalized, watched_constraints,
                 target_context, graph):
        self.watched_name = watched_name
        self.watched_normalized = watched_normalized
        self.watched_constraints = watched_constraints
        self.target_context = target_context
        self.graph = graph
        self.watched_keys = []
        # root key -> list of paths; each path is a list of (source key, Edge)
        self.paths = {}
        self.cyclic_roots = set()
        self.uncertainties = []

    def record_path(self, root_key, chain, cyclic=False):
        existing = self.paths.setdefault(root_key, [])
        signature = tuple(edge.raw_requirement for _key, edge in chain)
        for recorded in existing:
            if tuple(edge.raw_requirement for _key, edge in recorded) == \
                    signature:
                return
        existing.append(chain)
        if cyclic:
            self.cyclic_roots.add(root_key)

    def add_uncertainty(self, uncertainty):
        """Record a report-level uncertainty, suppressing exact duplicates."""
        signature = (uncertainty.kind, uncertainty.subject,
                     uncertainty.detail)
        for existing in self.uncertainties:
            if (existing.kind, existing.subject, existing.detail) == \
                    signature:
                return
        self.uncertainties.append(uncertainty)

    def affected_roots(self):
        return sorted(self.paths)

    def as_dict(self):
        paths = {}
        for root_key, chains in self.paths.items():
            paths[root_key] = []
            for chain in chains:
                paths[root_key].append([
                    {
                        'source': source_key,
                        'raw_requirement': edge.raw_requirement,
                        'marker': edge.marker_text,
                        'marker_verdict': edge.marker_verdict,
                        'marker_reason': edge.marker_reason,
                        'extra_context': edge.extra_context,
                        'targets': [{'key': key, 'version_matches': matches}
                                   for key, matches in edge.targets],
                    }
                    for source_key, edge in chain
                ])
        return {
            'watched': {
                'name': self.watched_name,
                'normalized_name': self.watched_normalized,
                'constraints': self.watched_constraints,
                'matching_distributions': list(self.watched_keys),
            },
            'target_environment': dict(self.target_context),
            'affected_top_level_packages': self.affected_roots(),
            'dependency_paths': paths,
            'cyclic_roots': sorted(self.cyclic_roots),
            'ambiguous_names': sorted(self.graph.ambiguous_names),
            'uncertainties': [u.as_dict() for u in self.all_uncertainties()],
        }

    def all_uncertainties(self):
        seen = set()
        result = []
        for uncertainty in list(self.uncertainties) + \
                list(self.graph.uncertainties):
            signature = (uncertainty.kind, uncertainty.subject,
                         uncertainty.detail)
            if signature not in seen:
                seen.add(signature)
                result.append(uncertainty)
        return result


def render_text_report(report):
    """Render an :class:`ImpactReport` as a human-readable plain-text report."""
    lines = []
    watched = report.watched_name
    if report.watched_constraints:
        watched = '%s %s' % (watched, report.watched_constraints)
    lines.append('Offline impact analysis for watched requirement: %s'
                 % watched)
    lines.append('Target environment (markers evaluated here only):')
    for key in sorted(report.target_context):
        lines.append('  %s = %s' % (key, report.target_context[key]))
    if report.watched_keys:
        lines.append('Matching installed distribution(s): %s'
                     % ', '.join(report.watched_keys))
    lines.append('')

    roots = report.affected_roots()
    lines.append('Affected top-level packages: %d' % len(roots))
    for root_key in roots:
        root_dist = report.graph.distributions[root_key]
        suffix = ' [path contains a dependency cycle]' \
            if root_key in report.cyclic_roots else ''
        lines.append('  * %s%s' % (root_dist.label(), suffix))
        for chain in report.paths[root_key]:
            lines.append('    verifiable dependency path:')
            for source_key, edge in chain:
                verdict = edge.marker_verdict.upper()
                marker = edge.marker_text or '(no marker)'
                extra = (' extra=%s' % edge.extra_context
                         if edge.extra_context is not None else '')
                lines.append('      %s' % source_key)
                lines.append('        requirement : %s'
                             % edge.raw_requirement)
                lines.append('        marker      : %s [%s]%s'
                             % (marker, verdict, extra))
                if edge.marker_reason:
                    lines.append('        detail      : %s'
                                 % edge.marker_reason)
                target_labels = ', '.join(
                    '%s%s' % (key, '' if matches else ' (VERSION MISMATCH)')
                    for key, matches in edge.targets) or '(unresolved)'
                lines.append('        resolves to : %s' % target_labels)
            lines.append('      %s' % (report.watched_keys[0]
                                       if report.watched_keys else '?'))
    lines.append('')

    lines.append('Uncertainties (not proof of being unaffected):')
    uncertainties = report.all_uncertainties()
    if not uncertainties:
        lines.append('  (none)')
    else:
        for uncertainty in uncertainties:
            lines.append('  - [%s] %s: %s'
                         % (uncertainty.kind, uncertainty.subject,
                            uncertainty.detail))
    return '\n'.join(lines)


# Marker variables overridable from the command line.
_CLI_MARKER_VARS = (
    'python_version', 'python_full_version', 'sys_platform', 'os_name',
    'platform_system', 'platform_machine', 'platform_release',
    'platform_version', 'platform_python_implementation',
    'implementation_name', 'implementation_version',
)


def _build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description='Offline dependency impact analysis (no network, no '
                    'project imports, markers evaluated against the supplied '
                    'target environment).')
    parser.add_argument('--path', action='append', default=[],
                        help='directory containing .dist-info entries; may be '
                             'repeated to model path priority.')
    parser.add_argument('--watched', required=True,
                        help='normalized distribution name to trace.')
    parser.add_argument('--constraint', dest='watched_constraints',
                        help="version specifier for the watched package, "
                             "e.g. '<2.0'.")
    parser.add_argument('--json', action='store_true',
                        help='emit the structured report as JSON.')
    for variable in _CLI_MARKER_VARS:
        parser.add_argument('--%s' % variable.replace('_', '-'),
                            dest=variable)
    return parser


def main(argv=None):
    """Console entry point. Returns a process exit code."""
    import json
    import sys

    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    if not args.path:
        parser.error('at least one --path is required')

    overrides = dict((variable, getattr(args, variable))
                     for variable in _CLI_MARKER_VARS
                     if getattr(args, variable) is not None)
    target_context = make_target_environment(**overrides)
    report = analyze_impact(
        args.path, args.watched, target_context,
        watched_constraints=args.watched_constraints)
    if args.json:
        json.dump(report.as_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write('\n')
    else:
        sys.stdout.write(render_text_report(report))
        sys.stdout.write('\n')
    # Non-zero when the answer itself is not fully provable.
    return 2 if report.all_uncertainties() else 0


if __name__ == '__main__':  # pragma: no cover
    import sys
    sys.exit(main())
