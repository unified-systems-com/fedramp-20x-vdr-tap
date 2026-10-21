"""Which asset a finding belongs to, as an importable function and a `module` Search runner (`req-fedramp-20x-vdr-reach`).

A method that scores a finding by what its asset needs has to know which asset the finding belongs to. This ships that
answer once so every method plugin reuses it. It names the owner of each open finding and the programs involved, reads no
profile and scores nothing, and stores nothing: it is computed on read.

The unit is one finding on one owner in one container. A package node is shared by every host that installs it, so
ownership is decided per container: for each container whose image host installs the finding's package, a program owns the
package only if that container runs the program (through `RUNS_PROGRAM`, followed program to program) and the package is
reachable from the program's `RUNS_PACKAGE` root along `REQUIRES_PACKAGE`; otherwise the container owns it, with the
container's programs involved. The programs an operating system holds are not the container's programs here (they carry no
profile by nature, so counting them would make every container High). A finding on a library follows `LOADS_LIBRARY`. A
finding the grid cannot tie to a container or a program yields one row with no owner, so the gap shows; nothing is dropped.

The row: `finding_id`, `vuln_id`, `component`, `owner_kind` (`program`, `container` or `none`), `owner_id`, `owner`,
`container_id`, `container` and `programs` (the `{id, name}` of every program involved). Open findings with a
`CONCERNS_COMPLIANCE_VULNERABILITY` edge only, the set the VDR-max collector covers. The work is proportional to the edges
of the five types it follows, which it reads in bulk; it has not been measured on a large grid.

Inputs: `entity_id` (optional, one finding) and `max_results` (1 to 5000, default 1000).
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from tap_grid.gryphon import read_scope
from tap_grid.models import Search

CC = "compliance_core__"
COMP = "computing_core__"
FINDING_TYPE = CC + "compliance_finding"
CONCERNS_EDGE = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
CARRIES_EDGE = "CARRIES_COMPLIANCE_FINDING__compliance_core"
INSTALLS_EDGE = "INSTALLS_PACKAGE__computing_core"
RUNS_IMAGE_EDGE = "RUNS_IMAGE__computing_core"
RUNS_PROGRAM_EDGE = "RUNS_PROGRAM__computing_core"
RUNS_PACKAGE_EDGE = "RUNS_PACKAGE__computing_core"
REQUIRES_EDGE = "REQUIRES_PACKAGE__computing_core"
LOADS_EDGE = "LOADS_LIBRARY__computing_core"
PACKAGE_TYPE = COMP + "package"
LIBRARY_TYPE = COMP + "library"
PROGRAM_TYPE = COMP + "program"

DEFAULT_MAX_RESULTS = 1000
MAX_RESULTS = 5000


def _inputs(inputs: dict[str, Any]) -> tuple[str | None, int]:
    entity_id = inputs.get("entity_id")
    if entity_id is not None and (not isinstance(entity_id, str) or not entity_id):
        raise ValueError("entity_id must be a non-empty string when given")
    max_results = inputs.get("max_results", DEFAULT_MAX_RESULTS)
    if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= MAX_RESULTS:
        raise ValueError(f"max_results must be an integer from 1 to {MAX_RESULTS}")
    return entity_id, max_results


def _pairs(edge_type: str, *, db_alias: str, **filters: Any) -> list[tuple[str, str]]:
    rows = (
        read_scope.edge_relation(read_scope.DEFAULT_SCOPE, db_alias=db_alias)
        .filter(edge_type=edge_type, **filters)
        .values_list("from_entity_id", "to_entity_id")
    )
    return [(str(a), str(b)) for a, b in rows]


def _reach(starts: Iterable[str], step: dict[str, set[str]]) -> set[str]:
    """Everything reachable from the starts along the step map, the starts included."""
    seen: set[str] = set()
    queue = deque(starts)
    while queue:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        queue.extend(step.get(node, ()))
    return seen


def reach_rows(inputs: dict[str, Any] | None = None, *, db_alias: str = "default") -> list[dict[str, Any]]:
    """The reach rows for the open, vulnerability-linked findings, in a stable order. See the module docstring."""
    entity_id, max_results = _inputs(inputs or {})
    scope = read_scope.DEFAULT_SCOPE

    # The findings: open, concerning a vulnerability (the set req-fedramp-20x-vdr-collector-1 covers).
    finding_filters: dict[str, Any] = {
        "from_entity__entity_type": FINDING_TYPE,
        "from_entity__compliancefinding__status": "open",
    }
    if entity_id is not None:
        finding_filters["from_entity_id"] = entity_id
    vulns: dict[str, set[str]] = defaultdict(set)
    for finding, vuln in _pairs(CONCERNS_EDGE, db_alias=db_alias, **finding_filters):
        vulns[finding].add(vuln)
    if not vulns:
        return []
    findings = sorted(vulns)

    carriers: dict[str, set[str]] = defaultdict(set)
    for carrier, finding in _pairs(CARRIES_EDGE, db_alias=db_alias, to_entity_id__in=findings):
        carriers[finding].add(carrier)
    carrier_ids = sorted({c for cs in carriers.values() for c in cs})
    types = {
        str(pk): etype
        for pk, etype in read_scope.node_relation(scope, None, db_alias=db_alias)
        .filter(pk__in=carrier_ids)
        .values_list("pk", "entity_type")
    }
    packages = {c for c in carrier_ids if types.get(c) == PACKAGE_TYPE}
    libraries = {c for c in carrier_ids if types.get(c) == LIBRARY_TYPE}

    # Containers of a package: container -RUNS_IMAGE-> image host -INSTALLS_PACKAGE-> package.
    hosts_of: dict[str, set[str]] = defaultdict(set)
    for host, package in _pairs(INSTALLS_EDGE, db_alias=db_alias, to_entity_id__in=sorted(packages)):
        hosts_of[package].add(host)
    all_hosts = sorted({h for hs in hosts_of.values() for h in hs})
    containers_of_host: dict[str, set[str]] = defaultdict(set)
    image_containers: set[str] = set()  # every node that runs an image: what a container is
    for container, host in _pairs(RUNS_IMAGE_EDGE, db_alias=db_alias):
        image_containers.add(container)
        if host in all_hosts:
            containers_of_host[host].add(container)

    # Programs: what a container runs, followed program to program; each program's closure over REQUIRES_PACKAGE.
    runs: dict[str, set[str]] = defaultdict(set)
    for source, program in _pairs(RUNS_PROGRAM_EDGE, db_alias=db_alias):
        runs[source].add(program)
    loads: dict[str, set[str]] = defaultdict(set)  # library -> programs that load it
    for program, library in _pairs(LOADS_EDGE, db_alias=db_alias, to_entity_id__in=sorted(libraries)):
        loads[library].add(program)
    roots: dict[str, set[str]] = defaultdict(set)
    for program, root in _pairs(RUNS_PACKAGE_EDGE, db_alias=db_alias):
        roots[program].add(root)
    requires: dict[str, set[str]] = defaultdict(set)
    for package, needed in _pairs(REQUIRES_EDGE, db_alias=db_alias):
        requires[package].add(needed)
    closure_cache: dict[str, set[str]] = {}

    def closure(program: str) -> set[str]:
        if program not in closure_cache:
            closure_cache[program] = _reach(roots.get(program, ()), requires)
        return closure_cache[program]

    def programs_of(container: str) -> list[str]:
        return sorted(_reach(runs.get(container, ()), runs) - {container})

    def containers_running(program: str) -> list[str]:
        """Containers (nodes that run an image) that run the program, directly or through another program."""
        return sorted(c for c in image_containers if program in _reach(runs.get(c, ()), runs))

    # Names for every node a row can name.
    program_universe = {p for ps in runs.values() for p in ps} | {p for ps in loads.values() for p in ps}
    name_ids = sorted(program_universe | image_containers | set(carrier_ids))
    names = {
        str(pk): name or ""
        for pk, name in read_scope.node_relation(scope, None, db_alias=db_alias)
        .filter(pk__in=name_ids)
        .values_list("pk", "name")
    }

    def program_ref(program: str) -> dict[str, str]:
        return {"id": program, "name": names.get(program, "")}

    rows: list[dict[str, Any]] = []
    for finding in findings:
        vuln_id = sorted(vulns[finding])[0]
        finding_carriers = sorted(carriers.get(finding, ()))
        produced = False
        for carrier in finding_carriers:
            base = {"finding_id": finding, "vuln_id": vuln_id, "component": names.get(carrier, "")}
            if carrier in packages:
                for host in sorted(hosts_of.get(carrier, ())):
                    for container in sorted(containers_of_host.get(host, ())):
                        programs = programs_of(container)
                        owners = [p for p in programs if carrier in closure(p)]
                        if owners:
                            for program in owners:
                                rows.append(
                                    _row(base, "program", program, names, container, [program_ref(program)])
                                )
                        else:
                            rows.append(
                                _row(base, "container", container, names, container, [program_ref(p) for p in programs])
                            )
                        produced = True
            elif carrier in libraries:
                for program in sorted(loads.get(carrier, ())):
                    running = containers_running(program)
                    for container in running or [None]:
                        rows.append(_row(base, "program", program, names, container, [program_ref(program)]))
                        produced = True
        if not produced:
            component = names.get(finding_carriers[0], "") if finding_carriers else ""
            rows.append(
                {
                    "finding_id": finding,
                    "vuln_id": vuln_id,
                    "component": component,
                    "owner_kind": "none",
                    "owner_id": None,
                    "owner": None,
                    "container_id": None,
                    "container": None,
                    "programs": [],
                }
            )
    rows = _dedupe(rows)
    rows.sort(key=lambda r: (r["finding_id"], r["container_id"] or "", r["owner_kind"], r["owner_id"] or ""))
    return rows[:max_results]


def _row(
    base: dict[str, Any],
    kind: str,
    owner_id: str,
    names: dict[str, str],
    container: str | None,
    programs: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        **base,
        "owner_kind": kind,
        "owner_id": owner_id,
        "owner": names.get(owner_id, ""),
        "container_id": container,
        "container": names.get(container, "") if container else None,
        "programs": programs,
    }


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per finding, component, owner and container: a package carried twice or reached by two paths counts once."""
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = (row["finding_id"], row["component"], row["owner_kind"], row["owner_id"], row["container_id"])
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def vdr_reach(search: Search, inputs: dict[str, Any], *, db_alias: str, layer: str = "full") -> dict[str, Any]:
    """The `module` Search runner over `reach_rows`: one row per finding per owner per container.

    req-fedramp-20x-vdr-reach-13
    """
    rows = reach_rows(inputs, db_alias=db_alias)
    return {"nodes": [], "edges": [], "rows": rows, "info": {"row_count": len(rows)}, "warnings": {}}
