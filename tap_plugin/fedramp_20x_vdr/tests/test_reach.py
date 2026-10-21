"""Finding reach: which owner each open finding belongs to (`req-fedramp-20x-vdr-reach`).

Each test builds its own small graph through the service layer with computing_core's real types: containers (nodes that
run an image host), image hosts that install packages, programs with a root package, and the dependency closure.
"""

from __future__ import annotations

from typing import Any

import pytest
import tap_plugin.compliance_core.models as compliance  # noqa: F401 - trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 - trigger model registration
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr.searches import reach
from tap_plugin.fedramp_20x_vdr.searches.reach import reach_rows, vdr_reach

from tap_grid.models import Entity, Search
from tap_grid.search import execute_search
from tap_grid.services import create_edge, create_node, delete_node

FINDING = "compliance_core__compliance_finding"
VULN = "compliance_core__compliance_vulnerability"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
C = "computing_core__"

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


def _node(type_slug: str, payload: dict[str, Any]) -> Entity:
    made = create_node(type_slug, payload)
    assert made.success, made.errors
    return Entity.objects.get(pk=made.entity_id)


def _edge(src: Entity, name: str, dst: Entity) -> None:
    create_edge(src, dst, f"{name}__computing_core")


class World:
    """A small estate, built on demand."""

    def __init__(self) -> None:
        self.vuln = _node(VULN, {"vuln_id": "CVE-2026-1", "title": "t"})
        self.n = 0

    def package(self, name: str, ecosystem: str = "pypi") -> Entity:
        return _node(C + "package", {"ecosystem": ecosystem, "name": name, "version": "1.0"})

    def program(self, name: str) -> Entity:
        return _node(C + "program", {"program_name": name})

    def image_host(self, name: str) -> Entity:
        return _node(C + "host", {"realm": "assert", "stable_id": f"image-{name}", "kind": "container"})

    def container(self, name: str, host: Entity) -> Entity:
        container = _node(C + "host", {"realm": "assert", "stable_id": f"container-{name}", "kind": "container"})
        _edge(container, "RUNS_IMAGE", host)
        return container

    def finding(self, component: Entity, key: str | None = None, *, status: str = "open", linked: bool = True) -> Entity:
        key = key or f"f-{component.name}"
        finding = _node(FINDING, {"source": "t", "source_key": key, "name": key, "status": status})
        if linked:
            create_edge(finding, self.vuln, CONCERNS)
        create_edge(component, finding, CARRIES)
        return finding


def _by(rows: list[dict[str, Any]], finding: Entity) -> list[dict[str, Any]]:
    return [r for r in rows if r["finding_id"] == str(finding.pk)]


class TestOwnership:
    @pytest.mark.spec("req-fedramp-20x-vdr-reach-2")
    def test_a_program_owns_its_root_and_the_closure_in_the_container_that_runs_it(self) -> None:
        w = World()
        root, dep, deeper = w.package("tap"), w.package("django"), w.package("asgiref")
        _edge(root, "REQUIRES_PACKAGE", dep)
        _edge(dep, "REQUIRES_PACKAGE", deeper)
        program = w.program("tap-web")
        _edge(program, "RUNS_PACKAGE", root)
        host = w.image_host("web")
        for package in (root, dep, deeper):
            _edge(host, "INSTALLS_PACKAGE", package)
        container = w.container("web", host)
        _edge(container, "RUNS_PROGRAM", program)
        findings = {p.name: w.finding(p) for p in (root, dep, deeper)}
        rows = reach_rows()
        for package in (root, dep, deeper):
            (row,) = _by(rows, findings[package.name])
            assert (row["owner_kind"], row["owner_id"], row["container_id"]) == ("program", str(program.pk), str(container.pk))
            assert row["programs"] == [{"id": str(program.pk), "name": "tap-web"}]

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-2")
    def test_a_program_with_two_roots_owns_both_closures(self) -> None:
        w = World()
        a, b, dep_a, dep_b = w.package("a"), w.package("b"), w.package("dep-a"), w.package("dep-b")
        _edge(a, "REQUIRES_PACKAGE", dep_a)
        _edge(b, "REQUIRES_PACKAGE", dep_b)
        program = w.program("app")
        _edge(program, "RUNS_PACKAGE", a)
        _edge(program, "RUNS_PACKAGE", b)
        host = w.image_host("x")
        for package in (a, b, dep_a, dep_b):
            _edge(host, "INSTALLS_PACKAGE", package)
        _edge(w.container("x", host), "RUNS_PROGRAM", program)
        findings = [w.finding(p) for p in (dep_a, dep_b)]
        rows = reach_rows()
        assert [(_by(rows, f)[0]["owner_kind"]) for f in findings] == ["program", "program"]

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-2")
    def test_a_program_that_another_container_runs_does_not_claim_the_package_here(self) -> None:
        """A package node is shared by every host that installs it, so ownership is decided per container."""
        w = World()
        root, dep = w.package("tap"), w.package("django")
        _edge(root, "REQUIRES_PACKAGE", dep)
        program = w.program("tap-web")
        _edge(program, "RUNS_PACKAGE", root)
        host_a, host_b = w.image_host("a"), w.image_host("b")
        for host in (host_a, host_b):
            _edge(host, "INSTALLS_PACKAGE", dep)
        container_a, container_b = w.container("a", host_a), w.container("b", host_b)
        _edge(container_a, "RUNS_PROGRAM", program)  # only A runs it
        finding = w.finding(dep)
        rows = {r["container_id"]: r for r in _by(reach_rows(), finding)}
        assert rows[str(container_a.pk)]["owner_kind"] == "program"
        assert rows[str(container_b.pk)]["owner_kind"] == "container"
        assert rows[str(container_b.pk)]["owner_id"] == str(container_b.pk)

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-1")
    @pytest.mark.spec("req-fedramp-20x-vdr-reach-15")
    def test_one_program_in_two_containers_is_two_rows_and_the_container_makes_them_unique(self) -> None:
        w = World()
        root, dep = w.package("tap"), w.package("django")
        _edge(root, "REQUIRES_PACKAGE", dep)
        program = w.program("tap-web")
        _edge(program, "RUNS_PACKAGE", root)
        hosts = [w.image_host(n) for n in ("a", "b")]
        containers = [w.container(n, h) for n, h in zip("ab", hosts, strict=True)]
        for host, container in zip(hosts, containers, strict=True):
            _edge(host, "INSTALLS_PACKAGE", dep)
            _edge(container, "RUNS_PROGRAM", program)
        finding = w.finding(dep)
        rows = _by(reach_rows(), finding)
        assert len(rows) == 2
        assert {(r["owner_id"], r["container_id"]) for r in rows} == {(str(program.pk), str(c.pk)) for c in containers}
        assert all(r["container"] for r in rows)

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-1")
    def test_a_package_owned_by_two_programs_is_two_rows(self) -> None:
        w = World()
        shared = w.package("shared")
        programs = [w.program("one"), w.program("two")]
        host = w.image_host("x")
        _edge(host, "INSTALLS_PACKAGE", shared)
        container = w.container("x", host)
        for program in programs:
            _edge(program, "RUNS_PACKAGE", shared)
            _edge(container, "RUNS_PROGRAM", program)
        finding = w.finding(shared)
        rows = _by(reach_rows(), finding)
        assert sorted(r["owner_id"] for r in rows) == sorted(str(p.pk) for p in programs)
        assert {r["owner_kind"] for r in rows} == {"program"}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-3")
    def test_a_package_outside_every_closure_belongs_to_the_container_with_its_programs(self) -> None:
        w = World()
        root, system = w.package("tap"), w.package("glibc", "apk")
        program, gunicorn = w.program("tap-web"), w.program("gunicorn")
        _edge(program, "RUNS_PACKAGE", root)
        host = w.image_host("web")
        _edge(host, "INSTALLS_PACKAGE", root)
        _edge(host, "INSTALLS_PACKAGE", system)
        container = w.container("web", host)
        _edge(container, "RUNS_PROGRAM", gunicorn)
        _edge(gunicorn, "RUNS_PROGRAM", program)  # followed program to program
        finding = w.finding(system)
        (row,) = _by(reach_rows(), finding)
        assert (row["owner_kind"], row["owner_id"], row["container_id"]) == ("container", str(container.pk), str(container.pk))
        assert {p["id"] for p in row["programs"]} == {str(program.pk), str(gunicorn.pk)}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-4")
    def test_a_package_with_no_program_edge_is_never_dropped_or_treated_as_not_in_use(self) -> None:
        w = World()
        system = w.package("libfoo", "apk")
        host = w.image_host("web")
        _edge(host, "INSTALLS_PACKAGE", system)
        container = w.container("web", host)
        finding = w.finding(system)
        (row,) = _by(reach_rows(), finding)
        assert row["owner_kind"] == "container" and row["container_id"] == str(container.pk)
        assert row["programs"] == []  # a container that runs nothing the grid knows: the method reads that as high

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-5")
    def test_programs_an_operating_system_holds_are_not_the_containers(self) -> None:
        w = World()
        system = w.package("libfoo", "apk")
        host = w.image_host("web")
        _edge(host, "INSTALLS_PACKAGE", system)
        container = w.container("web", host)
        app, init = w.program("tap-web"), w.program("init")
        _edge(container, "RUNS_PROGRAM", app)
        wolfi = _node(C + "operating_system", {"os_id": "wolfi", "version_id": "1", "build_id": "sha256:" + "a" * 64, "rolling": True})
        _edge(wolfi, "RUNS_PROGRAM", init)  # the OS holds init
        finding = w.finding(system)
        (row,) = _by(reach_rows(), finding)
        assert [p["id"] for p in row["programs"]] == [str(app.pk)]
        assert str(init.pk) not in {p["id"] for p in row["programs"]}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-6")
    def test_a_library_finding_follows_its_loaders_into_their_containers(self) -> None:
        w = World()
        library = _node(C + "library", {"ecosystem": "generic", "name": "libssl", "version": "3", "language": "c", "source_kind": "self-built", "path": "/lib/libssl.so"})
        loaders = [w.program("one"), w.program("two")]
        host = w.image_host("web")
        container = w.container("web", host)
        for program in loaders:
            _edge(program, "LOADS_LIBRARY", library)
            _edge(container, "RUNS_PROGRAM", program)
        finding = w.finding(library, "f-lib")
        rows = _by(reach_rows(), finding)
        assert sorted(r["owner_id"] for r in rows) == sorted(str(p.pk) for p in loaders)
        assert {r["container_id"] for r in rows} == {str(container.pk)}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-6")
    def test_a_library_nobody_loads_yields_one_row_with_no_owner(self) -> None:
        w = World()
        library = _node(C + "library", {"ecosystem": "generic", "name": "libx", "version": "1", "language": "c", "source_kind": "self-built", "path": "/lib/libx.so"})
        finding = w.finding(library, "f-orphan")
        (row,) = _by(reach_rows(), finding)
        assert (row["owner_kind"], row["owner_id"], row["container_id"], row["programs"]) == ("none", None, None, [])

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-4")
    def test_a_finding_nothing_carries_or_no_container_installs_still_has_a_row(self) -> None:
        w = World()
        loose = w.package("loose")  # installed by no host
        carried = w.finding(loose)
        bare = _node(FINDING, {"source": "t", "source_key": "bare", "name": "bare", "status": "open"})
        create_edge(bare, w.vuln, CONCERNS)
        rows = reach_rows()
        assert _by(rows, carried)[0]["owner_kind"] == "none"
        assert _by(rows, bare)[0]["owner_kind"] == "none"

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-7")
    def test_every_row_carries_the_programs_list_and_json_safe_values(self) -> None:
        import json

        w = World()
        pkg = w.package("tap")
        program = w.program("p")
        _edge(program, "RUNS_PACKAGE", pkg)
        host = w.image_host("x")
        _edge(host, "INSTALLS_PACKAGE", pkg)
        _edge(w.container("x", host), "RUNS_PROGRAM", program)
        w.finding(pkg)
        rows = reach_rows()
        assert all(set(r) >= {"programs", "container_id", "container", "owner_kind", "component_id"} for r in rows)
        json.dumps(rows)


class TestScope:
    @pytest.mark.spec("req-fedramp-20x-vdr-reach-9")
    def test_a_resolved_or_unlinked_finding_yields_no_row(self) -> None:
        w = World()
        pkg = w.package("tap")
        host = w.image_host("x")
        _edge(host, "INSTALLS_PACKAGE", pkg)
        w.container("x", host)
        w.finding(pkg, "open")
        w.finding(pkg, "closed", status="resolved")
        w.finding(pkg, "unlinked", linked=False)
        assert {r["finding_id"] for r in reach_rows()} == {str(Entity.objects.get(name="open").pk)}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-12")
    def test_a_tombstoned_node_contributes_nothing(self) -> None:
        w = World()
        root, dep = w.package("tap"), w.package("django")
        _edge(root, "REQUIRES_PACKAGE", dep)
        program = w.program("tap-web")
        _edge(program, "RUNS_PACKAGE", root)
        host = w.image_host("x")
        _edge(host, "INSTALLS_PACKAGE", dep)
        container = w.container("x", host)
        _edge(container, "RUNS_PROGRAM", program)
        finding = w.finding(dep)
        assert _by(reach_rows(), finding)[0]["owner_kind"] == "program"
        assert delete_node(program.pk).success
        assert _by(reach_rows(), finding)[0]["owner_kind"] == "container"

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-11")
    def test_nothing_is_stored(self) -> None:
        w = World()
        pkg = w.package("tap")
        w.finding(pkg)
        before = (Entity.objects.count(), Entity.objects.filter(deleted_at__isnull=False).count())
        reach_rows()
        assert (Entity.objects.count(), Entity.objects.filter(deleted_at__isnull=False).count()) == before

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-10")
    def test_the_base_reads_no_profile_and_ships_no_profile_vocabulary(self) -> None:
        from pathlib import Path

        source = Path(reach.__file__).read_text().lower()
        for word in ("asset.cr", "asset.ir", "asset.ar", "archetype", "stamp"):
            assert word not in source.replace("no stamp", "")

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-13")
    def test_it_is_importable_and_registered_and_runs_through_the_search_service(self) -> None:
        from tap_grid.registry import get_search_runner

        assert get_search_runner("tap_plugin.fedramp_20x_vdr.searches.reach:vdr-reach") is vdr_reach
        w = World()
        pkg = w.package("tap")
        w.finding(pkg)
        search = Search(
            search_type="module",
            root="node",
            name="vdr-reach",
            definition={"runner_key": "tap_plugin.fedramp_20x_vdr.searches.reach:vdr-reach"},
            input_schema={"type": "object", "properties": {"max_results": {"type": "integer", "default": 10}}},
        )
        envelope = execute_search(search, {})
        assert envelope["nodes"] == [] and envelope["edges"] == [] and len(envelope["rows"]) == 1

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-14")
    def test_the_manifest_depends_on_computing_core(self) -> None:
        from pathlib import Path

        manifest = (Path(reach.__file__).parents[1] / "tap-plugin.toml").read_text()
        assert 'slug = "computing_core"' in manifest and "v0.10.2" in manifest

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-12")
    @pytest.mark.parametrize(
        ("bad", "match"),
        [({"entity_id": 7}, "entity_id"), ({"entity_id": ""}, "entity_id"), ({"max_results": 0}, "max_results"), ({"max_results": 5001}, "max_results"), ({"max_results": True}, "max_results")],
    )
    def test_a_bad_input_is_refused_naming_it(self, bad: dict[str, Any], match: str) -> None:
        with pytest.raises(ValueError, match=match):
            reach_rows(bad)

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-1")
    def test_entity_id_limits_the_rows_and_the_library_function_returns_everything_by_default(self) -> None:
        w = World()
        a, b = w.package("a"), w.package("b")
        fa, _fb = w.finding(a), w.finding(b)
        assert {r["finding_id"] for r in reach_rows({"entity_id": str(fa.pk)})} == {str(fa.pk)}
        assert len(reach_rows()) == 2
        assert len(reach_rows({"max_results": 1})) == 1

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-11")
    def test_the_runner_says_how_many_rows_it_left_out(self) -> None:
        w = World()
        for name in ("a", "b", "c"):
            w.finding(w.package(name))
        out = vdr_reach(Search(), {"max_results": 1}, db_alias="default")
        assert len(out["rows"]) == 1 and out["info"] == {"row_count": 1, "total_rows": 3}
        assert out["warnings"]["rows_omitted"] == ["2 of 3 rows were left out; max_results is 1"]
        full = vdr_reach(Search(), {}, db_alias="default")
        assert len(full["rows"]) == 3 and full["warnings"] == {}

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-1")
    def test_two_components_with_one_name_are_two_rows(self) -> None:
        w = World()
        one = _node(C + "package", {"ecosystem": "pypi", "name": "dup", "version": "1.0"})
        two = _node(C + "package", {"ecosystem": "pypi", "name": "dup", "version": "2.0"})
        finding = w.finding(one, "f-dup")
        create_edge(two, finding, CARRIES)
        rows = _by(reach_rows(), finding)
        assert sorted(r["component_id"] for r in rows) == sorted([str(one.pk), str(two.pk)])
