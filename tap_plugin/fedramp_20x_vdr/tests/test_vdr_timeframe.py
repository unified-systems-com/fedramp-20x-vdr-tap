"""The timeframe seed and the evidence-basis list (`req-fedramp-20x-vdr-timeframe`, `-evidence`).

The seed is FedRAMP's own tables, read as raw HTML on 2026-10-16, so these tests check the file
against itself and against the model: 53 rows, hours converted exactly from the quoted cell, no
invented row for PAIN N0 or N1, every row citing its source, and the worst-case row being a true
bound (every row and column is non-decreasing as a factor is lowered).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration

from tap_grid.grift import grift_import
from tap_grid.registry import get_model_class

PACKAGE = Path(__file__).resolve().parents[1]
TYPE = "fedramp_20x_vdr__vdr_timeframe"


def _rows() -> list[dict[str, Any]]:
    document = json.loads((PACKAGE / "grift" / "timeframes.grift.json").read_text(encoding="utf-8"))
    return [node["node"] for node in document["batches"][0]["nodes"]]


def _hours(cell: str) -> int:
    match = re.fullmatch(r"(\d+) (day|days|hour|hours)", cell)
    assert match, cell
    amount = int(match.group(1))
    return amount * 24 if match.group(2).startswith("day") else amount


def _cell(rows: list[dict[str, Any]], **where: str) -> dict[str, Any]:
    (found,) = [r for r in rows if all(r[k] == v for k, v in where.items())]
    return found


class TestSeedContent:
    def test_fifty_three_rows_of_three_rules(self) -> None:
        """req-fedramp-20x-vdr-timeframe-2."""
        rows = _rows()
        by_rule = {rule: sum(r["rule"] == rule for r in rows) for rule in {r["rule"] for r in rows}}
        assert len(rows) == 53
        assert by_rule == {"VDR-TFR-PVR": 48, "VER-TFR-EVU": 4, "VER-TFR-MAV": 1}

    def test_every_pvr_cell_exists_once(self) -> None:
        pvr = [r for r in _rows() if r["rule"] == "VDR-TFR-PVR"]
        keys = {(r["fedramp_class"], r["pain"], r["exposure"]) for r in pvr}
        assert keys == {
            (c, p, e) for c in "abcd" for p in ("N2", "N3", "N4", "N5") for e in ("lev_irv", "lev_nirv", "nlev")
        }
        assert len(keys) == len(pvr), "no cell is seeded twice"

    def test_hours_match_the_quoted_cell_exactly(self) -> None:
        """req-fedramp-20x-vdr-timeframe-3: days times 24, hours as stated."""
        for row in _rows():
            assert row["hours"] == _hours(row["canon_cell"]), row

    def test_no_row_for_pain_n0_or_n1(self) -> None:
        """req-fedramp-20x-vdr-timeframe-4: the pages publish none, so the plugin invents none."""
        assert not [r for r in _rows() if r["pain"] in ("N0", "N1")]

    def test_every_row_cites_its_source(self) -> None:
        """req-fedramp-20x-vdr-timeframe-5."""
        for row in _rows():
            assert row["canon_cell"] and row["canon_read_at"] == "2026-10-16", row
            assert row["canon_url"].startswith("https://www.fedramp.gov/2026/reference/"), row

    def test_the_cells_the_spec_names(self) -> None:
        rows = _rows()
        assert _cell(rows, rule="VDR-TFR-PVR", fedramp_class="d", pain="N5", exposure="lev_irv")["hours"] == 12
        assert _cell(rows, rule="VDR-TFR-PVR", fedramp_class="d", pain="N5", exposure="lev_nirv")["hours"] == 24
        assert _cell(rows, rule="VER-TFR-EVU", fedramp_class="d")["hours"] == 48
        assert _cell(rows, rule="VER-TFR-EVU", fedramp_class="a")["hours"] == 14 * 24
        assert _cell(rows, rule="VER-TFR-MAV")["hours"] == 192 * 24

    def test_class_a_and_b_are_identical_on_the_page_and_both_seeded(self) -> None:
        rows = _rows()
        a = {
            (r["pain"], r["exposure"]): r["hours"]
            for r in rows
            if r["rule"] == "VDR-TFR-PVR" and r["fedramp_class"] == "a"
        }
        b = {
            (r["pain"], r["exposure"]): r["hours"]
            for r in rows
            if r["rule"] == "VDR-TFR-PVR" and r["fedramp_class"] == "b"
        }
        assert a == b and len(a) == 12

    def test_the_worst_case_row_is_a_bound(self) -> None:
        """req-fedramp-20x-vdr-effective-5: lowering a factor never shortens the interval."""
        rows = [r for r in _rows() if r["rule"] == "VDR-TFR-PVR"]
        exposures = ["lev_irv", "lev_nirv", "nlev"]
        pains = ["N5", "N4", "N3", "N2"]
        for cls in "abcd":
            grid = {(r["pain"], r["exposure"]): r["hours"] for r in rows if r["fedramp_class"] == cls}
            for pain in pains:
                series = [grid[(pain, e)] for e in exposures]
                assert series == sorted(series), (cls, pain, series)
            for exposure in exposures:
                series = [grid[(p, exposure)] for p in pains]
                assert series == sorted(series), (cls, exposure, series)
            assert grid[("N5", "lev_irv")] == min(grid.values()), cls


@pytest.mark.django_db
class TestSeedImport:
    def test_the_bundle_imports_and_reimporting_is_a_no_op(self) -> None:
        """req-fedramp-20x-vdr-timeframe-1: the key is the cell, so re-seeding changes nothing."""
        document = json.loads((PACKAGE / "grift" / "timeframes.grift.json").read_text(encoding="utf-8"))
        model = get_model_class(TYPE)
        first = grift_import(document)
        assert first.success, first.errors
        assert model.objects.live().count() == 53
        second = grift_import(document)
        assert second.success, second.errors
        assert model.objects.live().count() == 53

    def test_a_row_reads_back_with_its_display_name_and_dimension(self) -> None:
        grift_import(json.loads((PACKAGE / "grift" / "timeframes.grift.json").read_text(encoding="utf-8")))
        row = (
            get_model_class(TYPE)
            .objects.live()
            .get(rule="VDR-TFR-PVR", fedramp_class="d", pain="N5", exposure="lev_irv")
        )
        row.entity.refresh_from_db()
        assert row.hours == 12
        assert row.entity.name == "VDR-TFR-PVR d N5 lev_irv"
        assert row.entity.dimensions.get("fedramp.rule") == "vdr"


class TestEvidenceBasisList:
    def _data(self) -> dict[str, Any]:
        return json.loads((PACKAGE / "data" / "evidence_basis.json").read_text(encoding="utf-8"))

    def test_the_list_validates_against_its_schema(self) -> None:
        """req-fedramp-20x-vdr-evidence-4."""
        schema = json.loads((PACKAGE / "data" / "evidence_basis.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(self._data(), schema, format_checker=jsonschema.FormatChecker())

    def test_keys_are_unique(self) -> None:
        keys = [b["key"] for b in self._data()["bases"]]
        assert len(keys) == len(set(keys)) == 9

    def test_the_edge_enum_is_the_list(self) -> None:
        """The enum on the edge definition is the enforced copy; it must equal the data file's keys."""
        edge = json.loads(
            (PACKAGE / "edges" / "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr.edge.json").read_text(encoding="utf-8")
        )
        enum = edge["property_schema"]["properties"]["basis"]["enum"]
        assert enum == [b["key"] for b in self._data()["bases"]]
