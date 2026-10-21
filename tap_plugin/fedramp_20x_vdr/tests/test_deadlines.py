"""The deadline lookup over the seeded timeframe rows (`req-fedramp-20x-vdr-pain-5` to `-7`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import tap_plugin.fedramp_20x_vdr.models as vdr  # noqa: F401 - trigger model registration
from tap_plugin.fedramp_20x_vdr import deadlines

from tap_grid.grift import grift_import

PACKAGE = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.django_db(transaction=True, databases=["default", "search_readonly"])


@pytest.fixture(autouse=True)
def seeded() -> None:
    result = grift_import(json.loads((PACKAGE / "grift" / "timeframes.grift.json").read_text(encoding="utf-8")))
    assert result.success, result.errors


@pytest.mark.spec("req-fedramp-20x-vdr-pain-5")
def test_class_d_n5_lev_irv_is_twelve_hours() -> None:
    assert deadlines.deadline_hours("d", "N5", "lev_irv") == 12


@pytest.mark.spec("req-fedramp-20x-vdr-pain-5")
@pytest.mark.parametrize("fedramp_class", deadlines.CLASSES)
@pytest.mark.parametrize("pain", ["N2", "N3", "N4", "N5"])
@pytest.mark.parametrize("column", ["lev_irv", "lev_nirv", "nlev"])
def test_every_published_cell_returns_its_seeded_hours(fedramp_class: str, pain: str, column: str) -> None:
    hours = deadlines.deadline_hours(fedramp_class, pain, column)
    assert isinstance(hours, int) and hours >= 1


@pytest.mark.spec("req-fedramp-20x-vdr-pain-5")
def test_a_stricter_class_never_gets_longer() -> None:
    for pain in ("N2", "N3", "N4", "N5"):
        for column in ("lev_irv", "lev_nirv", "nlev"):
            hours = [deadlines.deadline_hours(c, pain, column) for c in deadlines.CLASSES]
            assert hours == sorted(hours, reverse=True), (pain, column, hours)


@pytest.mark.spec("req-fedramp-20x-vdr-pain-6")
@pytest.mark.parametrize("column", ["lev_irv", "lev_nirv", "nlev"])
def test_n1_has_no_timeframe_and_returns_none_not_zero(column: str) -> None:
    assert deadlines.deadline_hours("d", "N1", column) is None


@pytest.mark.spec("req-fedramp-20x-vdr-pain-7")
def test_it_returns_hours_not_dates() -> None:
    assert isinstance(deadlines.deadline_hours("a", "N2", "nlev"), int)


@pytest.mark.spec("req-fedramp-20x-vdr-pain-2")
@pytest.mark.parametrize(
    "args", [("z", "N5", "lev_irv"), ("d", "N0", "lev_irv"), ("d", "N5", "everything"), ("D", "N5", "lev_irv")]
)
def test_a_value_outside_the_vocabulary_is_refused(args: tuple[str, str, str]) -> None:
    with pytest.raises(ValueError):
        deadlines.deadline_hours(*args)


@pytest.mark.spec("req-fedramp-20x-vdr-pain-5")
def test_an_unseeded_published_cell_is_a_data_fault_not_a_none() -> None:
    from tap_plugin.fedramp_20x_vdr.models import VdrTimeframe

    from tap_grid.services import delete_node

    row = VdrTimeframe.objects.get(rule="VDR-TFR-PVR", fedramp_class="d", pain="N5", exposure="lev_irv")
    assert delete_node(row.entity_id).success
    with pytest.raises(LookupError, match="N5"):
        deadlines.deadline_hours("d", "N5", "lev_irv")
