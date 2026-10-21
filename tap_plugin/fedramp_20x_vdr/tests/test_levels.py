"""The pure PAIN module (`req-fedramp-20x-vdr-pain-1` to `-3`, `-8`) and the profile reduction (`req-fedramp-20x-vdr-reach-8`)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from tap_plugin.fedramp_20x_vdr import levels

LEVELS_FILE = Path(levels.__file__)


class TestPure:
    @pytest.mark.spec("req-fedramp-20x-vdr-pain-1")
    def test_it_imports_and_runs_with_django_blocked(self) -> None:
        """A fresh interpreter, with Django and the grid unimportable, loads the module and gets the same answers."""
        program = (
            "import importlib.abc, importlib.util, sys\n"
            "class Block(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] in ('django', 'tap_grid', 'tap_cares', 'tap_plugin'):\n"
            "            raise ImportError('blocked: ' + name)\n"
            "sys.meta_path.insert(0, Block())\n"
            f"spec = importlib.util.spec_from_file_location('levels', {str(LEVELS_FILE)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "print(m.exposure_column(True, True), m.reduce_profiles([('low','medium','high'),('medium','low','low')]))\n"
        )
        out = subprocess.run([sys.executable, "-I", "-c", program], capture_output=True, text=True, check=True)  # noqa: S603
        assert out.stdout.strip() == "lev_irv ('medium', 'medium', 'high')"

    @pytest.mark.spec("req-fedramp-20x-vdr-pain-1")
    def test_it_is_deterministic(self) -> None:
        profiles = [("low", "high", None), ("medium", "low", "low")]
        assert levels.reduce_profiles(profiles) == levels.reduce_profiles(list(profiles))


class TestLevels:
    @pytest.mark.spec("req-fedramp-20x-vdr-pain-2")
    def test_levels_compare_in_order(self) -> None:
        assert levels.LEVELS == ("N1", "N2", "N3", "N4", "N5")
        ranks = [levels.level_rank(level) for level in levels.LEVELS]
        assert ranks == sorted(ranks) == [0, 1, 2, 3, 4]

    @pytest.mark.spec("req-fedramp-20x-vdr-pain-2")
    @pytest.mark.parametrize("bad", ["N0", "N6", "n3", "", "high", None, 3])
    def test_a_level_outside_the_five_is_refused(self, bad: object) -> None:
        with pytest.raises(ValueError):
            levels.level_rank(bad)  # type: ignore[arg-type]

    @pytest.mark.spec("req-fedramp-20x-vdr-pain-3")
    @pytest.mark.parametrize(
        ("likely", "reachable", "column"),
        [(True, True, "lev_irv"), (True, False, "lev_nirv"), (False, True, "nlev"), (False, False, "nlev")],
    )
    def test_the_exposure_column(self, likely: bool, reachable: bool, column: str) -> None:
        assert levels.exposure_column(likely, reachable) == column

    @pytest.mark.spec("req-fedramp-20x-vdr-pain-3")
    @pytest.mark.parametrize(
        ("likely", "reachable", "column"),
        [(None, None, "lev_irv"), (None, False, "lev_nirv"), (None, True, "lev_irv"), (True, None, "lev_irv"), (False, None, "nlev"), (True, False, "lev_nirv")],
    )
    def test_an_unknown_factor_reads_as_true_so_unknown_never_picks_a_lenient_column(
        self, likely: bool | None, reachable: bool | None, column: str
    ) -> None:
        assert levels.exposure_column(likely, reachable) == column

    @pytest.mark.spec("req-fedramp-20x-vdr-pain-8")
    def test_the_module_ships_no_formula_weight_or_threshold(self) -> None:
        source = LEVELS_FILE.read_text()
        for word in ("weight", "threshold", "theta", "epss", "kev", "cvss"):
            assert word not in source.lower().replace("no weight or threshold", "")


class TestReduction:
    @pytest.mark.spec("req-fedramp-20x-vdr-reach-8")
    def test_it_takes_the_per_objective_maximum(self) -> None:
        got = levels.reduce_profiles([("low", "medium", "high"), ("medium", "low", "low"), ("low", "low", "medium")])
        assert got == ("medium", "medium", "high")

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-8")
    def test_a_single_profile_is_returned_as_it_is(self) -> None:
        assert levels.reduce_profiles([("low", "medium", "low")]) == ("low", "medium", "low")

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-8")
    @pytest.mark.parametrize(
        "profiles",
        [[], [None], [(None, None, None)], [("low", "low", "low"), None]],
    )
    def test_an_empty_list_a_missing_profile_or_a_missing_value_counts_as_high(self, profiles: list) -> None:
        got = levels.reduce_profiles(profiles)
        assert got == ("high", "high", "high")

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-8")
    def test_a_missing_value_raises_only_its_own_objective(self) -> None:
        assert levels.reduce_profiles([("low", None, "low")]) == ("low", "high", "low")

    @pytest.mark.spec("req-fedramp-20x-vdr-reach-8")
    @pytest.mark.parametrize("bad", [[("low", "low")], [("low", "low", "huge")], [("Low", "low", "low")]])
    def test_a_malformed_profile_is_refused(self, bad: list) -> None:
        with pytest.raises(ValueError):
            levels.reduce_profiles(bad)
