"""VDR timeframe — one cell of a FedRAMP timeframe table, as a seeded row."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_RULES = ["VDR-TFR-PVR", "VER-TFR-EVU", "VER-TFR-MAV"]
_CLASSES = ["a", "b", "c", "d", "all"]
# N0 and N1 have no published timeframe (observed 2026-10-16), so no row may carry them.
_PAINS = ["N2", "N3", "N4", "N5", ""]
_EXPOSURES = ["lev_irv", "lev_nirv", "nlev", ""]


class VdrTimeframe(BaseModel):
    """One cell of a FedRAMP timeframe table: how long a class has to act, in whole hours.

    FedRAMP states its deadlines as tables: the time to partially mitigate, fully mitigate or
    remediate to a lower PAIN (VDR-TFR-PVR, by class, PAIN and exposure), the time to evaluate
    (VER-TFR-EVU, by class) and the time after which an unfixed vulnerability is an accepted
    vulnerability (VER-TFR-MAV). Each cell is a row that quotes the page cell and the date it was
    read, so a changed table is a changed seed file and any row can be checked against its source.

    `pain` and `exposure` are `""` on the rules that have no such dimension: the rule was looked
    at and has none, which is observed-empty, not unobserved.

    Spec: specs/spec-fedramp-20x-vdr-v0.md (req-fedramp-20x-vdr-timeframe).
    """

    ENTITY_TYPE: ClassVar[str] = "fedramp_20x_vdr__vdr_timeframe"
    # The cell's coordinates. `pain` and `exposure` are "" (observed-empty) on rules without
    # them, which the generated search matches like any other value.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("rule", "fedramp_class", "pain", "exposure")
    ENTITY_NAME: ClassVar[str] = "VDR Timeframe"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One cell of a FedRAMP Vulnerability Detection and Response timeframe table, in whole hours, "
        "quoting the page cell it was read from."
    )
    ENTITY_ICON: ClassVar[str] = "vdr-timeframe"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"fedramp.rule": "vdr"}

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "rule": {"type": "string", "enum": _RULES},
        "fedramp_class": {"type": "string", "enum": _CLASSES},
        "pain": {"type": "string", "enum": _PAINS},
        "exposure": {"type": "string", "enum": _EXPOSURES},
        "hours": {"type": "integer", "minimum": 1},
        "canon_cell": {"type": "string", "minLength": 1, "maxLength": 64},
        "canon_read_at": {"type": "string", "format": "date"},
        "canon_url": {"type": "string", "minLength": 1, "maxLength": 512},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = [
        "rule",
        "fedramp_class",
        "hours",
        "canon_cell",
        "canon_read_at",
        "canon_url",
    ]

    rule = models.CharField(max_length=16, blank=True, default="", db_index=True)
    fedramp_class = models.CharField(max_length=3, blank=True, default="")
    pain = models.CharField(max_length=2, blank=True, default="", help_text='"" where the rule has no PAIN dimension.')
    exposure = models.CharField(
        max_length=8, blank=True, default="", help_text='"" where the rule has no exposure dimension.'
    )
    hours = models.PositiveIntegerField(
        null=True, blank=True, default=None, help_text="The interval in whole hours, converted exactly from canon_cell."
    )
    canon_cell = models.CharField(
        max_length=64, blank=True, default="", help_text="The page cell, as the page states it."
    )
    canon_read_at = models.DateField(null=True, blank=True, default=None, help_text="The date the page was read.")
    canon_url = models.CharField(max_length=512, blank=True, default="", help_text="The page the cell comes from.")

    class Meta(BaseModel.Meta):
        db_table = "fedramp_20x_vdr__vdr_timeframe"

    def get_name(self) -> str:
        return " ".join(part for part in (self.rule, self.fedramp_class, self.pain, self.exposure) if part)

    def __str__(self) -> str:
        return self.get_name()
