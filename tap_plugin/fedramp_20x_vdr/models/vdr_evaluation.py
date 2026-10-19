"""VDR evaluation — one finding's FedRAMP evaluation: likely exploitable, internet-reachable, PAIN."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_NULLABLE_STRING: dict[str, Any] = {"type": ["string", "null"]}
_NULLABLE_BOOL: dict[str, Any] = {"type": ["boolean", "null"]}


class VdrEvaluation(BaseModel):
    """One finding's evaluation under FedRAMP's Vulnerability Detection and Response rules.

    The evaluation answers three questions FedRAMP asks of every detected vulnerability: is it a
    likely exploitable vulnerability (VER-EVA-ELX), is it internet-reachable (VER-EVA-EIR), and
    what is the potential agency impact (VER-EVA-EPA, rated N0 to N5). It is a node of its own,
    not fields on the finding, because it is a judgement made by a party at a time with a
    rationale and evidence, while `compliance_finding` records a scanner's observation.

    Every factor is `null` until observed, and `null` is the worst case: every shipped Search
    reads an unset factor as likely exploitable, internet-reachable, N5, and counts a set factor
    only when an evidence edge backs it. The stored fields are raw inputs, never answers. In v0
    `pain` cannot be set at all, because no evidence basis for lowering PAIN exists yet
    (`req-fedramp-20x-vdr-evaluation-6`).

    Spec: specs/spec-fedramp-20x-vdr-v0.md (req-fedramp-20x-vdr-evaluation).
    """

    ENTITY_TYPE: ClassVar[str] = "fedramp_20x_vdr__vdr_evaluation"
    # The finding evaluated, by the finding's own identity (compliance_core keys a finding on
    # ("source", "source_key")), copied verbatim into two columns so the evaluation is found
    # again on any grid the finding is. A check reports an evaluation whose key and the key of
    # the finding it EVALUATES disagree (req-fedramp-20x-vdr-evaluation-4); an edge cannot be
    # validated against a node's fields when the node is written.
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("finding_source", "finding_source_key")
    ENTITY_NAME: ClassVar[str] = "VDR Evaluation"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One finding's FedRAMP Vulnerability Detection and Response evaluation: likely exploitable, "
        "internet-reachable and potential agency impact. Unset factors read as the worst case."
    )
    ENTITY_ICON: ClassVar[str] = "vdr-evaluation"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"fedramp.rule": "vdr"}

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "compliance_core__compliance_finding"}],
            "edges": [{"type": "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"}],
        },
        {
            "nodes": [{"type": "compliance_core__compliance_evidence"}],
            "edges": [{"type": "CITES_FACTOR_EVIDENCE__fedramp_20x_vdr"}],
        },
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "finding_source": {"type": "string", "minLength": 1, "maxLength": 64},
        "finding_source_key": {"type": "string", "minLength": 1, "maxLength": 512},
        "likely_exploitable": _NULLABLE_BOOL,
        "internet_reachable": _NULLABLE_BOOL,
        # v0: PAIN stays null. No evidence basis for lowering PAIN exists, so a non-null value
        # could never be backed (req-fedramp-20x-vdr-evaluation-6, -evidence-6). The refusal is
        # lifted, with an N0..N5 enum, when the PAIN basis list is specified.
        "pain": {"type": "null"},
        "evaluator": {"type": ["string", "null"], "maxLength": 255},
        "evaluated_at": {"type": ["string", "null"], "format": "date-time"},
        "rationale": _NULLABLE_STRING,
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["finding_source", "finding_source_key"]

    finding_source = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="The `source` of the finding evaluated, verbatim. Half of the identity.",
    )
    finding_source_key = models.CharField(
        max_length=512,
        blank=True,
        default="",
        db_index=True,
        help_text="The `source_key` of the finding evaluated, verbatim. Other half of the identity.",
    )
    likely_exploitable = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="VER-EVA-ELX. Null = unobserved, which every Search reads as the worst case (true).",
    )
    internet_reachable = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="VER-EVA-EIR. Null = unobserved, which every Search reads as the worst case (true).",
    )
    pain = models.CharField(  # noqa: DJ001  (req-fedramp-20x-vdr-evaluation-2)
        max_length=2,
        null=True,
        blank=True,
        default=None,
        help_text="VER-EVA-EPA, N0 to N5. Null = unobserved, read as N5. Cannot be set in v0.",
    )
    evaluator = models.CharField(  # noqa: DJ001  (req-fedramp-20x-vdr-evaluation-2)
        max_length=255,
        null=True,
        blank=True,
        default=None,
        help_text="Who made the evaluation. Null = nobody has.",
    )
    evaluated_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="When the evaluation was made. Null = not yet evaluated.",
    )
    rationale = models.TextField(
        null=True,  # noqa: DJ001  (req-fedramp-20x-vdr-evaluation-2)
        blank=True,
        default=None,
        help_text="Why, in the evaluator's words. Null = unobserved.",
    )

    class Meta(BaseModel.Meta):
        db_table = "fedramp_20x_vdr__vdr_evaluation"

    def get_name(self) -> str:
        return f"VDR {self.finding_source_key}"

    def __str__(self) -> str:
        return self.get_name()
