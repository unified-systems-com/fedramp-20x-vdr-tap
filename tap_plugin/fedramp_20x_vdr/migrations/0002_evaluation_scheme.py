"""An evaluation carries a scheme, so several algorithms can evaluate one finding.

`scheme` joins the natural key (`req-fedramp-20x-vdr-evaluation-1`, `-7`). Every evaluation that exists was
written by the VDR-max collector, so the column is added with `max` for the rows already there; the model's own
default is the empty string, which the schema refuses, so a new write must name its scheme. The second step stamps
the `vdr.scheme: max` dimension on those evaluations and on their `EVALUATES_COMPLIANCE_FINDING` edges
(`req-fedramp-20x-vdr-evaluation-9`).
"""

from django.db import migrations, models

EVALUATION_TYPE = "fedramp_20x_vdr__vdr_evaluation"
EVALUATES_EDGE = "EVALUATES_COMPLIANCE_FINDING__fedramp_20x_vdr"
SCHEME_DIMENSION = "vdr.scheme"


def stamp_existing_as_max(apps, schema_editor):
    """Stamp `vdr.scheme: max` on every existing evaluation and its edge; leave anything already stamped alone."""
    Entity = apps.get_model("tap_grid", "Entity")
    Edge = apps.get_model("tap_grid", "Edge")
    db = schema_editor.connection.alias
    edge_entity_ids = list(
        Edge.objects.using(db).filter(edge_type=EVALUATES_EDGE).values_list("entity_id", flat=True)
    )
    for entities in (
        Entity.objects.using(db).filter(entity_type=EVALUATION_TYPE),
        Entity.objects.using(db).filter(pk__in=edge_entity_ids),
    ):
        for entity in entities:
            dimensions = dict(entity.dimensions or {})
            if SCHEME_DIMENSION not in dimensions:
                dimensions[SCHEME_DIMENSION] = "max"
                Entity.objects.using(db).filter(pk=entity.pk).update(dimensions=dimensions)


class Migration(migrations.Migration):

    dependencies = [
        ("fedramp_20x_vdr", "0001_initial"),
        ("tap_grid", "0007_batchevent_authority_proposed"),
    ]

    operations = [
        # Existing rows are the VDR-max collector's: they take `max`.
        migrations.AddField(
            model_name="vdrevaluation",
            name="scheme",
            field=models.CharField(db_index=True, default="max", max_length=64),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="historicalvdrevaluation",
            name="scheme",
            field=models.CharField(db_index=True, default="max", max_length=64),
            preserve_default=False,
        ),
        # The final definition: the model's default is empty, so an unnamed scheme is refused by the schema.
        migrations.AlterField(
            model_name="vdrevaluation",
            name="scheme",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="The algorithm or method that made this evaluation (`max` for VDR-max). Part of the identity.",
                max_length=64,
            ),
        ),
        migrations.AlterField(
            model_name="historicalvdrevaluation",
            name="scheme",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text="The algorithm or method that made this evaluation (`max` for VDR-max). Part of the identity.",
                max_length=64,
            ),
        ),
        # The natural-key index now covers the scheme as well.
        migrations.RemoveIndex(model_name="vdrevaluation", name="nk_fedramp_20x_vdr__vd_2fff5b7"),
        migrations.AddIndex(
            model_name="vdrevaluation",
            index=models.Index(
                fields=["finding_source", "finding_source_key", "scheme"], name="nk_fedramp_20x_vdr__vd_2fff5b7"
            ),
        ),
        migrations.RunPython(stamp_existing_as_max, migrations.RunPython.noop),
    ]
