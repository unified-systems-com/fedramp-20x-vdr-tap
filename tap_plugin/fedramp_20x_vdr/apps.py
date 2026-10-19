"""TAP FedRAMP 20x VDR plugin AppConfig."""

from tap_plugins.base import TapPluginConfig


class FedrampVdrConfig(TapPluginConfig):
    def ready(self) -> None:
        super().ready()  # MUST run first: it loads tap-plugin.toml

        # Inside ready(), not at module top, to keep app loading light.
        from tap_plugin.fedramp_20x_vdr.collectors.vdr_max.collector import VdrMaxCollector

        from tap_cares.registry import register_collector

        register_collector(
            key="vdr_max",
            # Stable scope (the plugin slug), so the collector's derived entity id survives module
            # renames (req-tap-cares-collector-model-10).
            scope="fedramp_20x_vdr",
            cls=VdrMaxCollector,
            name="FedRAMP 20x VDR Max Evaluations",
            description=(
                "Gives every open compliance finding that concerns a vulnerability a VDR evaluation with "
                "every factor unset, which every Search reads as the worst case. Reads the grid, calls no "
                "external service and needs no credential. Never touches an evaluation that already exists."
            ),
        )
