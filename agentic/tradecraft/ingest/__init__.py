"""Tradecraft 2.0 ingestion: from a resource's URL to its map, cards and stored pages.

``fetch`` (pages through ``net.get_fetcher()``, cleaning to Markdown), ``detect`` (the site
type), ``builders`` (one map builder per known type) and ``crawl`` (any other website) are
ports of the 1.x verify path that read every limit from ``EffectiveSettings``; with the
defaults they behave as 1.x does. ``pipeline`` runs them as a job's stages (T1.8). Nothing
here imports the 1.x modules except the pure helpers of ``orchestrator_helpers.web_sources``.
"""
