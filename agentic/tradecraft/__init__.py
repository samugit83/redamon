"""Tradecraft 2.0: the resource library's ingestion, store and query side.

Built beside the 1.x path (``orchestrator_helpers/tradecraft_lookup.py``) and reached
only when the owner's switch is on, until the cut-over removes 1.x. ``net.py`` is the
only module of this package that reaches the web (``tests/test_tradecraft_fetcher_contract.py``
holds that rule), and ``clock.py`` the only source of time, so every test can replace both.
"""
