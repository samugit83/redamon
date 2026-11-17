"""Tradecraft 2.0: the resource library's ingestion, store and query side.

The only tradecraft path since the cut-over (T9.2) removed 1.x and its page cache. ``net.py`` is the
only module of this package that reaches the web (``tests/test_tradecraft_fetcher_contract.py``
holds that rule), and ``clock.py`` the only source of time, so every test can replace both.
"""
