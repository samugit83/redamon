"""The Tradecraft library service: what the agent's tradecraft tools read.

``types.py`` holds the result types and the text formats the agent sees (Q7.1 search, Q7.1
browse, Q8 read, Q9.5 librarian), ``page_ids.py`` the page ID format and its resolution.
Search, browse, reading, the coverage map and the hints build on them in later phases;
every query is keyed by the owner and the resource, and reads the resource's live generation.
"""
