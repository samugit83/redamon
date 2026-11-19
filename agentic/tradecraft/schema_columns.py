"""The table and column names the agent reads and writes with raw SQL (master plan TD-5).

The webapp owns the schema (``webapp/prisma/schema.prisma``); the agent writes the
ingestion output itself, so every name it uses is listed here once and
``tests/test_tradecraft_schema_columns.py`` checks each against the schema, together with
every column an INSERT must supply. Build SQL from these constants, never from literals
spread across modules, and never from ``RESOURCE_SECRET_COLUMNS``.

Two schema facts the writers rely on:

- ``updated_at`` is set by the Prisma client, not by Postgres, on UPDATE: a raw UPDATE sets
  it itself. INSERTs get the database default.
- ``search_vector`` of an entry and of a section is filled by a trigger
  (``webapp/scripts/apply-tradecraft-search.mjs``): writers never compute it, and readers
  query it with the same text search configuration.
"""

from __future__ import annotations

TABLE_RESOURCES = "user_tradecraft_resources"
TABLE_JOBS = "tradecraft_ingestion_jobs"
TABLE_PAGE_IDS = "tradecraft_page_ids"
TABLE_ENTRIES = "tradecraft_entries"
TABLE_SECTIONS = "tradecraft_sections"
TABLE_TREE = "tradecraft_tree_nodes"
TABLE_CURATIONS = "tradecraft_curations"
TABLE_PROJECT_CHOICES = "tradecraft_project_choices"
TABLE_USER_SETTINGS = "tradecraft_user_settings"

RESOURCES = (
    "id", "user_id", "name", "slug", "url", "enabled", "resource_type", "summary", "sitemap",
    "crawl_stopped_because", "crawl_stats", "llm_model",
    "last_verified_at", "last_refreshed_at", "last_error", "updated_at",
    "storage_mode", "forced_type", "type_options", "focus", "has_login",
    "summary_source", "summary_locked", "settings_snapshot", "settings_hash", "ingestion_report",
    "map_version", "legacy_map_hash", "generation", "active_job_id", "priority", "preset_key",
)

# Never selected by the agent. A resource's GitHub token and login reach it only inside what
# the webapp sends (the run catalog, a job or Check URL request), which applies the rules on
# who may use them (TD-9, §6.6); a query that read them here would hand the owner's logins to
# a collaborator's run. Listed only so the schema test sees a rename.
RESOURCE_SECRET_COLUMNS = ("github_token_override", "credentials")

JOBS = (
    "id", "user_id", "resource_id", "kind", "status", "stage", "progress", "error_code",
    "cancel_requested", "lease_until", "owner_instance", "bulk_id", "target_generation",
    "actor_user_id", "real_actor_user_id", "started_at", "finished_at", "created_at", "updated_at",
)

PAGE_IDS = ("id", "resource_id", "url", "created_at")

ENTRIES = (
    "id", "user_id", "resource_id", "generation", "page_id", "url", "title", "title_source",
    "breadcrumb", "headings", "description", "description_source", "source", "status",
    "drop_reason", "topics", "kinds", "technologies", "entities", "size_chars", "stored_text",
    "stored_bytes", "text_hash", "etag", "last_modified", "fetched_at", "search_vector",
    "created_at", "updated_at",
)

SECTIONS = (
    "id", "entry_id", "resource_id", "user_id", "generation", "ord", "heading", "level", "anchor",
    "text", "chars", "search_vector",
)

TREE = (
    "id", "resource_id", "user_id", "generation", "path", "parent_path", "label", "page_count",
    "description", "kind",
)

CURATIONS = (
    "id", "resource_id", "url", "pinned", "blocked", "renamed_title", "restored_from_drop",
    "created_by_id", "created_at", "updated_at",
)

PROJECT_CHOICES = ("project_id", "resource_id", "created_by_id", "created_at")

USER_SETTINGS = ("user_id", "v2_enabled", "ingestion", "search", "recipes", "synonyms")

COLUMNS = {
    TABLE_RESOURCES: RESOURCES + RESOURCE_SECRET_COLUMNS,
    TABLE_JOBS: JOBS,
    TABLE_PAGE_IDS: PAGE_IDS,
    TABLE_ENTRIES: ENTRIES,
    TABLE_SECTIONS: SECTIONS,
    TABLE_TREE: TREE,
    TABLE_CURATIONS: CURATIONS,
    TABLE_PROJECT_CHOICES: PROJECT_CHOICES,
    TABLE_USER_SETTINGS: USER_SETTINGS,
}

# The tables the agent INSERTs into: the schema test checks that every column with no
# database default (but the autoincrement id) is in the tuple above.
AGENT_INSERTS = (TABLE_PAGE_IDS, TABLE_ENTRIES, TABLE_SECTIONS, TABLE_TREE)

# How search_vector is filled, and the configuration queries must use (to_tsquery etc.).
SEARCH_VECTOR_FILLED_BY = "trigger"
SEARCH_VECTOR_FUNCTIONS = {
    TABLE_ENTRIES: "tradecraft_entry_search_vector",
    TABLE_SECTIONS: "tradecraft_section_search_vector",
}
TEXT_SEARCH_CONFIG = "english"
# Characters of one field that reach to_tsvector in the trigger: a longer stored text is
# still stored whole but only its start is searchable.
SEARCH_VECTOR_INPUT_MAX_CHARS = 250_000

# Closed value sets of the page-store columns (phase 1 "Data model"). Job kinds, statuses,
# stages, error codes and storage modes are the contract's (contract.py, enums.json).
TITLE_SOURCES = ("real", "guessed", "renamed")
ENTRY_SOURCES = ("sitemap", "tree", "crawl", "nav", "searchindex", "pdf", "pin", "legacy")
ENTRY_STATUSES = ("kept", "dropped")
TREE_KINDS = ("folder", "topic")
MAP_VERSION_LEGACY = 1
MAP_VERSION_CONVERTED = 2
MAP_VERSION_V2 = 3
