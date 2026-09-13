"""
RedAmon Agent Logging Configuration

Configures logging with file rotation, console output, and proper formatting.
"""
import logging
import re
import threading
from collections import OrderedDict
from logging.handlers import RotatingFileHandler
from pathlib import Path

from project_settings import get_setting

# =============================================================================
# I5 — secret redaction filter
# =============================================================================
# Scrub known token shapes from EVERY log record before any handler writes, so a
# future exception (SDK error, clone URL, header dump) carrying a secret cannot
# land in agent.log / codefix.log / triage.log in cleartext.
_REDACT_PATTERNS = [
    re.compile(r"gh[posru]_[A-Za-z0-9]{20,}"),                    # GitHub PAT / OAuth
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),                  # fine-grained PAT
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),                        # OpenAI-style keys
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),                 # Slack tokens
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),             # Bearer <token>
    re.compile(r"(?i)(authorization|api[-_]?key|x-api-key|token)\s*[:=]\s*[^\s,;]{6,}"),  # header/kv value
    re.compile(r"https?://[^/\s:@]+:[^/\s@]+@"),                  # user:pass@ in URLs (x-access-token:...@)
    re.compile(r"AKIA[0-9A-Z]{16}"),                             # AWS access key id
    re.compile(r"tvly-[A-Za-z0-9_\-]{16,}"),                     # Tavily search key
    re.compile(r"AIza[A-Za-z0-9_\-]{30,}"),                      # Google / Gemini key
    re.compile(r"xai-[A-Za-z0-9]{20,}"),                         # xAI (Grok) key
    # ProjectDiscovery Cloud key: what vulnx sends upstream, opaque and long.
    re.compile(r"(?i)\bpdcp[-_]?(?:api[-_]?)?key\s*[:=]\s*[^\s,;\"']{8,}"),
]
_REDACTED = "[REDACTED]"


def _redact_text(text: str) -> str:
    for pat in _REDACT_PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


def redact_text(text: str) -> str:
    """Public secret-scrubber. Used by session_log to redact event field values
    BEFORE json.dumps, so the JSONL stream stays valid JSON (the line-level
    RedactingFilter can eat a trailing quote/brace when a token shape abuts it)."""
    return _redact_text(text)


def _format_exc_info(exc_info) -> str:
    import traceback
    return "".join(traceback.format_exception(*exc_info)).rstrip("\n")


class RedactingFilter(logging.Filter):
    """Rewrite token-shaped substrings in the formatted message + args to
    ``[REDACTED]``. Attached to every handler this module creates."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: _redact_text(v) if isinstance(v, str) else v
                                   for k, v in record.args.items()}
                else:
                    record.args = tuple(_redact_text(a) if isinstance(a, str) else a
                                        for a in record.args)
            # `logger.exception(...)` puts the provider's own message and the
            # frames in exc_info, which the formatter appends AFTER msg/args.
            # Redacting only the message left the traceback in cleartext, which
            # is exactly where an SDK puts the key it was called with.
            if record.exc_info:
                record.exc_text = _redact_text(
                    record.exc_text or _format_exc_info(record.exc_info)
                )
                record.exc_info = None
            if getattr(record, "stack_info", None):
                record.stack_info = _redact_text(record.stack_info)
        except Exception:
            # Redaction must never break logging.
            pass
        return True


_REDACTING_FILTER = RedactingFilter()


# =============================================================================
# Per-session file routing
# =============================================================================
# Routes each record to logs/agent.<session_id>.log based on the
# current_log_session_id ContextVar (set per turn at the graph entrypoint).
# Records with no bound session (startup, websocket housekeeping, background
# threads that didn't inherit the context) fall back to the shared agent.log.
class PerSessionRoutingHandler(logging.Handler):
    """A handler that fans records out to one RotatingFileHandler per session id.

    Per-session handlers are created lazily and cached with LRU eviction so the
    number of open file descriptors stays bounded on a long-lived server that
    has served many sessions.
    """

    # Drop "." too: the only dots in the filename are the ones we add around the
    # session id (agent.<id>.log), so a ".." in a session id can never survive.
    _SAFE = re.compile(r"[^A-Za-z0-9_-]")

    def __init__(self, log_dir: Path, fallback_name: str, formatter,
                 max_bytes: int, backup_count: int, max_open: int = 64,
                 name_template: str = "agent.{session}.log"):
        super().__init__(level=FILE_LOG_LEVEL)
        self._log_dir = log_dir
        self._fallback_name = fallback_name
        self._formatter = formatter
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._max_open = max(2, max_open)
        self._name_template = name_template
        self._handlers: "OrderedDict[str, RotatingFileHandler]" = OrderedDict()
        self._lock = threading.Lock()

    def _target_name(self, session_id: str) -> str:
        if not session_id:
            return self._fallback_name
        safe = self._SAFE.sub("_", session_id)[:120]
        return self._name_template.format(session=safe)

    def _get_handler(self, name: str) -> RotatingFileHandler:
        with self._lock:
            handler = self._handlers.get(name)
            if handler is not None:
                self._handlers.move_to_end(name)
                return handler
            handler = RotatingFileHandler(
                filename=str(self._log_dir / name),
                maxBytes=self._max_bytes,
                backupCount=self._backup_count,
                encoding="utf-8",
                delay=True,  # don't open the file until something is written
            )
            handler.setLevel(FILE_LOG_LEVEL)
            handler.setFormatter(self._formatter)
            handler.addFilter(_REDACTING_FILTER)  # I5 — redact per-session files too
            self._handlers[name] = handler
            self._handlers.move_to_end(name)
            # Evict least-recently-used handlers beyond the cap; never the fallback.
            while len(self._handlers) > self._max_open:
                old_name = next(iter(self._handlers))
                if old_name == self._fallback_name:
                    self._handlers.move_to_end(old_name)
                    continue
                old_handler = self._handlers.pop(old_name)
                try:
                    old_handler.close()
                except Exception:
                    pass
            return handler

    def emit(self, record: logging.LogRecord) -> None:
        try:
            from agent_context import current_log_session_id
            session_id = current_log_session_id.get()
        except Exception:
            session_id = ""
        try:
            self._get_handler(self._target_name(session_id)).handle(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        with self._lock:
            for handler in self._handlers.values():
                try:
                    handler.close()
                except Exception:
                    pass
            self._handlers.clear()
        super().close()


# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log directory (relative to this file)
LOG_DIR = Path(__file__).parent / "logs"

# Module-specific log directories
CODEFIX_LOG_DIR = Path(__file__).parent / "cypherfix_codefix" / "logs"
TRIAGE_LOG_DIR = Path(__file__).parent / "cypherfix_triage" / "logs"

# Module log config: (logger_name, log_dir, log_file_name)
MODULE_LOGS = [
    ("cypherfix_codefix", CODEFIX_LOG_DIR, "codefix.log"),
    ("cypherfix_triage", TRIAGE_LOG_DIR, "triage.log"),
]

# Log file settings
LOG_FILE_NAME = "agent.log"
LOG_MAX_BYTES = get_setting('LOG_MAX_MB', 10) * 1024 * 1024  # Convert MB to bytes

# Log levels
FILE_LOG_LEVEL = logging.DEBUG
CONSOLE_LOG_LEVEL = logging.INFO

# Log format
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Detailed format for file (includes more context)
FILE_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(funcName)-20s | %(message)s"


def setup_logging(
    log_level: int = logging.INFO,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> None:
    """
    Configure logging for the RedAmon agent.

    Args:
        log_level: Minimum log level for console output
        log_to_console: Whether to output logs to console
        log_to_file: Whether to output logs to file with rotation
    """
    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Get root logger for agentic module
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture all levels, handlers will filter

    # Clear existing handlers to avoid duplicates. Close first so a re-init does
    # not leak the per-session routing handler's cached file descriptors.
    for _old in list(root_logger.handlers):
        try:
            _old.close()
        except Exception:
            pass
    root_logger.handlers.clear()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(_REDACTING_FILTER)  # I5
        root_logger.addHandler(console_handler)

    # File handler with rotation. When per-session routing is on, each turn's
    # records go to agent.<session_id>.log and anything with no bound session
    # falls back to agent.log; when off, everything shares a single agent.log.
    if log_to_file:
        file_formatter = logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        backup_count = get_setting('LOG_BACKUP_COUNT', 5)
        if get_setting('LOG_PER_SESSION', True):
            file_handler = PerSessionRoutingHandler(
                log_dir=LOG_DIR,
                fallback_name=LOG_FILE_NAME,
                formatter=file_formatter,
                max_bytes=LOG_MAX_BYTES,
                backup_count=backup_count,
            )
            # The routed inner handlers each redact; the router itself just fans out.
            root_logger.addHandler(file_handler)
        else:
            file_handler = RotatingFileHandler(
                filename=str(LOG_DIR / LOG_FILE_NAME),
                maxBytes=LOG_MAX_BYTES,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(FILE_LOG_LEVEL)
            file_handler.setFormatter(file_formatter)
            file_handler.addFilter(_REDACTING_FILTER)  # I5
            root_logger.addHandler(file_handler)

    # Module-specific file handlers (separate log files for CypherFix agents)
    if log_to_file:
        for module_name, log_dir, log_file in MODULE_LOGS:
            log_dir.mkdir(parents=True, exist_ok=True)
            module_handler = RotatingFileHandler(
                filename=str(log_dir / log_file),
                maxBytes=LOG_MAX_BYTES,
                backupCount=get_setting('LOG_BACKUP_COUNT', 5),
                encoding="utf-8",
            )
            module_handler.setLevel(FILE_LOG_LEVEL)
            module_handler.setFormatter(
                logging.Formatter(FILE_LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
            )
            module_handler.addFilter(_REDACTING_FILTER)  # I5
            module_logger = logging.getLogger(module_name)
            module_logger.handlers.clear()  # Prevent duplicates on re-init
            module_logger.addHandler(module_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.INFO)
    logging.getLogger("langgraph").setLevel(logging.INFO)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    # MCP client logs are very verbose - suppress them
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("mcp.client").setLevel(logging.WARNING)
    logging.getLogger("mcp.client.sse").setLevel(logging.WARNING)
    # websocket_api emits one DEBUG line per message sent + per ping/pong; at
    # DEBUG that floods the per-session file with thousands of housekeeping lines.
    logging.getLogger("websocket_api").setLevel(logging.INFO)

    # Structured per-session event stream (agent.<session_id>.events.jsonl). The
    # 'session_events' logger is ALWAYS isolated from root (propagate=False) so
    # that log_event() — which callers invoke unconditionally — can never leak
    # JSON into the prose log or console, even when the stream is disabled. When
    # enabled it routes to per-session .jsonl files; when disabled it gets a
    # NullHandler so records are silently dropped (no lastResort to stderr).
    events_logger = logging.getLogger("session_events")
    events_logger.setLevel(logging.INFO)
    events_logger.propagate = False
    for _old in list(events_logger.handlers):  # close before clear: no FD leak on re-init
        try:
            _old.close()
        except Exception:
            pass
    events_logger.handlers.clear()
    if log_to_file and get_setting('LOG_EVENT_STREAM', True):
        events_logger.addHandler(PerSessionRoutingHandler(
            log_dir=LOG_DIR,
            fallback_name="agent.events.jsonl",
            formatter=logging.Formatter("%(message)s"),  # message is already JSON
            max_bytes=LOG_MAX_BYTES,
            backup_count=get_setting('LOG_BACKUP_COUNT', 5),
            name_template="agent.{session}.events.jsonl",
        ))
    else:
        events_logger.addHandler(logging.NullHandler())

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured - File: {LOG_DIR / LOG_FILE_NAME}")
    for module_name, log_dir, log_file in MODULE_LOGS:
        logger.info(f"  Module log: {module_name} -> {log_dir / log_file}")
    logger.info(f"Max file size: {LOG_MAX_BYTES / 1024 / 1024:.1f} MB, Backup count: {get_setting('LOG_BACKUP_COUNT', 5)}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
