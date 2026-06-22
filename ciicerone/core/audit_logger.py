"""Audit logging framework for Ciicerone.

Provides structured audit event logging with configurable sinks
(memory, file) and compliance-ready event categorisation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AuditCategory(str, Enum):
    """High-level audit event categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA = "data"
    CONFIG = "config"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    ADMIN = "admin"
    API = "api"
    SYSTEM = "system"


class AuditSeverity(str, Enum):
    """Severity levels aligned with syslog / audit-events-catalog."""

    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFO = "INFO"
    DEBUG = "DEBUG"


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
    "refresh_token",
    "authorization",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
}


def sanitize_for_log(data: Any) -> Any:
    """Recursively redact sensitive fields from *data* before logging.

    Returns a deep-copy with sensitive values replaced by ``"[REDACTED]"``.
    """
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else sanitize_for_log(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [sanitize_for_log(item) for item in data]
    if isinstance(data, str):
        # Redact common token patterns
        redacted = re.sub(
            r"(sk-[a-zA-Z0-9]{20,})", "[REDACTED]", data
        )
        return redacted
    return data


class AuditEvent(BaseModel):
    """A single audit event record."""

    event_type: str = Field(..., description="Hierarchical event identifier, e.g. 'authentication.login.success'")
    category: AuditCategory = Field(..., description="High-level category")
    severity: AuditSeverity = Field(default=AuditSeverity.INFO)
    actor: Dict[str, Any] = Field(default_factory=dict, description="Who performed the action")
    target: Dict[str, Any] = Field(default_factory=dict, description="Resource acted upon")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = Field(default=None, description="Trace / correlation ID")
    description: Optional[str] = Field(default=None)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict with sanitised sensitive fields."""
        raw = self.model_dump(mode="json")
        return sanitize_for_log(raw)

    def to_json(self) -> str:
        """Return a JSON string representation."""
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class AuditSink:
    """Abstract base for audit event sinks."""

    def write(self, event: AuditEvent) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class MemoryAuditSink(AuditSink):
    """Stores audit events in memory — useful for testing."""

    def __init__(self, max_size: int = 10_000) -> None:
        self._events: List[AuditEvent] = []
        self._max_size = max_size
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        with self._lock:
            if len(self._events) >= self._max_size:
                self._events.pop(0)
            self._events.append(event)

    @property
    def events(self) -> List[AuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def filter(
        self,
        *,
        category: Optional[AuditCategory] = None,
        severity: Optional[AuditSeverity] = None,
        event_type: Optional[str] = None,
    ) -> List[AuditEvent]:
        result = self.events
        if category is not None:
            result = [e for e in result if e.category == category]
        if severity is not None:
            result = [e for e in result if e.severity == severity]
        if event_type is not None:
            result = [e for e in result if e.event_type == event_type]
        return result


class FileAuditSink(AuditSink):
    """Appends audit events to a file as JSON lines."""

    def __init__(self, file_path: Union[str, Path]) -> None:
        self._path = Path(file_path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: AuditEvent) -> None:
        line = event.to_json() + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)

    def flush(self) -> None:
        # File writes are already flushed on each write.
        pass


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Main audit logger that fans out events to registered sinks."""

    def __init__(
        self,
        *,
        sinks: Optional[List[AuditSink]] = None,
        min_severity: AuditSeverity = AuditSeverity.INFO,
    ) -> None:
        self._sinks: List[AuditSink] = list(sinks) if sinks else []
        self._min_severity = min_severity
        self._lock = threading.Lock()

    # -- sink management ---------------------------------------------------

    def add_sink(self, sink: AuditSink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def remove_sink(self, sink: AuditSink) -> None:
        with self._lock:
            self._sinks.remove(sink)

    @property
    def sinks(self) -> List[AuditSink]:
        with self._lock:
            return list(self._sinks)

    # -- configuration -----------------------------------------------------

    @property
    def min_severity(self) -> AuditSeverity:
        return self._min_severity

    @min_severity.setter
    def min_severity(self, value: AuditSeverity) -> None:
        self._min_severity = value

    # -- severity ordering -------------------------------------------------

    _SEVERITY_ORDER = {
        AuditSeverity.EMERGENCY: 0,
        AuditSeverity.ALERT: 1,
        AuditSeverity.CRITICAL: 2,
        AuditSeverity.ERROR: 3,
        AuditSeverity.WARNING: 4,
        AuditSeverity.NOTICE: 5,
        AuditSeverity.INFO: 6,
        AuditSeverity.DEBUG: 7,
    }

    def _should_log(self, severity: AuditSeverity) -> bool:
        return self._SEVERITY_ORDER[severity] <= self._SEVERITY_ORDER[self._min_severity]

    # -- core logging ------------------------------------------------------

    def log(
        self,
        event_type: str,
        *,
        category: AuditCategory,
        severity: AuditSeverity = AuditSeverity.INFO,
        actor: Optional[Dict[str, Any]] = None,
        target: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> AuditEvent:
        """Create and dispatch an audit event."""
        event = AuditEvent(
            event_type=event_type,
            category=category,
            severity=severity,
            actor=actor or {},
            target=target or {},
            context=context or {},
            correlation_id=correlation_id,
            description=description,
        )
        self.log_event(event)
        return event

    def log_event(self, event: AuditEvent) -> None:
        """Dispatch an already-constructed :class:`AuditEvent`."""
        if not self._should_log(event.severity):
            return
        for sink in self.sinks:
            try:
                sink.write(event)
            except Exception:
                logger.exception("Audit sink %s failed to write event", type(sink).__name__)

    # -- convenience helpers ----------------------------------------------

    def info(self, event_type: str, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("severity", AuditSeverity.INFO)
        return self.log(event_type, **kwargs)

    def warning(self, event_type: str, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("severity", AuditSeverity.WARNING)
        return self.log(event_type, **kwargs)

    def error(self, event_type: str, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("severity", AuditSeverity.ERROR)
        return self.log(event_type, **kwargs)

    def critical(self, event_type: str, **kwargs: Any) -> AuditEvent:
        kwargs.setdefault("severity", AuditSeverity.CRITICAL)
        return self.log(event_type, **kwargs)

    # -- lifecycle ---------------------------------------------------------

    def flush(self) -> None:
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception:
                logger.exception("Audit sink %s flush failed", type(sink).__name__)

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:
                logger.exception("Audit sink %s close failed", type(sink).__name__)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_global_logger: Optional[AuditLogger] = None
_global_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Return the process-wide :class:`AuditLogger` singleton.

    On first call a default logger is created with a :class:`MemoryAuditSink`.
    A :class:`FileAuditSink` is added if ``CIICERONE_AUDIT_LOG_PATH`` is set
    in the environment.
    """
    global _global_logger
    if _global_logger is not None:
        return _global_logger

    with _global_lock:
        if _global_logger is not None:
            return _global_logger

        sinks: List[AuditSink] = [MemoryAuditSink()]

        env_path = os.environ.get("CIICERONE_AUDIT_LOG_PATH")
        if env_path:
            sinks.append(FileAuditSink(env_path))

        _global_logger = AuditLogger(sinks=sinks)
        return _global_logger


def reset_audit_logger() -> None:
    """Reset the global audit logger (primarily for testing)."""
    global _global_logger
    with _global_lock:
        if _global_logger is not None:
            _global_logger.close()
        _global_logger = None
