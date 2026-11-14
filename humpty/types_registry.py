"""humpty.types_registry — FR-12, type registry v0.

Centralized, versioned reconstruction of struct/class layouts with a single
owner per type. Two divergent reconstructions of one type must be surfaced as
an error by the caller (the ROADMAP's consistency rule); this module exposes
the write path (``register_type``), the read path (``get_layout``), and the
check (``check_consistency``) that a worker runs before writing.

Storage rides on the ``types`` table (``TypeRow``) as it stands (WHITEPAPERS
§6): the table is keyed by ``name`` + ``version`` and has no binary column, so
``binary_sha256`` is stored in a reserved ``layout_json`` key (``"_binary"``)
and every lookup is scoped by it. Rows are never updated — a new layout
version appends a row, so the full history is preserved and the newest row
(version = max for that binary + name) is authoritative. Ownership uses the
existing ``owner_worker`` column.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from humpty.db.models import TypeRow

__all__ = ["register_type", "check_consistency", "get_layout", "newest_layout_row"]

# Reserved layout_json keys. ``_binary`` records the binary the layout was
# reconstructed from (the ``types`` table has no binary column); ``_owner``
# mirrors ``owner_worker`` for layouts registered before ownership existed.
_RESERVED_KEYS = ("_binary", "_owner")

# Structural comparison excludes reserved bookkeeping keys and sorts keys, so
# dict insertion order never fabricates a difference.


def _normalize(layout: dict[str, Any]) -> str:
    """Canonical JSON for layout equality, minus reserved keys."""
    payload = {k: v for k, v in layout.items() if k not in _RESERVED_KEYS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _newest_row(session: Session, *, binary_sha256: str, name: str) -> TypeRow | None:
    """Newest authoritative row for (binary, name), or None."""
    stmt = (
        select(TypeRow)
        .where(TypeRow.name == name)
        .where(TypeRow.layout_json["_binary"].as_string() == binary_sha256)
        .order_by(TypeRow.version.desc())
        .limit(1)
    )
    return session.scalars(stmt).first()


def _next_version(session: Session, *, name: str) -> int:
    # ``uq_types_name_version`` scopes uniqueness to (name, version) — the
    # table has no binary column — so versions are allocated per name across
    # binaries. Allocation is monotone, so the newest row per (binary, name)
    # is still its max-version row.
    return int(
        session.scalar(
            select(func.coalesce(func.max(TypeRow.version), 0)).where(TypeRow.name == name)
        )
    ) + 1


def _validate(layout_json: dict[str, Any]) -> None:
    """v0 shape check: at least ``size`` and ``fields`` with name/offset/type."""
    if "size" not in layout_json:
        raise ValueError("layout_json must contain 'size'")
    fields = layout_json.get("fields")
    if not isinstance(fields, list):
        raise ValueError("layout_json must contain 'fields' as a list")
    for i, f in enumerate(fields):
        if not isinstance(f, dict) or not {"name", "offset", "type"} <= set(f):
            raise ValueError(f"fields[{i}] must contain 'name', 'offset', 'type'")


def register_type(
    session: Session,
    *,
    binary_sha256: str,
    name: str,
    layout_json: dict[str, Any],
    owner: str,
) -> TypeRow:
    """Insert or version a type layout; returns the authoritative row.

    - No layout for this (binary, name) yet: inserts version 1.
    - Identical layout (same normalized JSON) already newest: returns that
      existing row unchanged — re-registration is idempotent.
    - Different layout: appends a new row with version bumped (history is
      preserved; the newest row is authoritative). Ownership moves with the
      write: the new row is owned by ``owner``.

    Single-owner rule: a type already owned by another worker raises
    ``TypeError``; the same worker may keep evolving its own type.

    Commits nothing: participates in the caller's transaction, like
    ``record_event`` (the unit of work stays with ``session_scope``).
    """
    _validate(layout_json)

    newest = _newest_row(session, binary_sha256=binary_sha256, name=name)
    if newest is not None:
        if newest.owner_worker is not None and newest.owner_worker != owner:
            raise TypeError(
                f"type {name!r} (binary {binary_sha256[:12]}) is owned by "
                f"worker {newest.owner_worker!r}; refusing write from {owner!r}"
            )
        if _normalize(newest.layout_json) == _normalize(layout_json):
            return newest

    version = _next_version(session, name=name)
    stored = {**layout_json, "_binary": binary_sha256, "_owner": owner}
    row = TypeRow(
        name=name,
        layout_json=stored,
        owner_worker=owner,
        version=version,
    )
    session.add(row)
    session.flush()  # assign row.id/version without committing
    return row


def check_consistency(
    session: Session,
    *,
    binary_sha256: str,
    name: str,
    layout_json: dict[str, Any],
) -> bool:
    """True iff no conflicting layout for this name at the newest version.

    A caller that gets False (or catches the single-owner ``TypeError`` from
    ``register_type``) owns surfacing it: two divergent reconstructions of one
    type invalidate everything that depends on it.
    """
    _validate(layout_json)
    newest = _newest_row(session, binary_sha256=binary_sha256, name=name)
    if newest is None:
        return True
    return _normalize(newest.layout_json) == _normalize(layout_json)


def get_layout(
    session: Session,
    *,
    binary_sha256: str,
    name: str,
) -> dict[str, Any] | None:
    """The newest authoritative layout for (binary, name), or None."""
    row = _newest_row(session, binary_sha256=binary_sha256, name=name)
    if row is None:
        return None
    layout = dict(row.layout_json)
    for key in _RESERVED_KEYS:
        layout.pop(key, None)
    return layout


def newest_layout_row(
    session: Session,
    *,
    binary_sha256: str,
    name: str,
) -> TypeRow | None:
    """The newest authoritative ``TypeRow`` (exposes version/owner/history)."""
    return _newest_row(session, binary_sha256=binary_sha256, name=name)
