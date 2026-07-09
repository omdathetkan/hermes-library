"""
Bibliotheek WISE Hermes plugin.

Registers five tools:
  library_search        — search the catalog
  library_availability  — check availability of a specific title
  library_list_loans    — list loans across all linked accounts
  library_list_holds    — list holds across all linked accounts
  library_place_hold    — place a reservation

Install to ~/.hermes/plugins/bibliotheek/ and set env vars (see .env.example).
Enable with: hermes plugins enable bibliotheek
"""

import json
import os

try:
    from .api import LibraryClient          # loaded as a Hermes plugin package
except ImportError:
    from api import LibraryClient           # direct execution / test_local.py


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _get_client() -> LibraryClient:
    return LibraryClient(
        username=os.environ["LIBRARY_USERNAME"],
        password=os.environ["LIBRARY_PASSWORD"],
        branch_id=os.environ.get("LIBRARY_BRANCH_ID", "2850"),
        library_id=os.environ.get("LIBRARY_ID", "I285"),
    )


def _check_env() -> bool:
    return bool(os.getenv("LIBRARY_USERNAME") and os.getenv("LIBRARY_PASSWORD"))


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(ctx):

    # ── library_search ───────────────────────────────────────────────────────

    ctx.register_tool(
        name="library_search",
        toolset="bibliotheek",
        description="Search the local library catalog for books and other media.",
        schema={
            "name": "library_search",
            "description": (
                "Search the local library catalog. Returns a list of titles with "
                "their title_id, author, publication year, media type, and ISBN. "
                "Use the returned title_id with library_availability or library_place_hold."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search terms — title, author name, keyword, or ISBN.",
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["title", "author", "isbn"],
                        "description": "Which field to search. Default: 'title'.",
                        "default": "title",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10, max 25).",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        },
        handler=lambda params, **kw: _handle_search(params),
        check_fn=_check_env,
    )

    # ── library_availability ─────────────────────────────────────────────────

    ctx.register_tool(
        name="library_availability",
        toolset="bibliotheek",
        description="Check availability of a specific library title by its ID.",
        schema={
            "name": "library_availability",
            "description": (
                "Check whether a specific library title is available for borrowing "
                "or can be reserved. Requires the title_id from library_search."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title_id": {
                        "type": "string",
                        "description": (
                            "The WISE bibliographic record ID (numeric string). "
                            "Obtained from the title_id field in library_search results."
                        ),
                    },
                },
                "required": ["title_id"],
            },
        },
        handler=lambda params, **kw: _handle_availability(params),
        check_fn=_check_env,
    )

    # ── library_list_loans ───────────────────────────────────────────────────

    ctx.register_tool(
        name="library_list_loans",
        toolset="bibliotheek",
        description="List all items on loan across the logged-in member and linked accounts.",
        schema={
            "name": "library_list_loans",
            "description": (
                "List all library items currently on loan, grouped by account name. "
                "Always includes the logged-in member and any linked accounts (e.g. children). "
                "Each account has patron_id and a loans list with title, author, loan date, "
                "due date, renewal status, and fines."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        handler=lambda params, **kw: _handle_list_loans(params),
        check_fn=_check_env,
    )

    # ── library_list_holds ───────────────────────────────────────────────────

    ctx.register_tool(
        name="library_list_holds",
        toolset="bibliotheek",
        description="List all active holds across the logged-in member and linked accounts.",
        schema={
            "name": "library_list_holds",
            "description": (
                "List all active holds and reservations, grouped by account name. "
                "Always includes the logged-in member and any linked accounts (e.g. children). "
                "Each account has patron_id and a holds list with title, status, queue "
                "position, and pickup location."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        handler=lambda params, **kw: _handle_list_holds(params),
        check_fn=_check_env,
    )

    # ── library_place_hold ───────────────────────────────────────────────────

    ctx.register_tool(
        name="library_place_hold",
        toolset="bibliotheek",
        description="Place a hold (reservation) for a library title.",
        schema={
            "name": "library_place_hold",
            "description": (
                "Place a hold (reservation) for a library book or other media item. "
                "First use library_search to find the title_id, optionally verify "
                "availability with library_availability, then call this tool."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title_id": {
                        "type": "string",
                        "description": (
                            "The WISE bibliographic record ID (from library_search "
                            "or library_availability results)."
                        ),
                    },
                    "pickup_branch_id": {
                        "type": "string",
                        "description": (
                            "Branch ID for pickup. Defaults to your home branch "
                            f"(configured as LIBRARY_BRANCH_ID, e.g. '2850')."
                        ),
                    },
                },
                "required": ["title_id"],
            },
        },
        handler=lambda params, **kw: _handle_place_hold(params),
        check_fn=_check_env,
    )


# ---------------------------------------------------------------------------
# Handlers (separated so tracebacks are readable)
# ---------------------------------------------------------------------------

def _handle_search(params: dict) -> str:
    try:
        client = _get_client()
        result = client.search(
            query=params["query"],
            scope=params.get("scope", "title"),
            limit=min(int(params.get("limit", 10)), 25),
        )
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _handle_availability(params: dict) -> str:
    try:
        client = _get_client()
        result = client.check_availability(params["title_id"])
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _handle_list_loans(params: dict) -> str:
    try:
        client = _get_client()
        result = client.list_loans()
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _handle_list_holds(params: dict) -> str:
    try:
        client = _get_client()
        result = client.list_holds()
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _handle_place_hold(params: dict) -> str:
    try:
        client = _get_client()
        result = client.place_hold(
            title_id=params["title_id"],
            pickup_branch_id=params.get("pickup_branch_id"),
        )
        return json.dumps(result, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
