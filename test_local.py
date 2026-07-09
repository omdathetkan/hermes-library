"""
Local test script — exercises the library API client without Hermes.

Usage:
    python test_local.py           # run all tests
    python test_local.py search    # only search
    python test_local.py loans     # only list loans
    python test_local.py holds     # only list holds

Reads credentials from .env in the same directory.
"""

import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Load .env
# ---------------------------------------------------------------------------

def _load_dotenv():
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        print(f"[warn] no .env found at {env_file} — relying on shell environment")
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

# Import AFTER env is loaded so LibraryClient picks up env vars cleanly.
from api import LibraryClient  # noqa: E402 (intentional late import)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client() -> LibraryClient:
    username = os.environ.get("LIBRARY_USERNAME", "")
    password = os.environ.get("LIBRARY_PASSWORD", "")
    if not username or not password:
        sys.exit("[error] LIBRARY_USERNAME and LIBRARY_PASSWORD must be set in .env")
    return LibraryClient(
        username=username,
        password=password,
        branch_id=os.environ.get("LIBRARY_BRANCH_ID", "2850"),
        library_id=os.environ.get("LIBRARY_ID", "I285"),
    )


def section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_search(client: LibraryClient):
    section("Search by title: 'Harry Potter'")
    results = client.search("Harry Potter", scope="title", limit=5)
    print(f"  Total matches: {results['total']}")
    for r in results["results"]:
        tid = r["title_id"] or "?"
        print(f"  [{tid:>8}] {r['title']} ({r['year']}) — {r['author']}")

    if results["results"]:
        tid = next((r["title_id"] for r in results["results"] if r["title_id"]), None)
        if tid:
            section(f"Availability for title_id={tid}")
            avail = client.check_availability(tid)
            print(f"  available    : {avail['available']}")
            print(f"  hold_allowed : {avail['hold_allowed']}")
            for a in avail.get("availability", []):
                print(f"  status       : {a.get('status')} ({a.get('statusCode')})")


def test_loans(client: LibraryClient):
    section("Current loans (items you have borrowed)")
    loans = client.list_loans()
    if not loans:
        print("  (no active loans)")
    for loan in loans:
        due = loan["due_date"] or loan["renewed_due_date"] or "?"
        fine = f"  ⚠ fine: €{loan['fine']:.2f}" if loan["fine"] else ""
        renew = "✓ renewable" if loan["can_be_renewed"] else "✗ not renewable"
        print(f"  [{loan['loan_id']}] {loan['title']}")
        print(f"         author: {loan['author']}")
        print(f"         lent:   {loan['loan_date']}  due: {due}  {renew}{fine}")


def test_holds(client: LibraryClient):
    section("Active holds (reservations)")
    holds = client.list_holds()
    if not holds:
        print("  (no active holds)")
    for hold in holds:
        pickup = f"pickup: {hold['pickup_location']}" if hold["pickup_location"] else ""
        print(f"  [{hold['hold_id']}] {hold['title']}")
        print(f"         author: {hold['author']}")
        print(f"         status: {hold['status']}  queue: #{hold['queue_position']}  {pickup}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = set(sys.argv[1:]) or {"search", "loans", "holds"}

    print(f"[+] Using branch={os.environ.get('LIBRARY_BRANCH_ID', '2850')}, "
          f"library={os.environ.get('LIBRARY_ID', 'I285')}")

    client = _client()

    print("[+] Logging in …")
    client.ensure_logged_in()
    print(f"[+] Logged in — patron id: {client._patron_id}")

    if "search" in args:
        test_search(client)

    if "loans" in args:
        test_loans(client)

    if "holds" in args:
        test_holds(client)

    print("\n[+] Done.")


if __name__ == "__main__":
    main()
