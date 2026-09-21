"""Shared test isolation.

Any test that touches xrefs_to_rva (use_index defaults to True) performs a
rip_index lookup, and the lookup path creates ~/.fridapilot/rip_index.db as
a side effect - and would happily serve a stale index built for a
content-identical file (the synthetic fixture is deterministic). Redirect
the default index DB to a per-test temporary file so the suite never
touches the real user home and cannot be poisoned by it
(audit finding M-P1).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_rip_index_db(tmp_path, monkeypatch):
    from fridapilot.tools import rip_index

    monkeypatch.setattr(rip_index, "DEFAULT_DB_PATH", tmp_path / "rip_index.db")
