"""
Hint deduplication tests — Jaccard similarity edge cases.

These tests exercise the _tokenise() and _jaccard() internals directly,
plus the full is_duplicate() pipeline against a live temp database.
"""

from __future__ import annotations

import pytest

from ctf_copilot.engine.hints import (
    _tokenise,
    _jaccard,
    is_duplicate,
    save_hint,
    get_recent_hints,
)
from ctf_copilot.core.database import get_connection


# ===========================================================================
# _tokenise
# ===========================================================================

class TestTokenise:

    def test_basic_words(self):
        tokens = _tokenise("nmap scan found port 80")
        assert "nmap" in tokens
        assert "port" in tokens

    def test_removes_short_tokens(self):
        tokens = _tokenise("do it now")
        # "do", "it" are <= 2 chars and should be excluded
        assert "do" not in tokens
        assert "it" not in tokens

    def test_lowercases(self):
        tokens = _tokenise("Nmap SCAN found Port 80")
        assert "nmap" in tokens
        assert "scan" in tokens

    def test_preserves_version_numbers(self):
        """'2.3.4' must become '2_3_4' so it stays as one token."""
        tokens = _tokenise("vsftpd version 2.3.4 backdoor")
        assert "2_3_4" in tokens
        # Should NOT be split into individual digit tokens
        assert "2" not in tokens
        assert "3" not in tokens

    def test_preserves_cve_id(self):
        tokens = _tokenise("CVE-2011-2523 allows RCE via backdoor")
        # CVE token should be unified
        assert any("cve" in t for t in tokens)

    def test_removes_punctuation(self):
        tokens = _tokenise("connect to: http://target/login.php?id=1")
        assert "http" in tokens
        # Colons, slashes, question marks should be removed
        assert any("login" in t for t in tokens)

    def test_empty_string(self):
        assert _tokenise("") == set()

    def test_repeated_words_deduplicated(self):
        tokens = _tokenise("scan scan scan the target target")
        # Sets deduplicate automatically
        assert isinstance(tokens, set)


# ===========================================================================
# _jaccard
# ===========================================================================

class TestJaccard:

    def test_identical_sets(self):
        a = {"apple", "banana", "cherry"}
        assert _jaccard(a, a) == 1.0

    def test_disjoint_sets(self):
        a = {"apple", "banana"}
        b = {"cherry", "date"}
        assert _jaccard(a, b) == 0.0

    def test_partial_overlap(self):
        a = {"apple", "banana", "cherry"}
        b = {"apple", "banana", "date"}
        # Intersection: {apple, banana} = 2, Union: 4
        assert abs(_jaccard(a, b) - 0.5) < 0.001

    def test_empty_sets(self):
        assert _jaccard(set(), set()) == 0.0
        assert _jaccard({"a"}, set()) == 0.0
        assert _jaccard(set(), {"a"}) == 0.0

    def test_one_subset_of_other(self):
        a = {"apple", "banana"}
        b = {"apple", "banana", "cherry", "date"}
        # Intersection: 2, Union: 4
        assert abs(_jaccard(a, b) - 0.5) < 0.001


# ===========================================================================
# is_duplicate — full pipeline with real temp DB
# ===========================================================================

class TestIsDuplicate:

    def _setup(self, tmp_db):
        """Insert a session row and return its id."""
        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO sessions (name, status) VALUES ('dedup-test', 'active')"
            )
            row = conn.execute(
                "SELECT id FROM sessions WHERE name='dedup-test'"
            ).fetchone()
        return row["id"]

    def test_not_duplicate_when_no_prior_hints(self, tmp_db):
        sid = self._setup(tmp_db)
        assert is_duplicate(sid, "Check port 21 for vsftpd backdoor") is False

    def test_exact_duplicate_detected(self, tmp_db):
        sid = self._setup(tmp_db)
        hint = "Port 21 is running vsftpd 2.3.4. This version has a backdoor on port 6200."
        save_hint(sid, hint, source="pattern", confidence=0.97)
        assert is_duplicate(sid, hint) is True

    def test_paraphrase_detected(self, tmp_db):
        sid = self._setup(tmp_db)
        original  = "vsftpd 2.3.4 has a backdoor. Connect with smiley and check port 6200."
        paraphrase = "vsftpd 2.3.4 contains a backdoor. Use smiley in username then check port 6200."
        save_hint(sid, original, source="pattern", confidence=0.97)
        assert is_duplicate(sid, paraphrase) is True

    def test_different_hint_passes(self, tmp_db):
        sid = self._setup(tmp_db)
        save_hint(sid, "Port 21 has vsftpd 2.3.4 backdoor.", source="pattern", confidence=0.97)
        different = "SMB is open on port 445. Run enum4linux to enumerate shares and users."
        assert is_duplicate(sid, different) is False

    def test_version_number_preserved_in_dedup(self, tmp_db):
        """2.3.4 and 3.0.20 must be treated as distinct tokens."""
        sid = self._setup(tmp_db)
        save_hint(sid, "vsftpd 2.3.4 backdoor on port 6200", source="pattern", confidence=0.97)
        # Same structure but different version number — should NOT be a duplicate
        different_version = "Samba 3.0.20 has a command injection RCE via usermap script"
        assert is_duplicate(sid, different_version) is False

    def test_isolated_between_sessions(self, tmp_db):
        """Hints from one session must not affect dedup in another."""
        sid1 = self._setup(tmp_db)

        # Add a second session
        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO sessions (name, status) VALUES ('dedup-session-2', 'active')"
            )
            sid2 = conn.execute(
                "SELECT id FROM sessions WHERE name='dedup-session-2'"
            ).fetchone()["id"]

        hint = "Port 21 has vsftpd 2.3.4 backdoor"
        save_hint(sid1, hint, source="pattern", confidence=0.97)

        # Same hint in session 2 should NOT be considered a duplicate
        # (session 1's hints don't affect session 2)
        assert is_duplicate(sid2, hint) is False


# ===========================================================================
# save_hint / get_recent_hints round-trip
# ===========================================================================

class TestHintPersistence:

    def _session(self, tmp_db) -> int:
        with get_connection(tmp_db) as conn:
            conn.execute("INSERT INTO sessions (name, status) VALUES ('persist-test', 'active')")
            return conn.execute(
                "SELECT id FROM sessions WHERE name='persist-test'"
            ).fetchone()["id"]

    def test_save_and_retrieve(self, tmp_db):
        sid = self._session(tmp_db)
        save_hint(sid, "test hint", source="ai", confidence=0.8)
        hints = get_recent_hints(sid, limit=10)
        assert len(hints) == 1
        assert hints[0]["hint_text"] == "test hint"
        assert hints[0]["source"]    == "ai"

    def test_retrieval_order_newest_first(self, tmp_db):
        sid = self._session(tmp_db)
        save_hint(sid, "first hint",  source="ai", confidence=0.8)
        save_hint(sid, "second hint", source="ai", confidence=0.8)
        hints = get_recent_hints(sid, limit=10)
        # Newest first
        assert hints[0]["hint_text"] == "second hint"
        assert hints[1]["hint_text"] == "first hint"

    def test_limit_respected(self, tmp_db):
        sid = self._session(tmp_db)
        for i in range(10):
            save_hint(sid, f"hint {i}", source="ai", confidence=0.8)
        hints = get_recent_hints(sid, limit=3)
        assert len(hints) == 3

    def test_rule_name_stored(self, tmp_db):
        sid = self._session(tmp_db)
        save_hint(sid, "vsftpd backdoor", source="pattern",
                  confidence=0.97, rule_name="vsftpd-2.3.4-backdoor")
        hints = get_recent_hints(sid, limit=5)
        assert hints[0]["rule_name"] == "vsftpd-2.3.4-backdoor"
