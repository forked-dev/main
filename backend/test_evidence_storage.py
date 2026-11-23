"""Tests for evidence_storage.assert_safe_destination and storage.BlobStore.

All tests use temporary directories as the storage root so no real
application state is touched.  No production credentials or database
connections are required.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import evidence_storage
from metrics import collector as metrics_collector


class FakeRow(dict):
    """Row mapping returned by FakeCursor.fetchone()."""


class FakeCursor:
    """In-memory fake cursor capturing SQL statements, parameters, and state."""

    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.executed: list[tuple[str, tuple]] = []
        self._last_row: FakeRow | None = None
        self._results: list[FakeRow] = []
        self._idx: int = 0

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())

        if normalized.startswith("insert into blobs"):
            if len(params) == 5:
                content_hash, encrypted_dek, size_bytes, storage_path, envelope_version = params
            else:
                content_hash, encrypted_dek, size_bytes, storage_path = params
                envelope_version = None
            # ON CONFLICT (content_hash) DO NOTHING
            with self.connection.lock:
                if content_hash not in self.connection.blobs:
                    self.connection.blobs[content_hash] = {
                        "content_hash": content_hash,
                        "encrypted_dek": encrypted_dek,
                        "size_bytes": size_bytes,
                        "storage_path": storage_path,
                        "envelope_version": envelope_version,
                        "created_at": time.time(),
                    }
            self._last_row = None

        elif normalized.startswith("insert into tenant_blob_refs"):
            tenant_id, content_hash = params
            key = (tenant_id, content_hash)
            # ON CONFLICT (tenant_id, content_hash) DO UPDATE SET ref_count = ref_count + 1
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] += 1
                else:
                    self.connection.tenant_refs[key] = {
                        "tenant_id": tenant_id,
                        "content_hash": content_hash,
                        "ref_count": 1,
                    }
            self._last_row = None

        elif normalized.startswith("select encrypted_dek, storage_path, envelope_version from blobs"):
            (content_hash,) = params
            with self.connection.lock:
                blob = self.connection.blobs.get(content_hash)
                if blob is None:
                    self._last_row = None
                else:
                    self._last_row = FakeRow(
                        encrypted_dek=blob["encrypted_dek"],
                        storage_path=blob["storage_path"],
                        envelope_version=blob.get("envelope_version"),
                    )

        elif "select ref_count from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self._last_row = FakeRow(ref_count=self.connection.tenant_refs[key]["ref_count"])
                else:
                    self._last_row = None

        elif "update tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] -= 1

        elif "delete from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                self.connection.tenant_refs.pop(key, None)

        elif "select content_hash, storage_path from blobs" in normalized and "where not exists" in normalized:
            limit = params[0]
            with self.connection.lock:
                unreferenced = []
                for h, b in sorted(self.connection.blobs.items(), key=lambda item: item[1].get("created_at", 0)):
                    has_ref = any(
                        ref["content_hash"] == h and ref["ref_count"] > 0
                        for ref in self.connection.tenant_refs.values()
                    )
                    if not has_ref:
                        unreferenced.append(b)
                        if len(unreferenced) >= limit:
                            break

            for b in unreferenced:
                row_lock = self.connection.get_row_lock(b["content_hash"])
                row_lock.acquire()
                self.connection.held_locks.append(row_lock)

            if self.connection.before_collector_delete_hook:
                self.connection.before_collector_delete_hook()

            self._results = [
                FakeRow(content_hash=b["content_hash"], storage_path=b["storage_path"])
                for b in unreferenced
            ]
            self._idx = 0

        elif "delete from blobs where content_hash = %s" in normalized:
            content_hash = params[0]
            with self.connection.lock:
                self.connection.blobs.pop(content_hash, None)
                to_delete = [k for k, v in self.connection.tenant_refs.items() if v["content_hash"] == content_hash]
                for k in to_delete:
                    del self.connection.tenant_refs[k]

        elif "from tenant_blob_refs r join blobs b" in normalized:
            (tenant_id,) = params
            with self.connection.lock:
                matched = []
                for (ref_tenant, content_hash), ref in self.connection.tenant_refs.items():
                    if ref_tenant != tenant_id or ref["ref_count"] <= 0:
                        continue
                    blob = self.connection.blobs.get(content_hash)
                    if blob is None:
                        continue
                    shared = any(
                        other_tenant != tenant_id
                        and other_hash == content_hash
                        and other_ref["ref_count"] > 0
                        for (other_tenant, other_hash), other_ref in self.connection.tenant_refs.items()
                    )
                    matched.append(
                        FakeRow(
                            content_hash=content_hash,
                            ref_count=ref["ref_count"],
                            size_bytes=blob["size_bytes"],
                            created_at=blob["created_at"],
                            shared_with_other_tenants=shared,
                        )
                    )
                matched.sort(key=lambda r: (r["created_at"], r["content_hash"]))
            self._results = matched
            self._idx = 0

    def fetchone(self) -> FakeRow | None:
        if self._results and self._idx < len(self._results):
            row = self._results[self._idx]
            self._idx += 1
            return row
        return self._last_row

    def fetchall(self) -> list[FakeRow]:
        res = self._results[self._idx:]
        self._idx = len(self._results)
        return res


class FakeConnection:
    """In-memory fake Postgres connection supporting cursor context managers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.blobs: dict[str, dict] = {}
        self.tenant_refs: dict[tuple[str, str], dict] = {}
        self.cursors: list[FakeCursor] = []
        self.commits: int = 0
        self.row_locks: dict[str, threading.Lock] = {}
        self.row_locks_guard = threading.Lock()
        self.held_locks: list[threading.Lock] = []
        self.before_collector_delete_hook = None

    def get_row_lock(self, content_hash: str) -> threading.Lock:
        with self.row_locks_guard:
            if content_hash not in self.row_locks:
                self.row_locks[content_hash] = threading.Lock()
            return self.row_locks[content_hash]

    @property
    def executed(self) -> list[tuple[str, tuple]]:
        return [call for cur in self.cursors for call in cur.executed]

    def cursor(self) -> FakeCursor:
        cur = FakeCursor(self)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self.commits += 1
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def rollback(self) -> None:
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    """Fixture providing a fake db.get_connection context manager and connection."""
    conn = FakeConnection()

    @contextmanager
    def _fake_get_connection():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_get_connection)
    metrics_collector.reset()
    yield conn
    metrics_collector.reset()


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Fixture configuring a deterministic valid Fernet MASTER_ENCRYPTION_KEY."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key)
    return key


# ---------------------------------------------------------------------------
# assert_safe_destination — core path-alias checks
# ---------------------------------------------------------------------------


class TestAssertSafeDestination:
    """Unit tests for the low-level alias-rejection function."""

    def _protected(self, *paths: Path) -> frozenset[Path]:
        return frozenset(p.resolve() for p in paths)

    def test_safe_path_is_accepted(self, tmp_path: Path) -> None:
        """A destination outside any protected path raises nothing."""
        safe = tmp_path / "evidence" / "abc123.bin"
        protected = self._protected(tmp_path / "keys" / "secret.pem")
        assert_safe_destination(safe, protected)  # must not raise

    def test_exact_match_is_rejected(self, tmp_path: Path) -> None:
        """A destination identical to a protected file is rejected."""
        key_file = tmp_path / "keys" / "secret.pem"
        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(key_file, self._protected(key_file))

    def test_destination_inside_protected_directory_is_rejected(self, tmp_path: Path) -> None:
        """A destination that is a child of a protected directory is rejected."""
        source_tree = tmp_path / "app"
        destination = source_tree / "config.py"
        with pytest.raises(ValueError, match="inside a protected directory"):
            assert_safe_destination(destination, self._protected(source_tree))

    def test_destination_that_is_parent_of_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """A destination that *contains* a protected file is rejected.

        Writing to a directory that holds the metadata DB would replace
        the directory entry — that must not be allowed.
        """
        db_dir = tmp_path / "data"
        db_file = db_dir / "metadata.db"
        # destination == db_dir (the directory that holds the DB file)
        with pytest.raises(ValueError, match="parent of a protected path"):
            assert_safe_destination(db_dir, self._protected(db_file))

    def test_symlink_to_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """A symlink whose target resolves to a protected file is rejected."""
        real_key = tmp_path / "real_keys" / "secret.pem"
        real_key.parent.mkdir(parents=True)
        real_key.write_bytes(b"key material")

        link = tmp_path / "evidence" / "link_to_key"
        link.parent.mkdir(parents=True)
        link.symlink_to(real_key)

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(link, frozenset({real_key.resolve()}))

    def test_symlink_to_protected_directory_is_rejected(self, tmp_path: Path) -> None:
        """A symlink whose target resolves to a protected directory is rejected."""
        source_tree = tmp_path / "app"
        source_tree.mkdir()

        link = tmp_path / "evidence" / "sneaky_link"
        link.parent.mkdir(parents=True)
        link.symlink_to(source_tree)

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(link, frozenset({source_tree.resolve()}))

    def test_dotdot_traversal_to_protected_file_is_rejected(self, tmp_path: Path) -> None:
        """Path-traversal via ``..`` components is resolved and rejected."""
        key_file = (tmp_path / "keys" / "secret.pem").resolve()
        traversal = tmp_path / "evidence" / ".." / "keys" / "secret.pem"

        with pytest.raises(ValueError, match="aliases protected path"):
            assert_safe_destination(traversal, frozenset({key_file}))

    def test_empty_protected_set_always_accepts(self, tmp_path: Path) -> None:
        """With no protected paths every destination is acceptable."""
        destination = tmp_path / "output" / "blob.bin"
        assert_safe_destination(destination, frozenset())  # must not raise

    def test_multiple_protected_paths_any_match_rejects(self, tmp_path: Path) -> None:
        """When multiple protected paths are given, a match against any one rejects."""
        key_a = tmp_path / "keyA.pem"
        key_b = tmp_path / "keyB.pem"
        protected = frozenset({key_a.resolve(), key_b.resolve()})

        with pytest.raises(ValueError):
            assert_safe_destination(key_b, protected)

    def test_path_in_different_unprotected_subtree_is_accepted(self, tmp_path: Path) -> None:
        """A path in a different subtree from the protected paths is fine."""
        protected_dir = tmp_path / "protected"
        safe_dir = tmp_path / "safe"
        destination = safe_dir / "output.bin"

        # The directories don't even need to exist on disk for path checks.
        assert_safe_destination(destination, frozenset({protected_dir.resolve()}))


# ---------------------------------------------------------------------------
# BlobStore — write / read / delete / escape prevention
# ---------------------------------------------------------------------------


class TestBlobStore:
    """Integration-style tests for BlobStore using a real temp directory."""

    def _make_store(self, tmp_path: Path, extra_protected: frozenset[Path] | None = None) -> BlobStore:
        storage_root = tmp_path / "blobs"
        storage_root.mkdir()
        protected = frozenset({(tmp_path / "protected_key.pem").resolve()})
        if extra_protected:
            protected = protected | extra_protected
        config = StorageConfig(storage_path=storage_root, protected_paths=protected)
        return BlobStore(config)

    assert fake_db.commits == 1
    assert len(fake_db.executed) == 1
    sql, params = fake_db.executed[0]
    normalized_sql = " ".join(sql.lower().split())
    assert "insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path, envelope_version)" in normalized_sql
    assert "values (%s, %s, %s, %s, %s)" in normalized_sql
    assert "on conflict (content_hash) do nothing" in normalized_sql
    assert params == (
        content_hash,
        encrypted_dek.decode(),
        size_bytes,
        storage_path,
        evidence_storage.DEFAULT_ENVELOPE_VERSION,
    )

    def test_write_creates_file_with_correct_content(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("abc123.bin", b"encrypted evidence")
        dest = tmp_path / "blobs" / "abc123.bin"
        assert dest.exists()
        assert dest.read_bytes() == b"encrypted evidence"

    def test_write_returns_absolute_path(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        result = store.write("output.bin", b"data")
        assert result.is_absolute()
        assert result == (tmp_path / "blobs" / "output.bin").resolve()

    def test_write_creates_subdirectory_as_needed(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        store.write("2026/11/abc.bin", b"blob")
        assert (tmp_path / "blobs" / "2026" / "11" / "abc.bin").exists()

    assert fake_db.commits == 2
