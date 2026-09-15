"""Unit tests for the shared peer-ownership predicates (registry.utils.sync_ownership).

These pin the two rules every write path shares:

* peer-ownership is decided by the ``sync_metadata`` flags AND the operator's
  detach, and "detached" is a TRUTHINESS test -- ``local_overrides`` has been
  stored both as a bool and as a dict of overridden fields, while ``False`` and
  ``{}`` must leave the record peer-owned;
* ownership must be POSITIVELY established, so two blank identities can never
  compare equal and unlock a record whose ``registered_by`` federation ingest
  cleared.
"""

from registry.utils.sync_ownership import (
    UNKNOWN_PEER,
    caller_owns_record,
    is_locally_detached,
    peer_owned_source,
)

PEER = "peer-registry-lob-1"


class TestPeerOwnedSource:
    """Tests for peer_owned_source()."""

    def test_federated_returns_source_peer(self) -> None:
        doc = {"sync_metadata": {"is_federated": True, "source_peer_id": PEER}}
        assert peer_owned_source(doc) == PEER

    def test_read_only_returns_source_peer(self) -> None:
        doc = {"sync_metadata": {"is_read_only": True, "source_peer_id": PEER}}
        assert peer_owned_source(doc) == PEER

    def test_both_flags_returns_source_peer(self) -> None:
        doc = {
            "sync_metadata": {
                "is_federated": True,
                "is_read_only": True,
                "source_peer_id": PEER,
            }
        }
        assert peer_owned_source(doc) == PEER

    def test_detach_true_releases_ownership(self) -> None:
        doc = {
            "sync_metadata": {
                "is_federated": True,
                "is_read_only": True,
                "source_peer_id": PEER,
                "local_overrides": True,
            }
        }
        assert peer_owned_source(doc) is None

    def test_detach_dict_releases_ownership(self) -> None:
        """A non-empty overrides dict detaches just like the bool spelling."""
        doc = {
            "sync_metadata": {
                "is_federated": True,
                "is_read_only": True,
                "source_peer_id": PEER,
                "local_overrides": {"description": "locally corrected"},
            }
        }
        assert peer_owned_source(doc) is None

    def test_detach_false_stays_peer_owned(self) -> None:
        """local_overrides=False is the stored "attached" state, not a detach."""
        doc = {
            "sync_metadata": {
                "is_federated": True,
                "source_peer_id": PEER,
                "local_overrides": False,
            }
        }
        assert peer_owned_source(doc) == PEER

    def test_detach_empty_dict_stays_peer_owned(self) -> None:
        """No fields overridden means nothing was detached."""
        doc = {
            "sync_metadata": {
                "is_read_only": True,
                "source_peer_id": PEER,
                "local_overrides": {},
            }
        }
        assert peer_owned_source(doc) == PEER

    def test_flagged_without_source_peer_id_returns_placeholder(self) -> None:
        """A flagged record must still be rejected when the peer id is missing."""
        assert peer_owned_source({"sync_metadata": {"is_federated": True}}) == UNKNOWN_PEER

    def test_flagged_with_blank_source_peer_id_returns_placeholder(self) -> None:
        doc = {"sync_metadata": {"is_read_only": True, "source_peer_id": ""}}
        assert peer_owned_source(doc) == UNKNOWN_PEER

    def test_sync_metadata_present_but_unflagged_is_local(self) -> None:
        doc = {"sync_metadata": {"last_synced_at": "2026-01-01T00:00:00Z"}}
        assert peer_owned_source(doc) is None

    def test_missing_sync_metadata_is_local(self) -> None:
        assert peer_owned_source({"path": "/local/server"}) is None

    def test_none_sync_metadata_is_local(self) -> None:
        assert peer_owned_source({"sync_metadata": None}) is None

    def test_non_dict_sync_metadata_is_local(self) -> None:
        """Malformed metadata must not raise on a hot mutation path."""
        assert peer_owned_source({"sync_metadata": "federated"}) is None
        assert peer_owned_source({"sync_metadata": ["is_federated"]}) is None

    def test_none_doc_is_local(self) -> None:
        assert peer_owned_source(None) is None

    def test_empty_doc_is_local(self) -> None:
        assert peer_owned_source({}) is None


class TestIsLocallyDetached:
    """Tests for is_locally_detached() -- the truthiness rule shared with sync."""

    def test_true_flag_detaches(self) -> None:
        assert is_locally_detached({"sync_metadata": {"local_overrides": True}}) is True

    def test_non_empty_dict_detaches(self) -> None:
        doc = {"sync_metadata": {"local_overrides": {"tags": ["local"]}}}
        assert is_locally_detached(doc) is True

    def test_false_flag_is_attached(self) -> None:
        assert is_locally_detached({"sync_metadata": {"local_overrides": False}}) is False

    def test_empty_dict_is_attached(self) -> None:
        assert is_locally_detached({"sync_metadata": {"local_overrides": {}}}) is False

    def test_missing_flag_is_attached(self) -> None:
        assert is_locally_detached({"sync_metadata": {"is_federated": True}}) is False

    def test_missing_or_malformed_metadata_is_attached(self) -> None:
        assert is_locally_detached({}) is False
        assert is_locally_detached({"sync_metadata": None}) is False
        assert is_locally_detached({"sync_metadata": "yes"}) is False
        assert is_locally_detached(None) is False


class TestCallerOwnsRecord:
    """Tests for caller_owns_record()."""

    def test_matching_identities_own(self) -> None:
        assert caller_owns_record({"registered_by": "alice"}, "alice") is True

    def test_mismatched_identities_deny(self) -> None:
        assert caller_owns_record({"registered_by": "alice"}, "bob") is False

    def test_blank_stored_owner_denies(self) -> None:
        """Federation ingest stores registered_by="" -- an ownerless record."""
        assert caller_owns_record({"registered_by": ""}, "alice") is False

    def test_missing_stored_owner_denies(self) -> None:
        assert caller_owns_record({}, "alice") is False

    def test_none_stored_owner_denies(self) -> None:
        assert caller_owns_record({"registered_by": None}, "alice") is False

    def test_blank_username_denies(self) -> None:
        """A token minted without `sub` yields username="" -- never an owner."""
        assert caller_owns_record({"registered_by": "alice"}, "") is False

    def test_both_blank_denies(self) -> None:
        """The fail-closed case: two empty identities must not compare equal."""
        assert caller_owns_record({"registered_by": ""}, "") is False

    def test_none_username_denies(self) -> None:
        assert caller_owns_record({"registered_by": "alice"}, None) is False
        assert caller_owns_record({"registered_by": ""}, None) is False
