"""Tests for the lawful-accountability layer: authorization, tamper-evident audit,
retention, and oversight. Deterministic (a fixed clock is passed throughout)."""

import pytest

from ariadne.authority import GENESIS_HASH, AuthorityStore, Authorization

T0 = 1_700_000_000.0
DAY = 86400.0


def _store(tmp_path):
    return AuthorityStore(tmp_path / "authority.sqlite")


# --------------------------------------------------------------------------- #
# authorizations
# --------------------------------------------------------------------------- #
def test_authorization_validity_and_scope():
    a = Authorization("id", "case1", "subj", "warrant", "court", "off",
                      granted_at=T0, expires_at=T0 + 10 * DAY, scope_addresses=["A"])
    assert a.is_valid(T0 + DAY) and not a.is_valid(T0 + 11 * DAY)
    assert a.covers("A") and not a.covers("B")     # scoped
    b = Authorization("id2", "case1", "subj", "warrant", "court", "off",
                      granted_at=T0, expires_at=T0 + 10 * DAY)
    assert b.covers("anything")                    # case-level covers all


def test_add_authorization_requires_legal_basis_and_authority(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.add_authorization("case1", "subj", "", "court", "off")
    with pytest.raises(ValueError):
        s.add_authorization("case1", "subj", "warrant", "", "off")
    s.close()


def test_valid_authorization_for(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect wallet", "prosecutor order #7", "Athens Prosecutor",
                            "Officer K", valid_days=30, scope_addresses=["ADDR1"], now=T0)
    assert s.valid_authorization_for("ADDR1", now=T0 + DAY).id == a.id
    assert s.valid_authorization_for("OTHER", now=T0 + DAY) is None          # out of scope
    assert s.valid_authorization_for("ADDR1", now=T0 + 40 * DAY) is None     # expired
    s.close()


# --------------------------------------------------------------------------- #
# tamper-evident audit chain
# --------------------------------------------------------------------------- #
def test_audit_chain_links_and_flags_authorization(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect", "warrant", "court", "off",
                            scope_addresses=["ADDR1"], now=T0)
    e1 = s.record_action("analyst1", "trace", "ADDR1", authorization_id=a.id, now=T0 + 1)
    e2 = s.record_action("analyst1", "trace", "ADDR2", authorization_id=a.id, now=T0 + 2)  # out of scope
    e3 = s.record_action("analyst1", "trace", "ADDR3", authorization_id=None, now=T0 + 3)  # none

    assert e1["authorized"] is True                    # covered
    assert e2["authorized"] is False                   # authorization doesn't cover ADDR2
    assert e3["authorized"] is False                   # no authorization at all
    assert e1["prev_hash"] == GENESIS_HASH
    assert e2["prev_hash"] == e1["entry_hash"]         # chained
    assert e3["prev_hash"] == e2["entry_hash"]
    assert s.verify_chain()["ok"] is True
    s.close()


def test_verify_chain_detects_tampering(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect", "warrant", "court", "off", now=T0)
    s.record_action("analyst1", "trace", "ADDR1", authorization_id=a.id, now=T0 + 1)
    s.record_action("analyst1", "trace", "ADDR2", authorization_id=a.id, now=T0 + 2)
    assert s.verify_chain()["ok"] is True

    # Silently rewrite a past entry's target directly in the database.
    s._conn.execute("UPDATE audit SET target='COVERUP' WHERE seq=1")
    s._conn.commit()

    result = s.verify_chain()
    assert result["ok"] is False and result["broken_at"] == 1   # tamper localised
    s.close()


def test_verify_chain_detects_deletion(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect", "warrant", "court", "off", now=T0)
    for i in range(3):
        s.record_action("analyst1", "trace", f"ADDR{i}", authorization_id=a.id, now=T0 + i)
    s._conn.execute("DELETE FROM audit WHERE seq=2")   # remove a middle entry
    s._conn.commit()
    assert s.verify_chain()["ok"] is False             # gap breaks the chain
    s.close()


# --------------------------------------------------------------------------- #
# retention & oversight
# --------------------------------------------------------------------------- #
def test_retention_review_flags_old_unauthorized(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect", "warrant", "court", "off", valid_days=30, now=T0)
    s.record_action("analyst1", "trace", "OLD", authorization_id=a.id, now=T0)             # old, auth expired later
    s.record_action("analyst1", "trace", "RECENT", authorization_id=a.id, now=T0 + 200 * DAY)
    # 100 days later, the first action is past a 90-day window and its auth has expired.
    review = s.retention_review(max_age_days=90, now=T0 + 200 * DAY)
    targets = {e["target"] for e in review["entries"]}
    assert "OLD" in targets and "RECENT" not in targets
    s.close()


def test_oversight_report_counts_and_flags(tmp_path):
    s = _store(tmp_path)
    a = s.add_authorization("case1", "suspect", "warrant", "court", "off",
                            scope_addresses=["ADDR1"], now=T0)
    s.record_action("analyst1", "trace", "ADDR1", authorization_id=a.id, now=T0 + 1)  # authorized
    s.record_action("analyst2", "trace", "ADDR9", authorization_id=None, now=T0 + 2)  # UNauthorized

    rep = s.oversight_report(now=T0 + 3)
    assert rep["authorizations"]["active"] == 1
    assert rep["actions"]["total"] == 2 and rep["actions"]["unauthorized"] == 1
    assert rep["compliance_flags"][0]["target"] == "ADDR9"
    assert rep["audit_chain"]["ok"] is True
    s.close()
