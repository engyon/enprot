use crate::Fixture;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

// CHAIN directive parser integration (TODO.finalize/17 parser side).
// These tests prove the wire format is stable: a CHAIN block in an
// EPT file parses cleanly, round-trips through tree_write, and
// appears in `enprot list` output.
//
// They do NOT test signature verification — that's verify-chain
// (TODO.finalize/18) which depends on resolving a pubkey.

#[test]
fn passthrough_preserves_chain_block() {
    let ept = Fixture::copy("test-data/chain-anchor.ept");
    let original = fs::read_to_string(&ept.path).unwrap();

    // passthrough = parse + re-write. The CHAIN block's fields must
    // survive; the field ORDER may differ because BTreeMap iterates
    // alphabetically (canonical form — see TODO.finalize/17).
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success();

    let after = fs::read_to_string(&ept.path).unwrap();
    for fragment in [
        "CHAIN",
        "parents:575d",
        "signer:ed25519:9f3a7b",
        "ts:20260725T143000Z",
        "mut:encrypt+WORD",
        "payload:7a4e9b",
        "sig:3045022100",
    ] {
        assert!(
            after.contains(fragment),
            "expected fragment '{}' in output:\n{}",
            fragment,
            after
        );
    }
    let _ = original; // sanity baseline; byte-identity isn't required
}

#[test]
fn list_shows_chain_anchor_summary() {
    let ept = Fixture::copy("test-data/chain-anchor.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("list")
        .arg(&ept.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("CHAIN"))
        .stdout(predicate::str::contains("signer="))
        .stdout(predicate::str::contains("payload="));
}

#[test]
fn chain_block_with_unknown_fields_round_trips() {
    // Forward-compatibility: a CHAIN block with extfields we don't
    // recognize today should still parse and round-trip. Future
    // enprot versions might add fields like `revision` or `branch`.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("future.ept");
    let body = "// <( CHAIN parents:abc123 signer:ed25519:deadbeef future-field:value-42 payload:fedcba sig:999fff )>\n";
    fs::write(&path, body).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg(&path)
        .assert()
        .success();

    let after = fs::read_to_string(&path).unwrap();
    assert!(
        after.contains("future-field:value-42"),
        "unknown extfield must round-trip: got {}",
        after
    );
}

#[test]
fn chain_with_no_extfields_is_a_parse_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("empty.ept");
    fs::write(&path, "// <( CHAIN )>\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg(&path)
        .assert()
        .failure();
}
