# Keeping this fork current

Sync official `tulir/whatsmeow` into a feature branch based on the current fork
`origin/main`, using a merge so both published histories remain intact. Open a
PR against fork `main`; review and test it before merge. Then update the platform
CI and deployment-guard pins together in a separate platform PR.

## Sync prepared on 2026-10-07

Fork base: `bd2f706a802e02ad06ec069a49a34995be46f5c6` (PR #12 merged).
Official upstream: `c386243a72bacad080ba2938b37e1e4e0f1ca3b2`.
The merge incorporates all 80 previously upstream-only commits.

| Overlap | Resolution |
| --- | --- |
| App-state conflict handling | Retain `applyConflictPatches` and the fork's atomic cursor/MAC ledger update. |
| Client lifecycle | Adopt upstream per-connection queues and headers; preserve lifecycle classification, bounded retry bookkeeping, reconnect backoff and owner cancellation. |
| Send results and Muse encryption | Keep `GroupDebug` and encryption-identity capture alongside upstream `Chat`, recipient PN and WASA encryption. `DisableAutoRetry` and controlled retry guards remain. |
| SQL upgrades | Keep fork migrations 15–20 unchanged; upstream 15/16 become fork 21/22. Fresh bootstrap becomes v22 while retaining flat sender-key bytes and indexes. |
| JID defaults | Adopt upstream's equivalent case/default simplification. |
| Module checksums | Retain fork dependencies and tidy the merged graph; upstream requires Go 1.26 and selects toolchain 1.27.1. |
| Media downloads (automatic merge) | Preserve authenticated decryption when a media key exists but the optional encrypted checksum is absent. Presence of a key, rather than checksum alone, chooses encrypted download. |

Existing sender-key recovery/cache, device absence, retry-owner, controlled-send,
physical socket write and SQL regressions remain in the suite. The media-delete
fixture now supplies the device required by upstream's companion nonce header.
The retry test's private constructor linkage follows upstream's changed signature.
No test assertions were removed.

## Validation

- Entire fork suite on Go 1.26.0 and 1.27.1, with an explicit disposable Postgres DSN.
- Go 1.27.1 race checks for root, socket, store and SQL-store packages.
- Fresh and existing v20 schema upgrade, repeat upgrade, exact sender-key bytes,
  generated key ID, prefix index, companion nonce and WASA secret round trips.
- Public memory/file/thumbnail downloads with nil/empty encrypted checksums;
  corrupted MACs and wrong plaintext hashes remain rejected.

CI now provisions disposable Postgres, bootstraps the schema and serializes packages
that share test tables. The upstream Go 1.26/1.27 build matrix is retained.

## Review each subsequent sync

Fetch both remotes, record their exact tips and compare changes since the last
merge base. Resolve each conflict from both implementations; also inspect automatic
merges in send/retry, message decryption, socket lifetime, cache wrappers and schema
upgrades. Keep fork migration numbers unique and advance the bootstrap snapshot.
Run the entire fork suite with disposable databases, concurrency checks and the
platform driver suite against the proposed tree. Verify upstream and the previous
fork tip are ancestors of the result. Keep pins immutable and publish validation
in the PR; production deployment uses only verified merged default branches.
