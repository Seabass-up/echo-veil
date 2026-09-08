# SQLite Lock Safety

POSIX file inspection must not open and close live SQLite database files or
their sidecars. Closing an independently opened descriptor can cancel the
process's existing advisory locks, including locks held by SQLite connections.
This is a documented [SQLite locking hazard](https://www.sqlite.org/howtocorrupt.html#_posix_advisory_locks_canceled_by_a_separate_thread_doing_close_).

The installed Echo Veil 0.8.0 dependency used by Algo CLI reproduced this defect
on macOS with Python 3.14.6 and SQLite 3.53.3. On a disposable database, a second
process first received `SQLITE_BUSY`, then acquired `BEGIN IMMEDIATE` after an
in-process security validator ran while the original transaction was still
open. Both payload and persistence validators failed in WAL and DELETE modes.
This demonstrates lock loss; it does not by itself prove the cause of a
previous native SIGBUS or establish that any operator database is corrupt.

## Implementation Contract

- Observe existing file metadata with no-follow, directory-relative stat calls.
  Pin and recheck the private parent and every trusted ancestor. Require a
  regular, singly linked file owned by the current user with no group or other
  permissions. Reject changes in observed identity, ownership, or mode.
- Retain the expected database identity across SQLite connection construction.
  These observations are not an attestation of SQLite's internal descriptor or
  protection against a compromised same-user host.
- Create missing databases only with an exclusive create, and close that new
  descriptor before opening SQLite. Serialize local initializers. An existing
  database must not be reopened by the creation helper.
- Apply the same rule to profile-wide health inspection, including the writer
  lease database and live sidecars. Windows DACL and handle checks are unchanged.
- Do not remove WAL/SHM files, force checkpoints, reset keys, disable required
  protection, or retry a potentially completed mutation to conceal a failure.

## Verification and Delivery

`tests/test_sqlite_lock_preservation.py` uses a real second process to check
writer exclusion across six inspection paths in both journal modes. It also
checks unsafe leaves, namespace replacement, parent replacement, permission
changes, expected identity, and the absence of existing-file opens. Existing
persistence and agent-memory security tests remain required.

Source qualification is not installed-host delivery. Rebuild and verify an
immutable dependency artifact, update reviewed source/artifact pins through
the release process, and qualify each consuming host before claiming its
runtime has the repair. Keep failed native-process receipts separate from
successful model-stream recovery checks.
