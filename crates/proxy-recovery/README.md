# Proxy recovery core

This crate owns the transaction state machine used before CodeIsCheap changes system proxy settings.

1. Read the exact original settings.
2. Persist an armed recovery journal.
3. Spawn an independent watchdog and wait for its `ready` handshake.
4. Apply the desired proxy settings.
5. On normal shutdown, restore and disarm the watchdog.
6. On owner-process death, pipe EOF makes the watchdog restore its in-memory snapshot.
7. On the next startup, an armed journal provides a second recovery path.

The included file backend exists only for deterministic crash injection. Production Windows and macOS backends, private journal-directory permissions, and platform notifications are separate work; `SPIKE-003` remains in progress until those backends pass real setting/restore experiments.
