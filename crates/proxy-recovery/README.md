# Proxy recovery core

This crate owns the transaction state machine used before CodeIsCheap changes system proxy settings.

1. Read the exact original settings.
2. Persist an armed recovery journal.
3. Spawn an independent watchdog and wait for its `ready` handshake.
4. Apply the desired proxy settings.
5. On normal shutdown, restore and disarm the watchdog.
6. On owner-process death, pipe EOF makes the watchdog restore its in-memory snapshot.
7. On the next startup, an armed journal provides a second recovery path.

The included file backend exists only for deterministic crash injection. Windows WinINet and macOS networksetup backends have both passed real force-kill recovery experiments on temporary GitHub runners. Production still requires private journal-directory permissions and a controlled macOS privileged helper.
