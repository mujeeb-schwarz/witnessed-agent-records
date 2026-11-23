# GateBothWitnesses (with late receipts and re-stamping): each wrong version against each check alone

Each cell is one TLC run with TypeOK and that one check, deadlock reporting off, two calls. BROKEN (n) means the check broke, with a trace of n states; holds means TLC searched every reachable state and the check held. Total time: 180 minutes.

| Wrong version | Rule1 | Check3 | RefusedNeverRuns | StampsOnlyFromAsked | BothListsHoldStarted | BothReceiptsHeld | Rule1Step | Rule2 | RunNeedsHeldStamp | CrashRefusesUndecided | JournalBeforeSend |
|---|---|---|---|---|---|---|---|---|---|---|---|
| WrongBothAcceptsUnaskedStamp | holds | holds | holds | BROKEN (8) | holds | holds | holds | holds | holds | holds | holds |
| WrongBothCatchUpOneWay | holds | holds | holds | holds | BROKEN (10) | BROKEN (10) | holds | holds | holds | holds | holds |
| WrongBothCrashRefusesNothing | holds | holds | holds | holds | holds | holds | holds | holds | holds | BROKEN (5) | holds |
| WrongBothFingerprintBeforeJournal | holds | BROKEN (4) | holds | holds | holds | holds | holds | holds | holds | holds | BROKEN (3) |
| WrongBothNoLateReceipt | holds | holds | holds | holds | holds | BROKEN (10) | holds | holds | holds | holds | holds |
| WrongBothNoRestamp | holds | holds | holds | holds | holds | BROKEN (11) | holds | holds | holds | holds | holds |
| WrongBothRunAfterRefusal | holds | holds | BROKEN (9) | holds | holds | holds | holds | holds | holds | holds | holds |
| WrongBothRunWhenBothDown | BROKEN (7) | holds | holds | holds | BROKEN (13) | BROKEN (13) | BROKEN (7) | holds | BROKEN (7) | holds | holds |
| WrongBothRunWithoutHeldStamp | holds | holds | holds | holds | BROKEN (11) | BROKEN (11) | holds | holds | BROKEN (6) | holds | holds |
| WrongBothStampAndRunInOneStep | holds | holds | holds | holds | holds | holds | BROKEN (5) | holds | BROKEN (5) | holds | holds |
| WrongBothStampWithoutAdding | BROKEN (7) | holds | holds | holds | BROKEN (12) | holds | BROKEN (7) | holds | holds | holds | holds |
| WrongBothWitnessInMemory | BROKEN (8) | holds | holds | holds | BROKEN (14) | holds | BROKEN (9) | BROKEN (6) | holds | holds | holds |
