------------------------ MODULE WrongFingerprintBeforeJournal ------------------------
\* Wrong version 4, added on 22 Nov 2026 to test the third check: the
\* gate sends the
\* fingerprint for an action before writing the action in the journal, and
\* goes on as if it had. The action then waits for its stamp and can run
\* without ever being journaled.
\* Expected broken: JournalBeforeSend, at the early send, and Check3, once
\* the witness stamps: the same fault seen at the gate and at the witness.
\* Nothing else should break, and the first two rules hold.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: the gate sends a proposed action's fingerprint at once and
\* starts waiting for the stamp, with nothing written in the journal.
SendBeforeJournal(a) ==
    /\ status[a] = "proposed"
    /\ fpInFlight' = fpInFlight \cup {Fp(a)}
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : SendBeforeJournal(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
