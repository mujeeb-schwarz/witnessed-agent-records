-------------------- MODULE WrongBothFingerprintBeforeJournal --------------------
\* Wrong version of the both-witnesses design: the gate sends the
\* fingerprint to both witnesses before writing the call in the journal,
\* and goes on as if it had. The call then waits for its stamp and can run
\* without ever being journaled.
\* Expected broken: JournalBeforeSend, at the early send, and Check3, once a
\* witness stamps: the same fault seen at the gate and at the witnesses.
\* Nothing else should break.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: the gate sends a proposed call's fingerprint to both
\* witnesses at once and starts waiting, with nothing in the journal.
SendBeforeJournal(a) ==
    /\ status[a] = "proposed"
    /\ fpInFlight' = [w \in Witnesses |-> fpInFlight[w] \cup {Fp(a)}]
    /\ asked' = [w \in Witnesses |-> asked[w] \cup {Fp(a)}]
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampVars, witnessVars,
                   gateCrashes>>

WrongNext == Next \/ \E a \in Actions : SendBeforeJournal(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
