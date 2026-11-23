--------------------------- MODULE WrongRunBeforeJournal ---------------------------
\* Wrong version 1: the gate lets the action run before
\* writing it in the journal.
\* The wrong step bypasses the whole pipeline: no journal entry, no
\* fingerprint and no stamp. TLC catches it through the missing fingerprint
\* (rule 1) and the missing stamp, so it tests a gate that runs at once.
\* The journal's place in the order is tested by WrongFingerprintBeforeJournal.
\* Expected broken: Rule1, Rule1Step and RunNeedsHeldStamp.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: a proposed action runs at once, with nothing written in
\* the journal and no fingerprint sent.
RunBeforeJournal(a) ==
    /\ status[a] = "proposed"
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ UNCHANGED <<journal, fpInFlight, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : RunBeforeJournal(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
