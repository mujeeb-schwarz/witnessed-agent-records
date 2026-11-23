------------------------ MODULE WrongBothWitnessInMemory ------------------------
\* Wrong version of the both-witnesses design: a witness keeps its list only
\* in memory, so its crash wipes the list. This tests losing a witness's
\* saved list as a whole; it does not test how storage is written.
\* Expected broken: Rule2, when either witness crashes after adding a
\* fingerprint. In longer orders: Rule1, if the wiped witness was the only
\* one holding a started call's fingerprint; Rule1Step, if a call runs after
\* the crash on a stamp the gate already held; and BothListsHoldStarted,
\* since the gate's receipts from the wiped witness stop any catch-up to it.
\* BothReceiptsHeld holds: the receipts are in the gate's journal, which
\* the witness's crash does not touch.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: a witness crashes, and its list, held only in memory, is
\* gone.
WitnessCrashWipesList(w) ==
    /\ witnessUp[w]
    /\ witnessCrashes[w] = 0
    /\ witnessUp' = [witnessUp EXCEPT ![w] = FALSE]
    /\ witnessCrashes' = [witnessCrashes EXCEPT ![w] = 1]
    /\ witnessList' = [witnessList EXCEPT ![w] = <<>>]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampVars,
                   gateCrashes, asked>>

WrongNext == Next \/ \E w \in Witnesses : WitnessCrashWipesList(w)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
