----------------------- MODULE WrongBothStampWithoutAdding -----------------------
\* Wrong version of the both-witnesses design: a witness stamps a
\* fingerprint without adding it to its list.
\* Expected broken: Rule1 and Rule1Step, where the other witness does not
\* hold the fingerprint either; and BothListsHoldStarted, where the stamping
\* witness's own copy is then lost, since the gate's receipt from it stops
\* any catch-up to it. The gate holds a real-looking stamp, so
\* RunNeedsHeldStamp holds, and it records that stamp, so catch-up brings
\* the other witness's and BothReceiptsHeld holds.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: the witness sends a stamp and leaves its list as it was.
StampWithoutAdding(w, f) ==
    /\ witnessUp[w]
    /\ f \in fpInFlight[w]
    /\ f \notin Range(witnessList[w])
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampVars,
                   witnessVars, gateCrashes, asked>>

WrongNext == Next \/ \E w \in Witnesses, f \in Fingerprints : StampWithoutAdding(w, f)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
