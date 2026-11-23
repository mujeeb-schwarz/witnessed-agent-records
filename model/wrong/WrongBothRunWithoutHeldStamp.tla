----------------------- MODULE WrongBothRunWithoutHeldStamp -----------------------
\* Wrong version of the both-witnesses design: once a witness has stamped,
\* the gate runs the call before the stamp has reached it.
\* Expected broken: RunNeedsHeldStamp. A witness does hold the fingerprint,
\* so rule 1 holds. BothListsHoldStarted and BothReceiptsHeld break too, in
\* orders where the gate never records a stamp for the call: the other
\* witness's copy is lost, and so are the stamping witness's stamp and its
\* copy of the fingerprint, which would otherwise bring the stamp again.
\* The gate then has no receipt to catch up from.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: once some witness holds the fingerprint, the gate runs
\* the call without holding a stamp.
RunWithoutHeldStamp(a) ==
    /\ status[a] = "waiting"
    /\ HeldBySomeWitness(Fp(a))
    /\ ~HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<messageVars, stampVars, witnessVars, gateCrashes, asked>>

WrongNext == Next \/ \E a \in Actions : RunWithoutHeldStamp(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
