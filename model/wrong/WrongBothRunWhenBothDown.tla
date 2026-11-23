------------------------ MODULE WrongBothRunWhenBothDown ------------------------
\* Wrong version of the both-witnesses design: the gate runs the call when
\* both witnesses are down, holding no stamp from either.
\* Expected broken: RunNeedsHeldStamp, in every order, since the gate holds
\* no stamp; Rule1 and Rule1Step, where neither witness holds the
\* fingerprint; and BothListsHoldStarted and BothReceiptsHeld, in orders
\* where the gate never records a stamp for the call, for instance when
\* both copies of the fingerprint are lost while the witnesses are down.
\* The gate then has no receipt to catch up from.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: with both witnesses down, the gate stops waiting for a
\* stamp and lets the call run.
RunWhenBothDown(a) ==
    /\ status[a] = "waiting"
    /\ ~witnessUp["main"]
    /\ ~witnessUp["backup"]
    /\ ~HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<messageVars, stampVars, witnessVars, gateCrashes, asked>>

WrongNext == Next \/ \E a \in Actions : RunWhenBothDown(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
