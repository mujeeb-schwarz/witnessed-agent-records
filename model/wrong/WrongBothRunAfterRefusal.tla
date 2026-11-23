------------------------ MODULE WrongBothRunAfterRefusal ------------------------
\* Wrong version of the both-witnesses design: a stamp that arrives after
\* the gate has refused the call revives it, and the gate runs it.
\* In the design the gate refuses only when it holds no stamp, so a refused
\* call never holds one; this file adds two steps to the spec in
\* GateBothWitnesses.tla: the gate taking a late stamp for a refused call,
\* and then running that call.
\* Expected broken: RefusedNeverRuns only. The stamp is real and held before
\* the start, so rule 1 and RunNeedsHeldStamp hold.
EXTENDS GateBothWitnesses

\* The first wrong step: the gate takes a stamp for a call it has refused.
LateStampArrives(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ f \in asked[w]
    /\ status[ActionOf(f)] = "refused"
    /\ f \notin stampsHeld[w]
    /\ stampsHeld' = [stampsHeld EXCEPT ![w] = @ \cup {f}]
    /\ receipts' = [receipts EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, messageVars, witnessVars,
                   gateCrashes, asked>>

\* The second wrong step: the gate runs the refused call on that stamp.
RunRefused(a) ==
    /\ status[a] = "refused"
    /\ HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<messageVars, stampVars, witnessVars, gateCrashes, asked>>

WrongNext ==
    \/ Next
    \/ \E w \in Witnesses, f \in Fingerprints : LateStampArrives(w, f)
    \/ \E a \in Actions : RunRefused(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
