--------------------------- MODULE WrongRunAfterRefusal ---------------------------
\* Added on Sun 22 Nov after the independent review: the gate gives up and
\* refuses the action, then runs it anyway with a stamp it already held.
\* Expected broken: RefusedNeverRuns only. The stamp is real and the witness
\* holds the fingerprint, so both rules hold.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: a refused action runs, because the gate still holds its
\* stamp.
RunAfterRefusal(a) ==
    /\ status[a] = "refused"
    /\ Fp(a) \in stampsHeld
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, stampsInFlight, stampsHeld, witnessList,
                   gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : RunAfterRefusal(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
