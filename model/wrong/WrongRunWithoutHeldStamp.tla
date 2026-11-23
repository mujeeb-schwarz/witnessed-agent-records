------------------------- MODULE WrongRunWithoutHeldStamp -------------------------
\* Added on Sun 22 Nov after the independent review: the witness stamps, and
\* the gate lets the action run before the stamp has reached it.
\* Expected broken: RunNeedsHeldStamp only. The witness does hold the
\* fingerprint, so both rules hold, and only the check that the gate held
\* the stamp sees the fault.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: once the witness has the fingerprint, the gate runs the
\* action without holding the stamp.
RunWithoutHeldStamp(a) ==
    /\ status[a] = "waiting"
    /\ Fp(a) \in Range(witnessList)
    /\ Fp(a) \notin stampsHeld
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, stampsInFlight, stampsHeld, witnessList,
                   gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : RunWithoutHeldStamp(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
