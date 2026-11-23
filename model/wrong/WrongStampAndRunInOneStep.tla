------------------------- MODULE WrongStampAndRunInOneStep -------------------------
\* Added on Sun 22 Nov after the independent review: the witness adds the
\* fingerprint and the tool starts, in the same step.
\* This tests the step form of rule 1. After the step the witness holds the
\* fingerprint, so the state form, Rule1, holds, and only Rule1Step sees
\* that the fingerprint was not there before the tool started.
\* Expected broken: Rule1Step, and RunNeedsHeldStamp on the same step, since
\* the gate cannot hold a stamp the witness has not yet made. Rule1, Rule2
\* and Check3 hold.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: in one step the witness adds and stamps the fingerprint,
\* and the gate lets the action run.
StampAndRun(a) ==
    /\ status[a] = "waiting"
    /\ Fp(a) \in fpInFlight
    /\ Fp(a) \notin Range(witnessList)
    /\ witnessList' = Append(witnessList, Fp(a))
    /\ stampsInFlight' = stampsInFlight \cup {Fp(a)}
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, stampsHeld, gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : StampAndRun(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
