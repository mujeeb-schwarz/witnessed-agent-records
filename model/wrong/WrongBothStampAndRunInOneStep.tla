----------------------- MODULE WrongBothStampAndRunInOneStep -----------------------
\* Wrong version of the both-witnesses design: a witness adds the
\* fingerprint, the gate takes its stamp, and the tool starts, all in the
\* same step.
\* This tests the step form of rule 1. After the step the witness holds the
\* fingerprint, so the state form, Rule1, holds, and only Rule1Step sees
\* that no witness held it before the tool started.
\* Expected broken: Rule1Step, and RunNeedsHeldStamp on the same step, since
\* the gate cannot hold a stamp the witness has not yet made. Rule1 holds.
\* The step records the receipt, so BothListsHoldStarted and
\* BothReceiptsHeld hold too.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: in one step witness w adds and stamps the fingerprint,
\* the gate takes the stamp, and the call runs.
StampAndRun(w, a) ==
    /\ status[a] = "waiting"
    /\ witnessUp[w]
    /\ Fp(a) \in fpInFlight[w]
    /\ Fp(a) \notin Range(witnessList[w])
    /\ witnessList' = [witnessList EXCEPT ![w] = Append(@, Fp(a))]
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \cup {Fp(a)}]
    /\ stampsHeld' = [stampsHeld EXCEPT ![w] = @ \cup {Fp(a)}]
    /\ receipts' = [receipts EXCEPT ![w] = @ \cup {Fp(a)}]
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, witnessUp, witnessCrashes, gateCrashes, asked>>

WrongNext == Next \/ \E w \in Witnesses, a \in Actions : StampAndRun(w, a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
