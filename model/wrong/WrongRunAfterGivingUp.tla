--------------------------- MODULE WrongRunAfterGivingUp ---------------------------
\* Wrong version 2: the gate lets the action run anyway when
\* it gives up waiting for the stamp.
\* It tests a gate that fails open when it stops waiting. Running an action
\* after the gate has refused it is WrongRunAfterRefusal's test.
\* Expected broken: RunNeedsHeldStamp in every order; Rule1 and Rule1Step in
\* orders where the fingerprint is lost or late, so the witness does not
\* hold it when the tool starts to run.
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: the gate stops waiting and lets the action run without a
\* stamp.
RunAnyway(a) ==
    /\ status[a] = "waiting"
    /\ Fp(a) \notin stampsHeld
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, stampsInFlight, stampsHeld, witnessList,
                   gateCrashes, witnessCrashes>>

WrongNext == Next \/ \E a \in Actions : RunAnyway(a)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
