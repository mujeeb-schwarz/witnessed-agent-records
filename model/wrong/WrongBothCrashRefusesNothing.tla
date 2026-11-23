----------------------- MODULE WrongBothCrashRefusesNothing -----------------------
\* Wrong version of the both-witnesses design: after its crash, the
\* restarted gate refuses nothing. It still loses the calls it had not
\* written down and the stamps it held, and it goes on waiting for the calls
\* it journaled and never decided.
\* Expected broken: CrashRefusesUndecided only, when the gate crashes with a
\* call journaled or waiting. Such a call can still run later, but only on
\* a stamp that arrives after the restart, so the other checks hold.
\* This file is the spec in GateBothWitnesses.tla with one wrong step added.
EXTENDS GateBothWitnesses

\* The wrong step: the gate crashes and restarts without refusing anything.
GateCrashRefusesNothing ==
    /\ gateCrashes = 0
    /\ gateCrashes' = 1
    /\ status' = [a \in Actions |->
                     IF status[a] = "proposed" THEN "lost" ELSE status[a]]
    /\ stampsHeld' = [w \in Witnesses |-> {}]
    /\ UNCHANGED <<journal, effects, messageVars, receipts, witnessVars, asked>>

WrongNext == Next \/ GateCrashRefusesNothing
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
