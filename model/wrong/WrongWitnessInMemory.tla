--------------------------- MODULE WrongWitnessInMemory ---------------------------
\* Wrong version 3: the witness keeps its list only in
\* memory, so a crash wipes it. This tests losing the witness's saved list
\* as a whole; it does not test how storage is written.
\* Expected broken: Rule2, when the witness crashes after adding a
\* fingerprint. In longer orders Rule1 breaks too (an action that ran before
\* the crash loses its fingerprint), and so does Rule1Step (an action runs
\* after the crash with a stamp the gate already held).
\* This file is the spec in Gate.tla with one wrong step added.
EXTENDS Gate

\* The wrong step: the witness crashes, and its list, held only in memory,
\* is gone.
WitnessCrashWipesList ==
    /\ witnessCrashes = 0
    /\ witnessCrashes' = 1
    /\ witnessList' = <<>>
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsInFlight,
                   stampsHeld, gateCrashes>>

WrongNext == Next \/ WitnessCrashWipesList
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
