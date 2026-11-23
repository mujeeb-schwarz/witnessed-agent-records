---------------------------- MODULE GateReach ----------------------------
\* A reachability check for the spike's model: can a normal run start a
\* tool at all? NoCallEverStarts says no call ever starts. TLC must report
\* it broken, with a trace that is a normal run of Gate's own steps. If it
\* held, the start checks would pass only because nothing ever runs.
EXTENDS Gate
NoCallEverStarts == effects = {}
=============================================================================
