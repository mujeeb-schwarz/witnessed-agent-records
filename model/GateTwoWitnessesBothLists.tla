----------------------- MODULE GateTwoWitnessesBothLists -----------------------
\* A comparison, not a wrong version: the failover-only design in
\* GateTwoWitnesses.tla, judged by the check that GateBothWitnesses.tla
\* adds. Expected: TLC reports BothListsHoldStarted broken. The backup may
\* never be asked, and catch-up runs only to the main witness after it
\* restarts, so a started call's fingerprint can be missing from one list
\* even once everything has settled. GateBothWitnesses should pass it.
EXTENDS GateTwoWitnesses

\* What catch-up in the failover-only design still has to send.
CatchUpPending(f) ==
    /\ witnessUp["main"]
    /\ witnessCrashes["main"] = 1
    /\ f \in stampsHeld["backup"]
    /\ f \notin caughtUp

\* Settled, as in GateBothWitnesses.tla: every call decided, both witnesses
\* up, no catch-up left to send, and nothing on its way still to be added.
Settled ==
    /\ \A a \in Actions : status[a] \in {"ran", "refused", "lost"}
    /\ \A w \in Witnesses : witnessUp[w]
    /\ \A f \in Fingerprints : ~CatchUpPending(f)
    /\ \A w \in Witnesses, f \in Fingerprints :
          ~(f \in fpInFlight[w] /\ f \notin Range(witnessList[w]))

\* Once everything has settled, both lists hold the fingerprint of every
\* started call.
BothListsHoldStarted ==
    Settled => \A a \in effects : \A w \in Witnesses : Fp(a) \in Range(witnessList[w])
=============================================================================
