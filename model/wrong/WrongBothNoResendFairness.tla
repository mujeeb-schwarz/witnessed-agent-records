----------------------- MODULE WrongBothNoResendFairness -----------------------
\* Wrong version of the both-witnesses design's progress assumptions: the
\* gate is not assumed to send a missing fingerprint again. The steps are
\* the design's; only the fairness on catch-up is gone.
\* Expected broken: EveryStartedCallGetsBothReceipts. A call runs on one
\* witness's stamp, the fingerprint on its way to the other is lost, and the
\* gate never sends it again, so the second stamp never comes.
\* Its steps are the design's, so the safety checks hold; its settings
\* file checks only the progress rule, with one call.
EXTENDS GateBothWitnesses

\* LiveSpec without weak fairness on CatchUp.
WrongLiveSpec ==
    /\ Spec
    /\ \A w \in Witnesses : WF_vars(WitnessRestart(w))
    /\ \A w \in Witnesses, f \in Fingerprints :
          /\ SF_vars(WitnessStamps(w, f))
          /\ SF_vars(WitnessRestamps(w, f))
          /\ SF_vars(RecordLateReceipt(w, f))
=============================================================================
