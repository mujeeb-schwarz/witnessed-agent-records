-------------------------- MODULE WrongWaitsForever --------------------------
\* The liveness check's wrong version, added on 22 Nov 2026 with
\* GateLive: a gate that can wait forever. It has no step for giving
\* up, and after a crash it refuses nothing.
\* Expected: TLC reports EveryProposedDecided broken. Once an action's
\* fingerprint or its stamp is lost, the gate waits for that action forever.
\* Run TLC on this file with -deadlock (see WrongWaitsForever.cfg).
\* Unlike the other wrong versions, this one takes a step away from the spec
\* in Gate.tla and changes another.
EXTENDS GateLive

\* The wrong gate's crash: it restarts without refusing anything. It still
\* loses the actions it held but had not written down, and every stamp it
\* held, and it goes on waiting for the actions it journaled and never
\* decided.
GateCrashNoRefusal ==
    /\ gateCrashes = 0
    /\ gateCrashes' = 1
    /\ status' = [a \in Actions |->
                     IF status[a] = "proposed" THEN "lost" ELSE status[a]]
    /\ stampsHeld' = {}
    /\ UNCHANGED <<journal, effects, fpInFlight, stampsInFlight, witnessList,
                   witnessCrashes>>

\* The wrong gate's steps: those of Gate.tla, without GiveUp, and with the
\* crash above in place of GateCrash.
WrongNext ==
    \/ \E a \in Actions :
          \/ Propose(a)
          \/ WriteInJournal(a)
          \/ SendFingerprint(a)
          \/ Run(a)
    \/ \E f \in Fingerprints :
          \/ WitnessStamps(f)
          \/ StampArrives(f)
          \/ LoseFingerprint(f)
          \/ LoseStamp(f)
    \/ GateCrashNoRefusal
    \/ WitnessCrash
    \/ Finished

\* The same fairness as GateLive, on the gate's steps this gate still has.
WrongGateSteps(a) ==
    \/ WriteInJournal(a)
    \/ SendFingerprint(a)
    \/ Run(a)

WrongLiveSpec ==
    /\ Init
    /\ [][WrongNext]_vars
    /\ \A a \in Actions : WF_vars(WrongGateSteps(a))

=============================================================================
