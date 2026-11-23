------------------------------ MODULE GateLive ------------------------------
\* One more rule for the spike's blueprint, added on 22 Nov 2026: the
\* gate cannot hang.
\* Every proposed action is eventually decided: it ran, was refused or was
\* lost. This file adds that rule, and the fairness it needs, to the spec in
\* Gate.tla. TLC checks it with GateLive.cfg.
\*
\* Why the model is smaller: two actions in place of three, with the same
\* crash bounds (at most one crash of the gate and one of the witness). A
\* rule about "eventually" makes TLC follow whole runs, including runs that
\* go on forever, which takes much longer than checking state by state. Two
\* actions keep that check quick. The rules about what must never happen
\* are checked at three actions, with Gate.cfg.
\*
\* What it assumes (TLA+ calls this weak fairness): if one of the gate's own
\* steps for an action stays possible, the gate takes one of them in the
\* end. Those steps are writing the action in the journal, sending its
\* fingerprint, letting it run and giving up. While the gate waits for a
\* stamp, giving up stays possible, so in the end it gives up, unless the
\* stamp arrives first and it lets the action run. Nothing like this is
\* assumed of the messages, the witness or the crashes: messages may still
\* be lost, the witness may never answer, and the gate may still give up at
\* any moment.
EXTENDS Gate

\* The gate's own steps for one action.
GateSteps(a) ==
    \/ WriteInJournal(a)
    \/ SendFingerprint(a)
    \/ Run(a)
    \/ GiveUp(a)

\* The spec in Gate.tla, with weak fairness on the gate's own steps for each
\* action.
LiveSpec == Spec /\ \A a \in Actions : WF_vars(GateSteps(a))

\* An action is decided once it ran, was refused or was lost.
Decided(a) == status[a] \in {"ran", "refused", "lost"}

\* The gate cannot hang: every proposed action is eventually decided.
EveryProposedDecided ==
    \A a \in Actions : (status[a] = "proposed") ~> Decided(a)

=============================================================================
