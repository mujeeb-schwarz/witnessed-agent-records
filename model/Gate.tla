-------------------------------- MODULE Gate --------------------------------
\* The spike's blueprint: the gate, the journal and one witness.
\* Each part below carries the words of the plain-language statement of
\* the design that it encodes, which the author approved on 22 Nov 2026.
\* TLC checks this file with Gate.cfg.
\*
\* What counts as an action: a tool call that Inspect runs itself, for
\* example "delete notes.txt", "run this command" or "open this web page".
\* Its effect is the tool starting to run. Calls that a model provider runs
\* on its own servers, and anything a scorer or solver does directly, are
\* outside this model, and the README says so.
\*
\* The sizes TLC checks: three actions, each proposed once; at most one
\* crash of the gate and one of the witness; any message may be lost, late
\* or doubled. The spec has no clock, so the gate may give up waiting at any
\* moment, which covers a witness that answers too late. An agent that asks
\* again after a refusal makes a new action, which these sizes leave out.
\*
\* What the spec takes as given:
\*   - Fingerprints and stamps can't be forged or guessed. The spec treats
\*     them as labels that only the right party can make.
\*   - Every tool call passes the gate: only the gate's steps start a tool.
\*   - One witness. A later design adds a second.
\*   - The witness's list here is its saved list, and the witness saves a
\*     fingerprint before it sends the stamp. A witness that stamps first,
\*     or whose save fails, is outside this spec.
\*   - A crash and the restart after it are one step, so nothing runs while
\*     the gate recovers. Recovery that is itself interrupted is not
\*     modelled.
\*   - The gate's approval entry in the journal and the tool's start are one
\*     step. A gap between recording the approval and starting the tool is
\*     not modelled.
\*   - Messages stay available after they arrive, which stands in for
\*     replays; a copy that would change nothing is never delivered. This
\*     does not test retry or duplicate-handling code.
\*   - A proposal lost in a crash before it was written in the journal
\*     leaves no record.
\*   - The journal is a set of entries: no order, no duplicates and no
\*     results. Its order and its chain are left to the code.
\*   - The three actions may overlap at every step. The approver takes one
\*     call at a time, so this allows more orders than the code has, which
\*     is the safe direction for rules like these. It says nothing about the
\*     code's thread safety.
\*   - It checks the design. Whether the Inspect code follows the design is
\*     a separate check of the code against the model.
\*   - The checks in this file say what must never happen. Whether every
\*     action is eventually decided is checked separately, under fairness,
\*     in GateLive.tla.

EXTENDS Naturals, Sequences

\* The agent proposes actions, three of them in the small version.
CONSTANT Actions

VARIABLES
    status,          \* where each action stands, as the gate sees it
    journal,         \* the journal: our own record, written before anything runs
    effects,         \* the actions whose tool has started to run
    fpInFlight,      \* fingerprints on their way from the gate to the witness
    stampsInFlight,  \* stamps on their way back, each naming one fingerprint
    stampsHeld,      \* the stamps the gate holds, in its memory
    witnessList,     \* the witness's list of fingerprints, which it saves
    gateCrashes,     \* how many times the gate has crashed: at most once
    witnessCrashes   \* how many times the witness has crashed: at most once

vars == <<status, journal, effects, fpInFlight, stampsInFlight, stampsHeld,
          witnessList, gateCrashes, witnessCrashes>>

\* Where an action can stand:
\*   "idle"       not yet proposed
\*   "proposed"   the agent has proposed it; the gate holds it in memory
\*   "journaled"  written in the journal; its fingerprint not yet sent
\*   "waiting"    its fingerprint sent; the gate waits for the stamp
\*   "ran"        the gate let it run: its effect has happened
\*   "refused"    the gate refused it and wrote the refusal in the journal
\*   "lost"       the gate crashed before writing it down, so it never runs
Statuses == {"idle", "proposed", "journaled", "waiting", "ran", "refused", "lost"}

\* Fingerprints and stamps can't be forged or guessed: the spec treats them
\* as labels that only the right party can make. An action's fingerprint is
\* a label naming the action. A stamp is a label naming one fingerprint, and
\* only the witness puts stamps on their way.
Fp(a) == <<"fingerprint", a>>
Fingerprints == {Fp(a) : a \in Actions}
ActionOf(f) == f[2]

\* A journal entry: which action, and what was written about it.
Entry(a, k) == [action |-> a, kind |-> k]

\* The set of things a list holds.
Range(s) == {s[i] : i \in DOMAIN s}

-----------------------------------------------------------------------------
\* The type check: every part holds only the kind of value it should.
TypeOK ==
    /\ status \in [Actions -> Statuses]
    /\ journal \subseteq [action : Actions, kind : {"intent", "approved", "refused"}]
    /\ effects \subseteq Actions
    /\ fpInFlight \subseteq Fingerprints
    /\ stampsInFlight \subseteq Fingerprints
    /\ stampsHeld \subseteq Fingerprints
    /\ witnessList \in Seq(Fingerprints)
    /\ gateCrashes \in 0..1
    /\ witnessCrashes \in 0..1

\* At the start nothing has been proposed, written, sent or run.
Init ==
    /\ status = [a \in Actions |-> "idle"]
    /\ journal = {}
    /\ effects = {}
    /\ fpInFlight = {}
    /\ stampsInFlight = {}
    /\ stampsHeld = {}
    /\ witnessList = <<>>
    /\ gateCrashes = 0
    /\ witnessCrashes = 0

-----------------------------------------------------------------------------
\* The steps. Each happens all at once; other steps can come between them.

\* The agent proposes actions, three of them in the small version. Each is
\* proposed once.
Propose(a) ==
    /\ status[a] = "idle"
    /\ status' = [status EXCEPT ![a] = "proposed"]
    /\ UNCHANGED <<journal, effects, fpInFlight, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

\* The gate writes each proposed action in the journal.
WriteInJournal(a) ==
    /\ status[a] = "proposed"
    /\ journal' = journal \cup {Entry(a, "intent")}
    /\ status' = [status EXCEPT ![a] = "journaled"]
    /\ UNCHANGED <<effects, fpInFlight, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

\* ... sends its fingerprint to the witness, and waits. The gate sends a
\* fingerprint only for an action it has already written in the journal,
\* and it never sends the same one twice.
SendFingerprint(a) ==
    /\ status[a] = "journaled"
    /\ Entry(a, "intent") \in journal
    /\ fpInFlight' = fpInFlight \cup {Fp(a)}
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

\* The witness adds each fingerprint to its list, saves the list, and sends
\* back a stamp (a receipt) naming that fingerprint. The three happen as one
\* step: a crash between them looks, from outside, like the fingerprint or
\* the stamp being lost, which the messages below already allow. A
\* fingerprint it already holds counts as logged, so a second copy changes
\* nothing, and this step is not taken for it.
WitnessStamps(f) ==
    /\ f \in fpInFlight
    /\ f \notin Range(witnessList)
    /\ witnessList' = Append(witnessList, f)
    /\ stampsInFlight' = stampsInFlight \cup {f}
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsHeld,
                   gateCrashes, witnessCrashes>>

\* A stamp reaches the gate. The gate takes it only while it still waits for
\* that action: a stamp that arrives later changes nothing, so this step is
\* not taken then. A message stays on its way after it arrives, so it can
\* arrive twice, and a second copy changes nothing either.
StampArrives(f) ==
    /\ f \in stampsInFlight
    /\ status[ActionOf(f)] = "waiting"
    /\ f \notin stampsHeld
    /\ stampsHeld' = stampsHeld \cup {f}
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsInFlight,
                   witnessList, gateCrashes, witnessCrashes>>

\* The gate lets an action run only when it holds a matching stamp. The tool
\* starting to run is the action's effect. The gate writes its decision in
\* the journal.
Run(a) ==
    /\ status[a] = "waiting"
    /\ Fp(a) \in stampsHeld
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<fpInFlight, stampsInFlight, stampsHeld, witnessList,
                   gateCrashes, witnessCrashes>>

\* If it gives up waiting, it refuses the action and writes the refusal in
\* the journal. The spec has no clock, so the gate may give up at any moment
\* while it waits.
GiveUp(a) ==
    /\ status[a] = "waiting"
    /\ status' = [status EXCEPT ![a] = "refused"]
    /\ journal' = journal \cup {Entry(a, "refused")}
    /\ UNCHANGED <<effects, fpInFlight, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

\* The messages between the gate and the witness can be lost. (They can
\* also arrive late, after the gate has given up, or arrive twice: see the
\* two steps above.)
LoseFingerprint(f) ==
    /\ f \in fpInFlight
    /\ fpInFlight' = fpInFlight \ {f}
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

LoseStamp(f) ==
    /\ f \in stampsInFlight
    /\ stampsInFlight' = stampsInFlight \ {f}
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsHeld,
                   witnessList, gateCrashes, witnessCrashes>>

\* Crashes: the gate can crash once, losing whatever it held only in memory,
\* and then restart. It loses the actions it held but had not written down,
\* which never run, and every stamp it held. The restarted gate refuses any
\* action it journaled and never decided, and writes the refusal in the
\* journal: it can't tell whether the witness ever got the fingerprint, so
\* nothing runs without a clear stamp. The crash and the restart are one
\* step here. While the gate is down nothing reaches it, which the losses
\* above already allow.
Undecided == {a \in Actions : status[a] \in {"journaled", "waiting"}}

GateCrash ==
    /\ gateCrashes = 0
    /\ gateCrashes' = 1
    /\ status' = [a \in Actions |->
                     CASE status[a] = "proposed"                 -> "lost"
                       [] status[a] \in {"journaled", "waiting"} -> "refused"
                       [] OTHER                                  -> status[a]]
    /\ journal' = journal \cup {Entry(a, "refused") : a \in Undecided}
    /\ stampsHeld' = {}
    /\ UNCHANGED <<effects, fpInFlight, stampsInFlight, witnessList,
                   witnessCrashes>>

\* The witness can crash once, losing whatever it held only in memory, and
\* then restart. Its list survives, because it saves the list before it
\* sends a stamp, and it holds nothing else.
WitnessCrash ==
    /\ witnessCrashes = 0
    /\ witnessCrashes' = 1
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsInFlight,
                   stampsHeld, witnessList, gateCrashes>>

\* A finished system stands still. This step lets TLC tell a finished run
\* from a stuck one: with the deadlock check on, a state where no step is
\* possible before every action is decided shows as a deadlock. A gate that
\* keeps waiting is never in such a state, since it can always give up, so
\* the deadlock check does not show a gate that waits forever. GateLive.tla
\* checks that.
Finished ==
    /\ \A a \in Actions : status[a] \in {"ran", "refused", "lost"}
    /\ UNCHANGED vars

\* Each step of the system is one of the steps above.
Next ==
    \/ \E a \in Actions :
          \/ Propose(a)
          \/ WriteInJournal(a)
          \/ SendFingerprint(a)
          \/ Run(a)
          \/ GiveUp(a)
    \/ \E f \in Fingerprints :
          \/ WitnessStamps(f)
          \/ StampArrives(f)
          \/ LoseFingerprint(f)
          \/ LoseStamp(f)
    \/ GateCrash
    \/ WitnessCrash
    \/ Finished

\* The system starts as Init says, and every step is one of the above.
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* The rules TLC checks.

\* Rule 1: no action takes effect before the witness
\* holds its fingerprint. In the till picture: no sale goes through before
\* head office has stamped it.
\* As a rule about states, checked in every state: every action whose tool
\* has started to run has its fingerprint in the witness's list.
Rule1 == \A a \in effects : Fp(a) \in Range(witnessList)

\* Rule 1 again, as a rule about steps: in any step where an action takes
\* effect, its fingerprint was already in the witness's list before the step.
Rule1Step ==
    [][\A a \in Actions :
          (a \notin effects /\ a \in effects') => Fp(a) \in Range(witnessList)
      ]_vars

\* Rule 2: the witness's list only grows. Nothing in it
\* is ever removed or rewritten: in each step that changes the list, the new
\* list is at least as long and begins with the whole old list. The length
\* is checked first, so the second part is read only when the new list is
\* long enough.
Rule2 ==
    [][ /\ Len(witnessList') >= Len(witnessList)
        /\ SubSeq(witnessList', 1, Len(witnessList)) = witnessList
      ]_witnessList

\* The third check, added to the first two rules: everything the witness
\* has stamped is in our journal. Every
\* fingerprint in the witness's list belongs to an action written in the
\* journal.
Check3 ==
    \A i \in DOMAIN witnessList :
        Entry(ActionOf(witnessList[i]), "intent") \in journal

-----------------------------------------------------------------------------
\* Checks of sentences already in the design statement, added on 22 Nov
\* 2026 after an independent review. Each checks a sentence the statement
\* already has, so the statement's meaning does not change.

\* "The gate lets an action run only when it holds a matching stamp": in any
\* step where an action takes effect, the gate held its stamp in the state
\* before.
RunNeedsHeldStamp ==
    [][\A a \in Actions :
          (a \notin effects /\ a \in effects') => Fp(a) \in stampsHeld
      ]_vars

\* "If it gives up waiting, it refuses the action and writes the refusal in
\* the journal; a stamp that arrives later changes nothing": no action with a
\* refusal in the journal has run.
RefusedNeverRuns == \A a \in effects : Entry(a, "refused") \notin journal

\* After a crash, for an action the gate wrote down but never decided: "the
\* gate refuses it and writes the refusal in the journal". In the step where
\* the gate crashes and restarts, every action that was journaled or
\* waiting has a refusal in the journal afterwards.
CrashRefusesUndecided ==
    [][(gateCrashes = 0 /\ gateCrashes' = 1) =>
          \A a \in Actions :
              status[a] \in {"journaled", "waiting"} => Entry(a, "refused") \in journal'
      ]_vars

\* "The gate writes each proposed action in the journal, sends its
\* fingerprint to the witness, and waits": a fingerprint newly on its way
\* had its action's entry in the journal in the state before.
JournalBeforeSend ==
    [][\A a \in Actions :
          (Fp(a) \notin fpInFlight /\ Fp(a) \in fpInFlight') => Entry(a, "intent") \in journal
      ]_vars

=============================================================================
