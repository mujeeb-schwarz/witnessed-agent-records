--------------------------- MODULE GateTwoWitnesses ---------------------------
\* The spike's blueprint with a backup witness, asked only while the gate
\* waits on the main one. It is a separate module, so Gate.tla, the public
\* version, stays as it is. Its steps follow Gate.tla's; what changes is
\* the second witness, the send to the backup and the catch-up. TLC checks
\* it with GateTwoWitnesses.cfg.
\*
\* The design, in plain words:
\*   - Two witnesses, the main one and a backup. Each keeps its own list and
\*     can crash once and then restart. Messages to and from each can be
\*     lost.
\*   - The gate sends the fingerprint to the main witness. While it waits,
\*     it may also send it to the backup, at any moment, since there is no
\*     clock. A stamp from either witness counts.
\*   - The gate refuses an action only when it gives up while holding no
\*     stamp. After its own crash it refuses, as in Gate.tla, every action it
\*     journaled and never decided.
\*   - Catch-up: after the main witness restarts, the gate may send it the
\*     fingerprints the backup stamped, and the main witness adds them.
\*
\* The sizes TLC checks: two actions, each proposed once; at most one crash
\* of the gate and one of each witness; any message may be lost, late or
\* doubled. Gate.tla checks three actions. Here the backup's messages, list
\* and stamps multiply the states, and by my estimate three actions would
\* take TLC far longer than two.
\*
\* What the spec takes as given: everything Gate.tla's header lists, for
\* each witness. A witness that is down stamps nothing; it saves its list
\* before it stamps, so a crash loses nothing it has stamped. The gate keeps
\* a record of which witnesses it has sent each fingerprint to, which the
\* checks read.

EXTENDS Naturals, Sequences

\* The agent proposes actions; the settings file says how many.
CONSTANT Actions

Witnesses == {"main", "backup"}

VARIABLES
    status,          \* where each action stands, as the gate sees it
    journal,         \* the journal: our own record, written before anything runs
    effects,         \* the actions whose tool has started to run
    fpInFlight,      \* for each witness, fingerprints on their way to it
    stampsInFlight,  \* for each witness, its stamps on their way to the gate
    stampsHeld,      \* for each witness, the stamps from it that the gate holds
    witnessList,     \* for each witness, its saved list of fingerprints
    witnessUp,       \* for each witness, whether it is running
    witnessCrashes,  \* for each witness, how many times it has crashed: at most once
    gateCrashes,     \* how many times the gate has crashed: at most once
    asked,           \* for each witness, the fingerprints the gate has sent it
    caughtUp         \* the fingerprints the gate has sent the main witness in catch-up

messageVars == <<fpInFlight, stampsInFlight>>
witnessVars == <<witnessList, witnessUp, witnessCrashes>>
recordVars == <<asked, caughtUp>>
vars == <<status, journal, effects, messageVars, stampsHeld, witnessVars,
          gateCrashes, recordVars>>

\* Where an action can stand, as in Gate.tla.
Statuses == {"idle", "proposed", "journaled", "waiting", "ran", "refused", "lost"}

\* Fingerprints and stamps are labels that only the right party can make.
Fp(a) == <<"fingerprint", a>>
Fingerprints == {Fp(a) : a \in Actions}
ActionOf(f) == f[2]
Entry(a, k) == [action |-> a, kind |-> k]
Range(s) == {s[i] : i \in DOMAIN s}

\* The gate holds a stamp for the action from at least one witness.
HoldsStamp(a) == \E w \in Witnesses : Fp(a) \in stampsHeld[w]

\* At least one witness holds the fingerprint in its list.
HeldBySomeWitness(f) == \E w \in Witnesses : f \in Range(witnessList[w])

-----------------------------------------------------------------------------
\* The type check: every part holds only the kind of value it should.
TypeOK ==
    /\ status \in [Actions -> Statuses]
    /\ journal \subseteq [action : Actions, kind : {"intent", "approved", "refused"}]
    /\ effects \subseteq Actions
    /\ fpInFlight \in [Witnesses -> SUBSET Fingerprints]
    /\ stampsInFlight \in [Witnesses -> SUBSET Fingerprints]
    /\ stampsHeld \in [Witnesses -> SUBSET Fingerprints]
    /\ witnessList \in [Witnesses -> Seq(Fingerprints)]
    /\ witnessUp \in [Witnesses -> BOOLEAN]
    /\ witnessCrashes \in [Witnesses -> 0..1]
    /\ gateCrashes \in 0..1
    /\ asked \in [Witnesses -> SUBSET Fingerprints]
    /\ caughtUp \subseteq Fingerprints

\* At the start nothing has been proposed, written, sent or run, and both
\* witnesses are running.
Init ==
    /\ status = [a \in Actions |-> "idle"]
    /\ journal = {}
    /\ effects = {}
    /\ fpInFlight = [w \in Witnesses |-> {}]
    /\ stampsInFlight = [w \in Witnesses |-> {}]
    /\ stampsHeld = [w \in Witnesses |-> {}]
    /\ witnessList = [w \in Witnesses |-> <<>>]
    /\ witnessUp = [w \in Witnesses |-> TRUE]
    /\ witnessCrashes = [w \in Witnesses |-> 0]
    /\ gateCrashes = 0
    /\ asked = [w \in Witnesses |-> {}]
    /\ caughtUp = {}

-----------------------------------------------------------------------------
\* The steps. Each happens all at once; other steps can come between them.

\* The agent proposes an action, once.
Propose(a) ==
    /\ status[a] = "idle"
    /\ status' = [status EXCEPT ![a] = "proposed"]
    /\ UNCHANGED <<journal, effects, messageVars, stampsHeld, witnessVars,
                   gateCrashes, recordVars>>

\* The gate writes each proposed action in the journal.
WriteInJournal(a) ==
    /\ status[a] = "proposed"
    /\ journal' = journal \cup {Entry(a, "intent")}
    /\ status' = [status EXCEPT ![a] = "journaled"]
    /\ UNCHANGED <<effects, messageVars, stampsHeld, witnessVars,
                   gateCrashes, recordVars>>

\* The gate sends the fingerprint to the main witness, and waits. It sends
\* only for an action it has already written in the journal.
SendToMain(a) ==
    /\ status[a] = "journaled"
    /\ Entry(a, "intent") \in journal
    /\ fpInFlight' = [fpInFlight EXCEPT !["main"] = @ \cup {Fp(a)}]
    /\ asked' = [asked EXCEPT !["main"] = @ \cup {Fp(a)}]
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampsHeld, witnessVars,
                   gateCrashes, caughtUp>>

\* While it waits, the gate may also send the fingerprint to the backup, at
\* any moment, since there is no clock. It sends it there once.
SendToBackup(a) ==
    /\ status[a] = "waiting"
    /\ Fp(a) \notin asked["backup"]
    /\ fpInFlight' = [fpInFlight EXCEPT !["backup"] = @ \cup {Fp(a)}]
    /\ asked' = [asked EXCEPT !["backup"] = @ \cup {Fp(a)}]
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampsHeld,
                   witnessVars, gateCrashes, caughtUp>>

\* A running witness adds a fingerprint to its list, saves the list, and
\* sends back a stamp naming that fingerprint, all in one step. A
\* fingerprint it already holds counts as logged, so a second copy changes
\* nothing, and this step is not taken for it.
WitnessStamps(w, f) ==
    /\ witnessUp[w]
    /\ f \in fpInFlight[w]
    /\ f \notin Range(witnessList[w])
    /\ witnessList' = [witnessList EXCEPT ![w] = Append(@, f)]
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsHeld,
                   witnessUp, witnessCrashes, gateCrashes, recordVars>>

\* A stamp reaches the gate. The gate takes it only from a witness it sent
\* that fingerprint to, and only while it still waits for that action; a
\* stamp that arrives later changes nothing, so this step is not taken then.
StampArrives(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ f \in asked[w]
    /\ status[ActionOf(f)] = "waiting"
    /\ f \notin stampsHeld[w]
    /\ stampsHeld' = [stampsHeld EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, messageVars, witnessVars,
                   gateCrashes, recordVars>>

\* The gate lets an action run only when it holds a stamp for it, from
\* either witness. The tool starting to run is the action's effect.
Run(a) ==
    /\ status[a] = "waiting"
    /\ HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<messageVars, stampsHeld, witnessVars, gateCrashes,
                   recordVars>>

\* The gate refuses an action only when it gives up while holding no stamp,
\* and writes the refusal in the journal.
GiveUp(a) ==
    /\ status[a] = "waiting"
    /\ ~HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "refused"]
    /\ journal' = journal \cup {Entry(a, "refused")}
    /\ UNCHANGED <<effects, messageVars, stampsHeld, witnessVars, gateCrashes,
                   recordVars>>

\* Messages to and from each witness can be lost.
LoseFingerprint(w, f) ==
    /\ f \in fpInFlight[w]
    /\ fpInFlight' = [fpInFlight EXCEPT ![w] = @ \ {f}]
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampsHeld,
                   witnessVars, gateCrashes, recordVars>>

LoseStamp(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \ {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampsHeld,
                   witnessVars, gateCrashes, recordVars>>

\* The gate's crash, as in Gate.tla: it loses what it held only in memory,
\* and the restarted gate refuses every action it journaled and never
\* decided, and writes the refusal in the journal.
Undecided == {a \in Actions : status[a] \in {"journaled", "waiting"}}

GateCrash ==
    /\ gateCrashes = 0
    /\ gateCrashes' = 1
    /\ status' = [a \in Actions |->
                     CASE status[a] = "proposed"                 -> "lost"
                       [] status[a] \in {"journaled", "waiting"} -> "refused"
                       [] OTHER                                  -> status[a]]
    /\ journal' = journal \cup {Entry(a, "refused") : a \in Undecided}
    /\ stampsHeld' = [w \in Witnesses |-> {}]
    /\ UNCHANGED <<effects, messageVars, witnessVars, recordVars>>

\* A witness can crash once. While it is down it stamps nothing. Its list
\* survives, because it saves the list before it stamps.
WitnessCrash(w) ==
    /\ witnessUp[w]
    /\ witnessCrashes[w] = 0
    /\ witnessUp' = [witnessUp EXCEPT ![w] = FALSE]
    /\ witnessCrashes' = [witnessCrashes EXCEPT ![w] = 1]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampsHeld,
                   witnessList, gateCrashes, recordVars>>

\* ... and then restarts.
WitnessRestart(w) ==
    /\ ~witnessUp[w]
    /\ witnessUp' = [witnessUp EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampsHeld,
                   witnessList, witnessCrashes, gateCrashes, recordVars>>

\* Catch-up: after the main witness restarts, the gate may send it, once
\* each, the fingerprints the backup stamped. The main witness adds them
\* with its usual step.
CatchUp(f) ==
    /\ witnessUp["main"]
    /\ witnessCrashes["main"] = 1
    /\ f \in stampsHeld["backup"]
    /\ f \notin caughtUp
    /\ fpInFlight' = [fpInFlight EXCEPT !["main"] = @ \cup {f}]
    /\ asked' = [asked EXCEPT !["main"] = @ \cup {f}]
    /\ caughtUp' = caughtUp \cup {f}
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampsHeld,
                   witnessVars, gateCrashes>>

\* A finished system stands still, as in Gate.tla.
Finished ==
    /\ \A a \in Actions : status[a] \in {"ran", "refused", "lost"}
    /\ UNCHANGED vars

\* Each step of the system is one of the steps above.
Next ==
    \/ \E a \in Actions :
          \/ Propose(a)
          \/ WriteInJournal(a)
          \/ SendToMain(a)
          \/ SendToBackup(a)
          \/ Run(a)
          \/ GiveUp(a)
    \/ \E w \in Witnesses, f \in Fingerprints :
          \/ WitnessStamps(w, f)
          \/ StampArrives(w, f)
          \/ LoseFingerprint(w, f)
          \/ LoseStamp(w, f)
    \/ \E w \in Witnesses :
          \/ WitnessCrash(w)
          \/ WitnessRestart(w)
    \/ \E f \in Fingerprints : CatchUp(f)
    \/ GateCrash
    \/ Finished

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* The checks TLC runs.

\* Rule 1: no call starts before at least one witness holds its fingerprint.
\* As a rule about states: every action whose tool has started has its
\* fingerprint in some witness's list.
Rule1 == \A a \in effects : HeldBySomeWitness(Fp(a))

\* Rule 1 as a rule about steps: in any step where an action takes effect,
\* some witness already held its fingerprint before the step.
Rule1Step ==
    [][\A a \in Actions :
          (a \notin effects /\ a \in effects') => HeldBySomeWitness(Fp(a))
      ]_vars

\* Rule 2, for each witness: its list only grows. Nothing in it is ever
\* removed or rewritten.
Rule2 ==
    [][\A w \in Witnesses :
          /\ Len(witnessList'[w]) >= Len(witnessList[w])
          /\ SubSeq(witnessList'[w], 1, Len(witnessList[w])) = witnessList[w]
      ]_witnessList

\* Check 3, for each witness: every fingerprint in its list belongs to an
\* action written in the journal.
Check3 ==
    \A w \in Witnesses :
        \A i \in DOMAIN witnessList[w] :
            Entry(ActionOf(witnessList[w][i]), "intent") \in journal

\* A stamp from either witness is held just before the tool starts.
RunNeedsHeldStamp ==
    [][\A a \in Actions :
          (a \notin effects /\ a \in effects') => HoldsStamp(a)
      ]_vars

\* No action with a refusal in the journal has run.
RefusedNeverRuns == \A a \in effects : Entry(a, "refused") \notin journal

\* A fingerprint newly on its way to either witness had its action's entry
\* in the journal before.
JournalBeforeSend ==
    [][\A w \in Witnesses :
          \A a \in Actions :
              (Fp(a) \notin fpInFlight[w] /\ Fp(a) \in fpInFlight'[w])
                  => Entry(a, "intent") \in journal
      ]_vars

\* In the step where the gate crashes and restarts, every action that was
\* journaled or waiting gets a refusal in the journal.
CrashRefusesUndecided ==
    [][(gateCrashes = 0 /\ gateCrashes' = 1) =>
          \A a \in Actions :
              status[a] \in {"journaled", "waiting"} => Entry(a, "refused") \in journal'
      ]_vars

\* Added for this model, for "a stamp from either counts": the gate holds a
\* stamp from a witness only for a fingerprint it sent that witness.
StampsOnlyFromAsked == \A w \in Witnesses : stampsHeld[w] \subseteq asked[w]

=============================================================================
