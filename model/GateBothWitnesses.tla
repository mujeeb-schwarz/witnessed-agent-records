--------------------------- MODULE GateBothWitnesses ---------------------------
\* The spike's blueprint with two witnesses, each sent every fingerprint. It
\* is a separate module:
\* Gate.tla, the public version, stays as it is, and GateTwoWitnesses.tla
\* keeps the failover-only version for comparison. TLC checks its safety
\* rules with GateBothWitnesses.cfg, and its progress rule with
\* GateBothWitnessesLive.cfg (one call) and GateBothWitnessesLive2.cfg (two
\* calls).
\*
\* The gate records stamps that arrive after a call has started, and a
\* witness stamps again a fingerprint it already holds, so the gate can
\* collect the second stamp. Settled covers these receipts, and two rules
\* check them: BothReceiptsHeld and EveryStartedCallGetsBothReceipts.
\*
\* The design, in plain words:
\*   - Two witnesses, the main one and a backup. Each keeps its own list and
\*     can crash once and then restart. Messages to and from each can be
\*     lost.
\*   - The gate sends every fingerprint to both witnesses, and lets the call
\*     run on the first valid stamp from either.
\*   - The gate refuses a call only when it gives up while holding no stamp.
\*     After its own crash it refuses, as in Gate.tla, every call it
\*     journaled and never decided.
\*   - The gate records each stamp it receives in its journal as a receipt,
\*     also when the stamp arrives after the call has run. A stamp for a
\*     refused call changes nothing.
\*   - A running witness that receives a fingerprint already in its list
\*     sends its stamp again, as the code's witness does.
\*   - Catch-up runs both ways: whenever a witness is up, the gate may send
\*     it a fingerprint the other witness has stamped and this one has not,
\*     unless a copy is already on its way. The gate knows which stamps it
\*     has received from the receipts in its journal. Catch-up is not tied
\*     to a restart: otherwise a fingerprint lost on its way to a witness
\*     that never crashed would stay missing.
\*   - Once everything has settled, both lists hold the fingerprint of every
\*     started call, so a forger would need both witnesses' keys
\*     (BothListsHoldStarted). The journal then also holds both witnesses'
\*     stamps for it, which is what the code's checker asks for when it
\*     demands completeness (BothReceiptsHeld).
\*   - Under the assumptions below, every started call eventually has both
\*     witnesses' stamps in the journal (EveryStartedCallGetsBothReceipts).
\*
\* The progress rule's assumptions (the fairness in LiveSpec):
\*   - A witness that is down eventually restarts.
\*   - The gate eventually sends again a fingerprint that a witness still
\*     lacks a receipt for (catch-up).
\*   - Messages may still be lost, but a message sent again and again gets
\*     through in the end: a witness that keeps being offered a fingerprint
\*     eventually adds it or stamps it again, and a stamp that keeps arriving
\*     is eventually recorded. TLA+ calls the first two assumptions weak
\*     fairness and this one strong fairness.
\*   - Nothing is assumed about the agent or the gate's decisions: the rule
\*     is about calls that have started.
\*
\* The sizes TLC checks: two calls, each proposed once; at most one crash of
\* the gate and one of each witness; any message may be lost, late or
\* doubled. Gate.tla checks three calls. Here the second witness's
\* messages, list and stamps multiply the states, and by my estimate three
\* calls would take TLC far longer than two. The progress rule also runs
\* with one call, because TLC's check of a rule about "eventually" follows
\* whole runs and is much slower than its state-by-state checks (Specifying
\* Systems, section 14.1).
\*
\* Two switches, RestampOn and LateReceiptsOn, are TRUE in the design. Two
\* wrong versions turn one off from their settings files, so that what
\* counts as settled follows their own steps.
\*
\* What the spec takes as given: everything Gate.tla's header lists, for
\* each witness. A witness that is down stamps nothing; it saves its list
\* before it stamps, so a crash loses nothing it has stamped. The gate keeps
\* a record of which witnesses it has sent each fingerprint to, which the
\* checks read.

EXTENDS Naturals, Sequences

\* The agent proposes calls; the settings file says how many.
CONSTANT Actions

Witnesses == {"main", "backup"}
Other(w) == IF w = "main" THEN "backup" ELSE "main"

\* The witnesses catch-up sends to: both, in the design. (A wrong version's
\* settings file replaces this with the main witness only.)
CatchUpTo == Witnesses

\* Re-stamping and receipts after the run, both on in the design.
RestampOn == TRUE
LateReceiptsOn == TRUE

VARIABLES
    status,          \* where each call stands, as the gate sees it
    journal,         \* the journal: our own record, written before anything runs
    effects,         \* the calls whose tool has started to run
    fpInFlight,      \* for each witness, fingerprints on their way to it
    stampsInFlight,  \* for each witness, its stamps on their way to the gate
    stampsHeld,      \* for each witness, its stamps the gate holds in memory
    receipts,        \* for each witness, its stamps the gate has recorded in the journal
    witnessList,     \* for each witness, its saved list of fingerprints
    witnessUp,       \* for each witness, whether it is running
    witnessCrashes,  \* for each witness, how many times it has crashed: at most once
    gateCrashes,     \* how many times the gate has crashed: at most once
    asked            \* for each witness, the fingerprints the gate has sent it

messageVars == <<fpInFlight, stampsInFlight>>
stampVars == <<stampsHeld, receipts>>
witnessVars == <<witnessList, witnessUp, witnessCrashes>>
vars == <<status, journal, effects, messageVars, stampVars, witnessVars,
          gateCrashes, asked>>

\* Where a call can stand, as in Gate.tla.
Statuses == {"idle", "proposed", "journaled", "waiting", "ran", "refused", "lost"}

\* Fingerprints and stamps are labels that only the right party can make.
Fp(a) == <<"fingerprint", a>>
Fingerprints == {Fp(a) : a \in Actions}
ActionOf(f) == f[2]
Entry(a, k) == [action |-> a, kind |-> k]
Range(s) == {s[i] : i \in DOMAIN s}

\* The gate holds a stamp for the call from at least one witness.
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
    /\ receipts \in [Witnesses -> SUBSET Fingerprints]
    /\ witnessList \in [Witnesses -> Seq(Fingerprints)]
    /\ witnessUp \in [Witnesses -> BOOLEAN]
    /\ witnessCrashes \in [Witnesses -> 0..1]
    /\ gateCrashes \in 0..1
    /\ asked \in [Witnesses -> SUBSET Fingerprints]

\* At the start nothing has been proposed, written, sent or run, and both
\* witnesses are running.
Init ==
    /\ status = [a \in Actions |-> "idle"]
    /\ journal = {}
    /\ effects = {}
    /\ fpInFlight = [w \in Witnesses |-> {}]
    /\ stampsInFlight = [w \in Witnesses |-> {}]
    /\ stampsHeld = [w \in Witnesses |-> {}]
    /\ receipts = [w \in Witnesses |-> {}]
    /\ witnessList = [w \in Witnesses |-> <<>>]
    /\ witnessUp = [w \in Witnesses |-> TRUE]
    /\ witnessCrashes = [w \in Witnesses |-> 0]
    /\ gateCrashes = 0
    /\ asked = [w \in Witnesses |-> {}]

-----------------------------------------------------------------------------
\* When the witness and receipt steps can be taken. Each is taken only when
\* it changes something. Settled, below, uses the same conditions.

\* A running witness has a fingerprint on its way that it has not yet added.
DeliveryPending(w, f) ==
    /\ witnessUp[w]
    /\ f \in fpInFlight[w]
    /\ f \notin Range(witnessList[w])

\* A running witness has a fingerprint on its way that it already holds, and
\* its stamp for it is not on its way.
RestampPending(w, f) ==
    /\ RestampOn
    /\ witnessUp[w]
    /\ f \in fpInFlight[w]
    /\ f \in Range(witnessList[w])
    /\ f \notin stampsInFlight[w]

\* A stamp for a call that has run is on its way, and the gate has not yet
\* recorded it.
ReceiptPending(w, f) ==
    /\ LateReceiptsOn
    /\ f \in stampsInFlight[w]
    /\ f \in asked[w]
    /\ status[ActionOf(f)] = "ran"
    /\ f \notin receipts[w]

\* While witness w is up, the gate has recorded the other witness's stamp
\* for a fingerprint, has no stamp from w for it, and no copy is on its way.
CatchUpPending(w, f) ==
    /\ w \in CatchUpTo
    /\ witnessUp[w]
    /\ f \in receipts[Other(w)]
    /\ f \notin receipts[w]
    /\ f \notin fpInFlight[w]

-----------------------------------------------------------------------------
\* The steps. Each happens all at once; other steps can come between them.

\* The agent proposes a call, once.
Propose(a) ==
    /\ status[a] = "idle"
    /\ status' = [status EXCEPT ![a] = "proposed"]
    /\ UNCHANGED <<journal, effects, messageVars, stampVars, witnessVars,
                   gateCrashes, asked>>

\* The gate writes each proposed call in the journal.
WriteInJournal(a) ==
    /\ status[a] = "proposed"
    /\ journal' = journal \cup {Entry(a, "intent")}
    /\ status' = [status EXCEPT ![a] = "journaled"]
    /\ UNCHANGED <<effects, messageVars, stampVars, witnessVars,
                   gateCrashes, asked>>

\* The gate sends the fingerprint to both witnesses, and waits. It sends
\* only for a call it has already written in the journal.
SendFingerprint(a) ==
    /\ status[a] = "journaled"
    /\ Entry(a, "intent") \in journal
    /\ fpInFlight' = [w \in Witnesses |-> fpInFlight[w] \cup {Fp(a)}]
    /\ asked' = [w \in Witnesses |-> asked[w] \cup {Fp(a)}]
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampVars, witnessVars,
                   gateCrashes>>

\* A running witness adds a fingerprint to its list, saves the list, and
\* sends back a stamp naming that fingerprint, all in one step.
WitnessStamps(w, f) ==
    /\ DeliveryPending(w, f)
    /\ witnessList' = [witnessList EXCEPT ![w] = Append(@, f)]
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampVars,
                   witnessUp, witnessCrashes, gateCrashes, asked>>

\* Re-stamping: a running witness that receives a fingerprint already in its
\* list sends its stamp again, as the code's witness does.
WitnessRestamps(w, f) ==
    /\ RestampPending(w, f)
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampVars,
                   witnessVars, gateCrashes, asked>>

\* A stamp reaches the gate while it still waits for that call. The gate
\* takes it only from a witness it sent that fingerprint to. It holds the
\* stamp and records the receipt in its journal.
StampArrives(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ f \in asked[w]
    /\ status[ActionOf(f)] = "waiting"
    /\ f \notin stampsHeld[w]
    /\ stampsHeld' = [stampsHeld EXCEPT ![w] = @ \cup {f}]
    /\ receipts' = [receipts EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, messageVars, witnessVars,
                   gateCrashes, asked>>

\* Receipts after the run: a stamp that reaches the gate after the call has
\* run is still recorded in the journal. A stamp for a refused call still
\* changes nothing.
RecordLateReceipt(w, f) ==
    /\ ReceiptPending(w, f)
    /\ receipts' = [receipts EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampsHeld,
                   witnessVars, gateCrashes, asked>>

\* The gate lets a call run on the first stamp it holds, from either
\* witness. The tool starting to run is the call's effect.
Run(a) ==
    /\ status[a] = "waiting"
    /\ HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "ran"]
    /\ effects' = effects \cup {a}
    /\ journal' = journal \cup {Entry(a, "approved")}
    /\ UNCHANGED <<messageVars, stampVars, witnessVars, gateCrashes, asked>>

\* The gate refuses a call only when it gives up while holding no stamp, and
\* writes the refusal in the journal.
GiveUp(a) ==
    /\ status[a] = "waiting"
    /\ ~HoldsStamp(a)
    /\ status' = [status EXCEPT ![a] = "refused"]
    /\ journal' = journal \cup {Entry(a, "refused")}
    /\ UNCHANGED <<effects, messageVars, stampVars, witnessVars, gateCrashes,
                   asked>>

\* Messages to and from each witness can be lost.
LoseFingerprint(w, f) ==
    /\ f \in fpInFlight[w]
    /\ fpInFlight' = [fpInFlight EXCEPT ![w] = @ \ {f}]
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampVars,
                   witnessVars, gateCrashes, asked>>

LoseStamp(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ stampsInFlight' = [stampsInFlight EXCEPT ![w] = @ \ {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampVars,
                   witnessVars, gateCrashes, asked>>

\* The gate's crash, as in Gate.tla: it loses the stamps it held in memory,
\* and the restarted gate refuses every call it journaled and never decided,
\* and writes the refusal in the journal. The receipts it recorded survive.
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
    /\ UNCHANGED <<effects, messageVars, receipts, witnessVars, asked>>

\* A witness can crash once. While it is down it stamps nothing. Its list
\* survives, because it saves the list before it stamps.
WitnessCrash(w) ==
    /\ witnessUp[w]
    /\ witnessCrashes[w] = 0
    /\ witnessUp' = [witnessUp EXCEPT ![w] = FALSE]
    /\ witnessCrashes' = [witnessCrashes EXCEPT ![w] = 1]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampVars,
                   witnessList, gateCrashes, asked>>

\* ... and then restarts.
WitnessRestart(w) ==
    /\ ~witnessUp[w]
    /\ witnessUp' = [witnessUp EXCEPT ![w] = TRUE]
    /\ UNCHANGED <<status, journal, effects, messageVars, stampVars,
                   witnessList, witnessCrashes, gateCrashes, asked>>

\* Catch-up: while witness w is up, the gate may send it a fingerprint whose
\* stamp from the other witness it has recorded, and whose stamp from w it
\* has not, unless a copy is already on its way.
CatchUp(w, f) ==
    /\ CatchUpPending(w, f)
    /\ fpInFlight' = [fpInFlight EXCEPT ![w] = @ \cup {f}]
    /\ asked' = [asked EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, stampsInFlight, stampVars,
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
          \/ SendFingerprint(a)
          \/ Run(a)
          \/ GiveUp(a)
    \/ \E w \in Witnesses, f \in Fingerprints :
          \/ WitnessStamps(w, f)
          \/ WitnessRestamps(w, f)
          \/ StampArrives(w, f)
          \/ RecordLateReceipt(w, f)
          \/ LoseFingerprint(w, f)
          \/ LoseStamp(w, f)
          \/ CatchUp(w, f)
    \/ \E w \in Witnesses :
          \/ WitnessCrash(w)
          \/ WitnessRestart(w)
    \/ GateCrash
    \/ Finished

Spec == Init /\ [][Next]_vars

\* The spec with the progress rule's assumptions: a witness that is down
\* eventually restarts (weak fairness); the gate eventually sends again a
\* fingerprint a witness still lacks a receipt for (weak fairness); and a
\* message sent again and again gets through in the end (strong fairness on
\* the steps that receive it).
LiveSpec ==
    /\ Spec
    /\ \A w \in Witnesses : WF_vars(WitnessRestart(w))
    /\ \A w \in Witnesses, f \in Fingerprints :
          /\ WF_vars(CatchUp(w, f))
          /\ SF_vars(WitnessStamps(w, f))
          /\ SF_vars(WitnessRestamps(w, f))
          /\ SF_vars(RecordLateReceipt(w, f))

-----------------------------------------------------------------------------
\* The checks TLC runs.

\* Rule 1: no call starts before at least one witness holds its fingerprint.
\* As a rule about states: every call whose tool has started has its
\* fingerprint in some witness's list.
Rule1 == \A a \in effects : HeldBySomeWitness(Fp(a))

\* Rule 1 as a rule about steps: in any step where a call takes effect, some
\* witness already held its fingerprint before the step.
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

\* Check 3, for each witness: every fingerprint in its list belongs to a
\* call written in the journal.
Check3 ==
    \A w \in Witnesses :
        \A i \in DOMAIN witnessList[w] :
            Entry(ActionOf(witnessList[w][i]), "intent") \in journal

\* A stamp from either witness is held just before the tool starts.
RunNeedsHeldStamp ==
    [][\A a \in Actions :
          (a \notin effects /\ a \in effects') => HoldsStamp(a)
      ]_vars

\* No call with a refusal in the journal has run.
RefusedNeverRuns == \A a \in effects : Entry(a, "refused") \notin journal

\* A fingerprint newly on its way to either witness had its call's entry in
\* the journal before.
JournalBeforeSend ==
    [][\A w \in Witnesses :
          \A a \in Actions :
              (Fp(a) \notin fpInFlight[w] /\ Fp(a) \in fpInFlight'[w])
                  => Entry(a, "intent") \in journal
      ]_vars

\* In the step where the gate crashes and restarts, every call that was
\* journaled or waiting gets a refusal in the journal.
CrashRefusesUndecided ==
    [][(gateCrashes = 0 /\ gateCrashes' = 1) =>
          \A a \in Actions :
              status[a] \in {"journaled", "waiting"} => Entry(a, "refused") \in journal'
      ]_vars

\* The gate holds a stamp from a witness only for a fingerprint it sent that
\* witness ("a stamp from either counts", read as either witness the gate
\* asked).
StampsOnlyFromAsked == \A w \in Witnesses : stampsHeld[w] \subseteq asked[w]

\* Settled: every call is decided, both witnesses are up, and nothing is
\* left that would still add a fingerprint to a list, send a stamp again,
\* record a receipt or catch up.
Settled ==
    /\ \A a \in Actions : status[a] \in {"ran", "refused", "lost"}
    /\ \A w \in Witnesses : witnessUp[w]
    /\ \A w \in Witnesses, f \in Fingerprints :
          /\ ~CatchUpPending(w, f)
          /\ ~DeliveryPending(w, f)
          /\ ~RestampPending(w, f)
          /\ ~ReceiptPending(w, f)

\* Once settled, both lists hold the fingerprint of every started call.
BothListsHoldStarted ==
    Settled => \A a \in effects : \A w \in Witnesses : Fp(a) \in Range(witnessList[w])

\* Once settled, the journal holds both witnesses' stamps for every
\* started call, which is what the code's checker asks for when it demands
\* completeness.
BothReceiptsHeld ==
    Settled => \A a \in effects : \A w \in Witnesses : Fp(a) \in receipts[w]

\* The progress rule, checked under LiveSpec: every started call eventually
\* has both witnesses' stamps in the journal.
EveryStartedCallGetsBothReceipts ==
    \A a \in Actions : (a \in effects) ~> (\A w \in Witnesses : Fp(a) \in receipts[w])

=============================================================================
