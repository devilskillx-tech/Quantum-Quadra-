------------------------- MODULE AtomicRevocation -------------------------
EXTENDS Naturals, TLC
\* Small *abstract* one-certificate model; no production storage semantics.
\* Model check with TLC separately. Mutation sensitivity is also tested using
\* the bounded Python abstraction in scripts/formal_mutation_runner.py.
VARIABLES requested, authorized, committed, outbox, anchored, checked,
          acknowledged, recovering, unsafeUse, effects
vars == <<requested, authorized, committed, outbox, anchored, checked,
          acknowledged, recovering, unsafeUse, effects>>
Init == /\ requested = FALSE /\ authorized = FALSE
        /\ committed = FALSE /\ outbox = FALSE /\ anchored = FALSE
        /\ checked = FALSE /\ acknowledged = FALSE
        /\ recovering = FALSE /\ unsafeUse = FALSE /\ effects = 0
RequestAuthorized == /\ ~requested
                     /\ requested' = TRUE /\ authorized' = TRUE
                     /\ UNCHANGED <<committed,outbox,anchored,checked,acknowledged,recovering,unsafeUse,effects>>
RequestDenied == /\ ~requested
                 /\ requested' = TRUE /\ authorized' = FALSE
                 /\ UNCHANGED <<committed,outbox,anchored,checked,acknowledged,recovering,unsafeUse,effects>>
Commit == /\ requested /\ authorized /\ ~committed /\ ~anchored
          /\ committed' = TRUE /\ outbox' = TRUE /\ effects' = 1
          /\ UNCHANGED <<requested,authorized,anchored,checked,acknowledged,recovering,unsafeUse>>
Publish == /\ committed /\ outbox /\ ~anchored /\ anchored' = TRUE
           /\ UNCHANGED <<requested,authorized,committed,outbox,checked,acknowledged,recovering,unsafeUse,effects>>
VerifyAnchor == /\ anchored /\ ~checked /\ checked' = TRUE
                /\ UNCHANGED <<requested,authorized,committed,outbox,anchored,acknowledged,recovering,unsafeUse,effects>>
Confirm == /\ committed /\ checked /\ ~acknowledged /\ acknowledged' = TRUE
           /\ UNCHANGED <<requested,authorized,committed,outbox,anchored,checked,recovering,unsafeUse,effects>>
Retry == /\ committed /\ requested /\ UNCHANGED vars
RestoreOld == /\ anchored /\ committed /\ ~recovering
              /\ committed' = FALSE /\ outbox' = FALSE
              /\ acknowledged' = FALSE /\ recovering' = TRUE
              /\ UNCHANGED <<requested,authorized,anchored,checked,unsafeUse,effects>>
Reconcile == /\ anchored /\ recovering
             /\ committed' = TRUE /\ outbox' = TRUE /\ recovering' = FALSE
             /\ UNCHANGED <<requested,authorized,anchored,checked,acknowledged,unsafeUse,effects>>
AttemptUse == /\ anchored /\ ~committed /\ ~recovering
              /\ unsafeUse' = TRUE
              /\ UNCHANGED <<requested,authorized,committed,outbox,anchored,checked,acknowledged,recovering,effects>>
Next == RequestAuthorized \/ RequestDenied \/ Commit \/ Publish
         \/ VerifyAnchor \/ Confirm \/ Retry \/ RestoreOld \/ Reconcile \/ AttemptUse
Spec == Init /\ [][Next]_vars
NoPrematureACK == acknowledged => (anchored /\ checked)
OutboxAtomicity == committed => outbox
NoResurrection == ~unsafeUse
IdempotentEffect == effects <= 1
TypeOK == /\ requested \in BOOLEAN /\ authorized \in BOOLEAN
          /\ committed \in BOOLEAN /\ outbox \in BOOLEAN
          /\ anchored \in BOOLEAN /\ checked \in BOOLEAN
          /\ acknowledged \in BOOLEAN /\ recovering \in BOOLEAN
          /\ unsafeUse \in BOOLEAN /\ effects \in Nat
=============================================================================
