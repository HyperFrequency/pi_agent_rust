# Operator Handoff Summary

- Status: blocked
- Project: pi_agent_rust
- Branch: main
- Head: abc1234
- Generated: [GENERATED_AT]

## What Changed
- No recently closed beads were provided.

## Safe Next Actions
- Renew stale or missing evidence before relying on release or drop-in claims.
- Resolve open action-plan decisions before starting the dependent operator lane.

## Must Not Touch
- Do not make strict release/drop-in claims from stale evidence.

## Gates
- No validation gates were provided.

## Open Action-Plan Decisions
- renew-dropin-verdict: renew_stale_evidence

## Invariants
- git_worktree_clean: pass - Worktree is clean
- git_pushed: pass - HEAD matches upstream
- validation_gates: pass - validation status=pass
- evidence_freshness: block - evidence freshness=stale
- agent_mail_usable: pass - agent mail health=green semantic=pass
- reservations_current: pass - No expired reservations
- rch_available: pass - rch status=ok
- action_plan_decisions: warn - 1 open action-plan decision(s)
