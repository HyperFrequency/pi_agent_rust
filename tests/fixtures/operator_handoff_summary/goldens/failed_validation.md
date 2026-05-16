# Operator Handoff Summary

- Status: blocked
- Project: pi_agent_rust
- Branch: main
- Head: abc1234
- Generated: [GENERATED_AT]

## What Changed
- No recently closed beads were provided.

## Safe Next Actions
- Fix or rerun the failed validation gates before claiming more implementation work.
- Use Beads comments as the coordination record until Agent Mail is healthy.
- Wait for RCH pressure to clear or use a smaller validation proof.

## Must Not Touch
- Do not claim validation is green until failed gates pass.

## Gates
- cargo_clippy_all_targets_rch: fail clippy.log

## Open Action-Plan Decisions
- None.

## Invariants
- git_worktree_clean: pass - Worktree is clean
- git_pushed: pass - HEAD matches upstream
- validation_gates: block - validation status=fail
- evidence_freshness: pass - evidence freshness=fresh
- agent_mail_usable: warn - agent mail health=red semantic=fail
- reservations_current: pass - No expired reservations
- rch_available: warn - rch status=degraded
- action_plan_decisions: pass - No open action-plan decisions
