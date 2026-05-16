# Operator Handoff Summary

- Status: watch
- Project: pi_agent_rust
- Branch: main
- Head: abc1234
- Generated: [GENERATED_AT]

## What Changed
- No recently closed beads were provided.

## Safe Next Actions
- Refresh or release expired reservations before treating ownership as current.

## Must Not Touch
- No additional protected paths beyond repo instructions and active Beads ownership.

## Gates
- No validation gates were provided.

## Open Action-Plan Decisions
- None.

## Invariants
- git_worktree_clean: pass - Worktree is clean
- git_pushed: pass - HEAD matches upstream
- validation_gates: pass - validation status=pass
- evidence_freshness: pass - evidence freshness=fresh
- agent_mail_usable: pass - agent mail health=green semantic=pass
- reservations_current: warn - 1 expired reservation(s)
- rch_available: pass - rch status=ok
- action_plan_decisions: pass - No open action-plan decisions
