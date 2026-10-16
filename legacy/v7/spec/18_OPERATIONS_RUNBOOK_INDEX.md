# BreachAtlas — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

Before public v1 provide tested runbooks for: deploy; rollback/forward repair; database migration; backup/restore; derived-store rebuild; queue poison/dead-letter; credential/certificate rotation; compromised release/dependency response; service/worker saturation; external provider outage; security incident; data deletion/legal hold where relevant; emergency disable/feature kill switch.

Each runbook specifies trigger, prerequisites, commands, safety checks, expected metrics/logs, rollback/abort point, verification and escalation owner.
