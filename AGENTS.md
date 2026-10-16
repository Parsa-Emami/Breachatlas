# BreachAtlas: agent entry point

Read START_HERE.md, docs/agents/EXECUTION_CONTRACT.md, docs/architecture/ADR-0003-open-source-local-first.md, plans/project-state.json, plans/progress.json and plans/release-gates.json. Actual code/tests and source-bound evidence determine capability. legacy/v7 and *_V7.md are historical; do not run their bootstrap or revive compulsory services.

1. Inspect Git status, current source/manifests/locks/tests/CI and preserve other work.
2. Run npm run validate:plan and npm run plan -- next; read the returned plans/commits/Cxx.md in full. Complete only unmet dependency-ready criteria.
3. Follow its exact targets, implementation actions, resources, fixtures, negative cases and current/future command labels. Domain belongs in the selected engine, UI in apps/web and adapters at boundaries. No sibling repository imports.
4. Implement a real vertical slice and meaningful regressions. A static example, generic JSON preview, successful placeholder endpoint or mocked durability/auth cannot replace the product feature.
5. Run actual relevant checks, record exact source/tool/provider/fixture identities and command exits/output; update only genuinely verified progress and session handoff. W evidence never certifies a C task.
6. C30 needs full clean-host core workflow/restart/restore. C40 needs authorized published source/artifacts and installed full-workflow proof.

Permanent owner restrictions: do not modify database schemas, migrations, .env files or Dockerfiles. Use compatible ADR-0003 adapters; record a precise blocker if a protected change is unavoidable and continue independent authorized work. Preserve existing code including RiskWeft's optional API, and fix observed CI defects without disabling checks or adding broad analysis ignores.

All core features remain open source with no required paid/cloud account, public domain or sibling clone. Pin compatible upstream licenses/provenance. Never invent versions, tests, customer feedback, deployment or release claims. Routine reversible authorized work needs no repeated approval; a planned task title does not authorize destructive data actions or publication. Implementation guidance and UI are English, with Persian overview in docs/ROADMAP_FA.md. There is no requirement to spawn subagents.
