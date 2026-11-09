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

---

## Local Skills Routing (.agents/skills/)

This repository bundles standard local skills to maintain consistent engineering quality across team members and autonomous agents. Follow **Progressive Disclosure**: do NOT load all skills at once; read only the specific `SKILL.md` required for your current task phase.

### Skill Activation by Task Phase

| Phase / Need | Primary Skill | Path | Activation Trigger |
|---|---|---|---|
| **Context & Session Setup** | `context-engineering` | `.agents/skills/context-engineering/SKILL.md` | Session start, task switching, or token optimization |
| **Contract & Spec Definition** | `spec-driven-development` | `.agents/skills/spec-driven-development/SKILL.md` | Freezing data shapes, fixtures, or interfaces (C01, C04) |
| **Feature Slicing** | `incremental-implementation` | `.agents/skills/incremental-implementation/SKILL.md` | Implementing multi-file changes or task work cards |
| **Quality Bar & Gates** | `constraint-driven-development` | `.agents/skills/constraint-driven-development/SKILL.md` | Verifying diffs against quality regressions or protected files |
| **Frontend UI/UX** | `frontend-ui-engineering` | `.agents/skills/frontend-ui-engineering/SKILL.md` | Modifying `apps/web/`, components, tokens, or accessibility |
| **Backend & Interface Design** | `api-and-interface-design` | `.agents/skills/api-and-interface-design/SKILL.md` | Developing Go engine modules, boundaries, or local APIs |
| **CI/CD & Workflows** | `ci-cd-and-automation` | `.agents/skills/ci-cd-and-automation/SKILL.md` | Modifying `.github/workflows/` or local test scripts |
| **New Features & Bug Fixes** | `test-driven-development` | `.agents/skills/test-driven-development/SKILL.md` | Writing any new logic; Red-Green-Refactor cycle |
| **Debugging & Root Cause** | `systematic-debugging` | `.agents/skills/systematic-debugging/SKILL.md` | Investigating failures; no symptom-fixes allowed |
| **Pre-Commit Verification** | `verification-before-completion` | `.agents/skills/verification-before-completion/SKILL.md` | Mandatory before declaring any task done or recording evidence |
| **Code Review & Quality** | `code-review-and-quality` | `.agents/skills/code-review-and-quality/SKILL.md` | 5-axis review before completing commits |
| **Refactoring & Anti-Bloat** | `code-simplification` | `.agents/skills/code-simplification/SKILL.md` | Reducing complexity while strictly preserving behavior |
| **Atomic Commits & Git** | `git-workflow-and-versioning` | `.agents/skills/git-workflow-and-versioning/SKILL.md` | Staging atomic commits for C01–C40 and release tags |
| **ADRs & Documentation** | `documentation-and-adrs` | `.agents/skills/documentation-and-adrs/SKILL.md` | Documenting architectural decisions and design blueprints |
| **Security & Threat Modeling** | `security-and-hardening` | `.agents/skills/security-and-hardening/SKILL.md` | Evidence handling, cryptographic sealing, and tamper guards |
| **Doc Grounding** | `source-driven-development` | `.agents/skills/source-driven-development/SKILL.md` | Verifying API usage against official upstream documentation |
| **Adversarial Plan Review** | `doubt-driven-development` | `.agents/skills/doubt-driven-development/SKILL.md` | Stress-testing assumptions before critical decisions |
| **AI Slop Prevention** | `no-ai-slop` | `.agents/skills/no-ai-slop/SKILL.md` | Editing documentation and messages; removing AI buzzwords |

### Core Engineering Principles
1. **Evidence Before Claims:** Always execute the verification command and check exit codes/output before claiming success (`verification-before-completion`).
2. **Grounding Over Memory:** Back every technical decision with official documentation or repo fixtures (`source-driven-development`).
3. **Simplicity First (YAGNI):** Refuse unnecessary abstractions and premature complexity (`code-simplification`).
4. **Clean Prose:** Keep documentation concise, human, and direct without AI filler words (`no-ai-slop`).
5. **Precedence in Conflicts:** Project constraints (`EXECUTION_CONTRACT.md`, `ADR-0003`) take absolute precedence over any skill suggestion.
