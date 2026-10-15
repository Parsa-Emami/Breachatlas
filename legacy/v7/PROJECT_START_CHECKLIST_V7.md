# BreachAtlas — Project Start Checklist v7

Before the first source commit:

- [ ] Create `Parsa-Emami/breachatlas` only when this project is the active portfolio project.
- [ ] Confirm repository visibility and license intentionally.
- [ ] Run `make validate` locally.
- [ ] Read `ROADMAP_V7.md`; accept Phase 0 scope and explicitly defer later phases.
- [ ] Run bootstrap commands and commit generated dependency lockfiles.
- [ ] Replace placeholder local secrets only in ignored `.env` files.
- [ ] Make CI green before enabling it as a required branch-protection check.
- [ ] Add branch protection after CI is stable.
- [ ] Open the first milestone containing only Phase 0 issues.
- [ ] Do not create marketing claims/screenshots for capabilities not yet implemented.

## Phase switching rule
Phase 1 starts only after Phase 0 Definition of Done and global gates in `ACCEPTANCE_GATES_V7.md` pass on `main`. The same rule repeats for every later phase.
