# BreachAtlas OSS Scaffold

This directory is the canonical repository shape to copy when source implementation starts. Do not create a second competing layout.

`apps/control-plane` Laravel; `apps/web` React; specialized engines/agents are added under `apps/engines/<name>` or `apps/agents/<name>` only when listed in the final architecture. Shared contracts belong in `packages/contracts`; infrastructure code cannot contain domain logic.
