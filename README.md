# BreachAtlas

[![Source](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Breachatlas/actions/workflows/web.yml?query=branch%3Amain)

[CI source integrity and dependency updates](docs/engineering/CI_SOURCE_INTEGRITY.md)


Open-source local-first web application under [Apache-2.0](LICENSE). **Current implementation: local Go runtime and evidence manifest validation.**

## Clone and run the current workspace

Prerequisites are Git, Node 24.19+ within Node 24 (npm included), and Go 1.24+.

```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

Open http://127.0.0.1:4173. The workspace offers a roadmap, local JSON preview and [evidence manifest validation](contracts/README.md) through the loopback engine. The current workspace runs with Git, Node and Go. [Clone guide](docs/engineering/CLONE_TO_RUN.md).

### Verify the local workspace

After setup, run:

```sh
npm run doctor
npm run check
```

The doctor reports the actual local engine and web build state. The check command
validates the current roadmap, builds the workspace and runs automated tests.
If port 4173 is already occupied, use `npm start -- --port 4301`.
The current JSON preview and manifest validator are **not** a completed incident
evidence or chain-of-custody platform; do not upload private incident records
or production secrets. See the [current implementation boundary](docs/engineering/CLONE_TO_RUN.md#runnable-today).


## Full product endpoint

Upload synthetic evidence -> seal -> add custody -> parse bounded timeline -> hold/delete negative test -> export -> verify on another host with external trust -> recover consistency.

[C30](plans/commits/C30.md) proves the first locally usable supported product from a clean clone, including restart/restore. [C40](plans/commits/C40.md) proves complete published OSS v1. These are future evidence gates, not current shell capability claims. [Runtime resources](ops/runtime-requirements.json).

## Implement the next commit

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C07
npm run check
```

Each [work card](plans/COMMIT_ROADMAP.md) specifies paths, actions, resources, fixtures, acceptance, negative tests, command availability and rollback. [AGENTS.md](AGENTS.md) and [execution contract](docs/agents/EXECUTION_CONTRACT.md) let an agent resume from this repository alone. [فارسی](docs/ROADMAP_FA.md).

[User guide](docs/release/USER_GUIDE.md) · [Open-source contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-party inventory](THIRD_PARTY_NOTICES.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). No DB schema, migration, .env or Dockerfile changes are authorized.
