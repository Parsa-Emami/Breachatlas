# BreachAtlas

Open-source local-first web application under [Apache-2.0](LICENSE). **Current implementation: web foundation; complete domain workflow pending.**

## Clone and run the current workspace

Prerequisites: Git and Node 24.19+ within Node 24 (npm included).

```sh
git clone https://github.com/Parsa-Emami/Breachatlas.git
cd Breachatlas
npm run setup
npm start
```

Open http://127.0.0.1:4173. Current features are a roadmap browser and local bounded JSON structure preview. No Python, database, paid/cloud account, public domain or sibling clone is needed for this shell. It does not run the domain engine. [Clone guide](docs/engineering/CLONE_TO_RUN.md).

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

[Open-source contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-party inventory](THIRD_PARTY_NOTICES.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). No DB schema, migration, .env or Dockerfile changes are authorized.
