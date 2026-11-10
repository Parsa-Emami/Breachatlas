# BreachAtlas: Unified Engine Launch & Supervisor Architecture

Updated for task **C03**: unified local engine setup and launch.

## Architecture

BreachAtlas operates under a local-first single-host architecture (`ADR-0003`). The unified process supervisor `scripts/start-local.mjs` orchestrates both the Go engine and the web server without requiring multiple terminal windows:

$$\text{npm start} \longrightarrow \text{start-local.mjs (Supervisor)} \begin{cases} \longrightarrow \text{Spawn Go Engine } (\text{127.0.0.1:8080}) \longrightarrow \text{Wait for child bind confirmation} \\ \longrightarrow \text{Start Web Server } (\text{127.0.0.1:4173}) \end{cases}$$

## Process Hierarchy & Lifecycle

1. **Supervisor Initialization**:
   - Parses loopback host (`127.0.0.1`, `::1`), web port (`4173`), and engine port (`8080`).
   - Rejects any non-loopback host strings (such as `0.0.0.0`) to prevent accidental network exposure.
2. **Engine Launch**:
   - Ensures binary `dist/bin/breachatlas` exists (or builds it on the fly).
   - Spawns child process: `dist/bin/breachatlas --host 127.0.0.1 --port 8080`.
   - Waits up to five seconds for the spawned child to confirm a successful bind. A response from a different process on the engine port cannot satisfy startup.
3. **Web Server Launch**:
   - Starts HTTP server on loopback port `4173` serving the web assets.
4. **Signal Propagation & Clean Shutdown**:
   - Intercepts `SIGINT` (Ctrl+C) and `SIGTERM`.
   - Closes incoming HTTP connections on the web server.
   - Forwards `SIGTERM` to the Go engine child process.
   - Awaits graceful termination without leaving orphan listeners.
5. **Crash Containment**:
   - If the Go engine crashes unexpectedly, the supervisor intercepts the exit event, logs the error, terminates the web server, and exits with code 1.

## Go Engine Endpoints

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | Loopback | Standard health probe; returns `200 OK` with JSON status |
| `GET` | `/version` | Loopback | Version probe; returns `200 OK` with `0.0.1` and commit identifier |
| `GET` | `/readyz` | Loopback | Readiness probe; confirms server is accepting requests |
| `GET` | `/api/v1/health` | Loopback | API health check for domain service discovery |
