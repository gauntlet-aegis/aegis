# Aegis — Build Brief: Local Proxy Sidecar (Milestone 1)

**For:** Claude Code
**Objective:** Turn the existing in-process context interceptor into a thin HTTP
proxy that sits **in front of a running llama.cpp server**. The proxy intercepts
every chat-completion request, runs it through the interceptor, forwards it to
llama.cpp unchanged, and returns the response. **Observe only — change nothing yet.**

This is the smallest step that turns Aegis from a library into a real local
sidecar. Resist adding anything beyond what's specified.

---

## What already exists (reuse, do not rewrite)

There is a working file `aegis_tap.py` containing:

- `Context` — a dataclass (`system_prompt`, `credentials: dict`, `untrusted_content`,
  `user_query`) with a `to_prompt()` assembly method.
- `ContextInterceptor` — has `process(ctx) -> ctx`, currently the **identity
  function** with an observation logger. This is "the seam." Every future layer
  attaches at its `return ctx` line.
- A terminal two-pane `view()` for raw vs. model-visible context.

**The proxy is a transport shell around this existing brain.** The interceptor
logic stays where it is; the proxy's only job is HTTP in, parse, hand to
`process()`, serialize, forward.

---

## The one architectural decision (already made)

- **llama.cpp is upstream and untouched.** Aegis sits in front of it. The model
  stays a black box. This also previews how Aegis would later sit in front of a
  closed API.
- Aegis exposes an **OpenAI-compatible** `/v1/chat/completions` endpoint so any
  client (our agent, the OpenAI SDK, plain `curl`) is protected by changing one
  base URL — nothing else.
- The proxy is **transparent**: a request that passes through Aegis must produce
  the same llama.cpp response as if the client had called llama.cpp directly.

---

## Scope

### IN (build exactly this)
1. A FastAPI app (`aegis_proxy.py`) exposing `POST /v1/chat/completions`.
2. Parse the incoming OpenAI-style payload (`messages`, plus model/params) into,
   or alongside, the existing `Context` abstraction (see "Provenance wrinkle").
3. Call `ContextInterceptor.process()` on it (still identity — forwards unchanged).
4. Forward the request to a **configurable** llama.cpp upstream
   (default `http://localhost:8080`) using `httpx`.
5. Return llama.cpp's response to the client verbatim.
6. Log each intercepted request through the existing observation path, and print
   the two-pane view (raw vs. model-visible — identical for now) per request.
7. A `GET /healthz` that confirms the proxy is up and reports the upstream URL.

### Explicitly OUT (do NOT build yet)
- No honeytoken substitution / no transformation of any kind.
- No scanning, scoring, blocking, or policy logic.
- No tool-call interception (requests only; responses pass straight through).
- No streaming support in v1 — handle `"stream": false`. If a request sets
  `"stream": true`, either force it false for now **or** pass through opaquely;
  pick the simpler one and leave a `# TODO: streaming` marker. Do not build a
  streaming relay.
- No auth, no TLS, no Vault. Local dev only.

---

## Target file layout

```
aegis/
  aegis_tap.py        # EXISTS — Context, ContextInterceptor, view(). Reuse.
  aegis_proxy.py      # NEW — FastAPI app, the transport shell.
  config.py           # NEW — upstream URL, ports (env-overridable).
  README.md           # NEW — how to run llama.cpp + Aegis + a test request.
  requirements.txt    # NEW — fastapi, uvicorn, httpx, pydantic.
```

Keep `aegis_proxy.py` thin — target well under ~120 lines. If it's growing past
that, logic is leaking into the proxy that belongs in the interceptor.

---

## Build tasks (ordered, each independently verifiable)

1. **Config** — `config.py` with `UPSTREAM_URL` (default `http://localhost:8080`),
   `AEGIS_PORT` (default `9000`), both overridable via env vars.
2. **Skeleton + health** — FastAPI app, `GET /healthz` returning `{status, upstream}`.
   Verify: `curl localhost:9000/healthz` works with no llama.cpp running.
3. **Pure pass-through forward** — implement `POST /v1/chat/completions` that
   forwards the raw JSON body to `{UPSTREAM_URL}/v1/chat/completions` via `httpx`
   and returns the response untouched. **No interceptor yet.** Verify against a
   live llama.cpp: response is byte-identical to calling llama.cpp directly.
4. **Wire in the interceptor** — map the payload into the `Context` shape (see
   below), call `ContextInterceptor.process()`, then forward. Since `process()`
   is identity, behavior must not change. Verify: response still identical; the
   observation log now records the request.
5. **Viewer hook** — print the existing two-pane `view()` per request. Confirm the
   DIFF line reads `identical (pass-through working)`.
6. **README** — exact local run instructions (below) plus one copy-paste test
   request.

---

## Provenance wrinkle (record this; do not try to solve it)

At the HTTP boundary you receive a flat `messages` array: `[{role, content}, ...]`.
Role-level origin (system / user / assistant) survives, but finer provenance —
"this span of the user message is untrusted retrieved content" — is **gone**; the
client already merged it before sending.

For v1, map what the protocol gives you:
- `role: "system"` → `Context.system_prompt`
- last `role: "user"` → `Context.user_query`
- everything else → concatenate into a single field for now.
- `Context.credentials` → empty `{}` at the proxy (the proxy can't see a separate
  credential map; that's a richer-integration concern for later).

Add a short `# LIMITATION:` comment noting that full provenance requires a
cooperating agent (e.g. structured content or an `X-Aegis-Provenance` header), and
that role-level granularity is sufficient for the current observe-only milestone.
Do **not** build the provenance channel now.

---

## How to run locally (put in README)

```bash
# 1. Start llama.cpp (any model) on :8080
llama-server -m model.gguf --port 8080

# 2. Start Aegis in front of it on :9000
pip install -r requirements.txt
uvicorn aegis_proxy:app --port 9000

# 3. Point a client at Aegis instead of llama.cpp
curl localhost:9000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"local","messages":[{"role":"user","content":"hello"}],"stream":false}'
```

Watch the Aegis terminal: the two-pane view prints, the DIFF says identical, the
completion returns from llama.cpp.

---

## Acceptance criteria (definition of done)

- [ ] `curl` against Aegis `:9000` returns the **same completion** as the same
      request sent directly to llama.cpp `:8080`.
- [ ] Each request prints the two-pane view; DIFF reads `identical`.
- [ ] The observation log records secrets-in-scope (empty for now), untrusted
      char count, and the query, per request.
- [ ] Upstream URL and port are env-configurable; nothing hardcoded.
- [ ] `aegis_tap.py` is **imported and reused**, not duplicated.
- [ ] No transformation, scanning, or policy logic exists anywhere.

---

## Guardrails for the implementer

- The seam stays in `ContextInterceptor.process()`. The proxy must not start
  inspecting or deciding — if you feel the urge, that's the next milestone.
- Keep llama.cpp's contract intact. Aegis must be invisible to the client beyond
  the base-URL change.
- Prefer fewer dependencies and less code. This milestone is "we can interpose on
  the live model boundary and forward transparently" — nothing more.
