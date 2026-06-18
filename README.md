# Aegis

Aegis is a local OpenAI-compatible proxy sidecar that observes Chat Completions
and Responses API requests before forwarding them unchanged to a running
llama.cpp server.

## Run locally

Start llama.cpp on port `8080`:

```bash
llama-server -m model.gguf --port 8080
```

Install the proxy dependencies into a virtual environment so they stay isolated
from your system Python (otherwise `uvicorn` won't be on your `PATH`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you use [uv](https://docs.astral.sh/uv/), the equivalent is:

```bash
uv venv .venv
uv pip install --python .venv -r requirements.txt
source .venv/bin/activate
```

Start Aegis on port `9000` (with the venv activated):

```bash
uvicorn aegis_proxy:app --host 127.0.0.1 --port "${AEGIS_PORT:-9000}"
```

Point clients at Aegis instead of llama.cpp:

```bash
curl localhost:9000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"local","messages":[{"role":"user","content":"hello"}],"stream":false}'
```

For Responses API clients:

```bash
curl localhost:9000/v1/responses \
  -H "Content-Type: application/json" \
  -d '{"model":"local","input":"hello","stream":false}'
```

Codex CLI expects the Responses API for custom providers. Create a user-level
profile such as `~/.codex/aegis.config.toml`:

```toml
model = "local"
model_provider = "aegis"

[model_providers.aegis]
name = "Aegis Local Proxy"
base_url = "http://127.0.0.1:9000/v1"
wire_api = "responses"
```

Then start Codex with:

```bash
codex --profile aegis
```

Watch the Aegis terminal. Each request prints the OpenAI-compatible request
context that passed through Aegis before being forwarded unchanged.

Open the local viewer:

```bash
open http://127.0.0.1:9000/
```

The viewer shows the OpenAI-compatible request context observed by this proxy
process plus the upstream response returned by llama.cpp.

Captured viewer events are persisted as local JSON files in `.aegis/events` by
default. The directory is ignored by git because request context can include
private prompts, code, paths, and secrets. Delete the directory whenever you want
to clear local history.

## Configuration

`AEGIS_UPSTREAM_URL` controls where Aegis forwards requests. It defaults to
`http://localhost:8080`.

`AEGIS_PORT` controls the port used by the README startup command and by
`python aegis_proxy.py`. It defaults to `9000`.

`AEGIS_EVENT_DIR` controls where viewer event JSON files are written. It
defaults to `.aegis/events`.

Check the proxy:

```bash
curl localhost:9000/healthz
```

Read captured events as JSON:

```bash
curl localhost:9000/aegis/events
```
