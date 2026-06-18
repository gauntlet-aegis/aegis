# Aegis

Aegis is a local OpenAI-compatible proxy sidecar that observes chat-completion
requests before forwarding them unchanged to a running llama.cpp server.

## Run locally

Start llama.cpp on port `8080`:

```bash
llama-server -m model.gguf --port 8080
```

Install the proxy dependencies:

```bash
pip install -r requirements.txt
```

Start Aegis on port `9000`:

```bash
uvicorn aegis_proxy:app --host 127.0.0.1 --port "${AEGIS_PORT:-9000}"
```

Point clients at Aegis instead of llama.cpp:

```bash
curl localhost:9000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"local","messages":[{"role":"user","content":"hello"}],"stream":false}'
```

Watch the Aegis terminal. Each request prints the OpenAI-compatible request
context that passed through Aegis before being forwarded unchanged.

Open the local viewer:

```bash
open http://127.0.0.1:9000/
```

The viewer shows the OpenAI-compatible request context observed by this proxy
process: `model`, `messages`, and request parameters. It resets when Aegis
restarts.

## Configuration

`AEGIS_UPSTREAM_URL` controls where Aegis forwards requests. It defaults to
`http://localhost:8080`.

`AEGIS_PORT` controls the port used by the README startup command and by
`python aegis_proxy.py`. It defaults to `9000`.

Check the proxy:

```bash
curl localhost:9000/healthz
```

Read captured events as JSON:

```bash
curl localhost:9000/aegis/events
```
