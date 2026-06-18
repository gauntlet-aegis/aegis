VIEWER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aegis Viewer</title>
  <style>
    :root { color-scheme: light; --ink: #1f2933; --muted: #697586; --line: #d8dee6; --panel: #f6f8fb; --accent: #087f8c; --warn: #b7791f; --ok: #26734d; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: #ffffff; }
    header { height: 56px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 0 20px; border-bottom: 1px solid var(--line); background: #fbfcfe; }
    h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: 0; }
    button { border: 1px solid var(--line); background: #ffffff; color: var(--ink); border-radius: 6px; min-height: 34px; padding: 0 12px; font: inherit; cursor: pointer; }
    button:hover { border-color: var(--accent); }
    main { height: calc(100vh - 56px); display: grid; grid-template-columns: minmax(260px, 360px) 1fr; }
    aside { border-right: 1px solid var(--line); background: var(--panel); overflow: auto; }
    .event { width: 100%; text-align: left; border: 0; border-bottom: 1px solid var(--line); border-radius: 0; background: transparent; padding: 14px 16px; display: grid; gap: 6px; }
    .event.active { background: #e8f5f6; box-shadow: inset 3px 0 0 var(--accent); }
    .event-top { display: flex; justify-content: space-between; gap: 10px; font-size: 12px; color: var(--muted); }
    .query { font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .meta { display: flex; gap: 8px; flex-wrap: wrap; color: var(--muted); font-size: 12px; }
    .pill { border: 1px solid var(--line); border-radius: 999px; padding: 1px 8px; background: #fff; }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    section { min-width: 0; overflow: auto; padding: 20px; }
    .empty { color: var(--muted); min-height: 220px; display: grid; place-items: center; }
    .toolbar { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 18px; }
    .title { min-width: 0; }
    .title h2 { margin: 0 0 6px; font-size: 22px; letter-spacing: 0; }
    .title p { margin: 0; color: var(--muted); }
    .stats { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .block { border: 1px solid var(--line); border-radius: 8px; min-width: 0; overflow: hidden; background: #fff; }
    .block h3 { margin: 0; padding: 10px 12px; border-bottom: 1px solid var(--line); font-size: 13px; background: #fbfcfe; }
    pre { margin: 0; padding: 12px; white-space: pre-wrap; overflow-wrap: anywhere; min-height: 160px; max-height: 46vh; overflow: auto; font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    @media (max-width: 820px) { main { grid-template-columns: 1fr; height: auto; } aside { max-height: 38vh; border-right: 0; border-bottom: 1px solid var(--line); } .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header><h1>Aegis Viewer</h1><button id="refresh" type="button">Refresh</button></header>
  <main><aside id="events"></aside><section id="detail" class="empty">No context events yet</section></main>
  <script>
    let selectedId = null;
    let detailSignature = "";
    const eventsEl = document.querySelector("#events");
    const detailEl = document.querySelector("#detail");

    const text = value => value === null || value === undefined || value === "" ? "empty" : typeof value === "string" ? value : JSON.stringify(value, null, 2);
    const esc = value => text(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));

    async function loadEvents() {
      const events = await fetch("/aegis/events").then(r => r.json());
      const signature = JSON.stringify(events.map(event => [event.id, event.upstream_status, event.latency_ms, event.response_bytes, event.message_count]));
      eventsEl.innerHTML = events.map(event => `
        <button class="event ${event.id === selectedId ? "active" : ""}" data-id="${event.id}" type="button">
          <span class="event-top"><span>#${event.id}</span><span>${esc(event.created_at)}</span></span>
          <span class="query">${esc(event.preview || "(no user message)")}</span>
          <span class="meta">
            <span class="pill">${event.upstream_status || "pending"}</span>
            <span class="pill">${event.message_count} messages</span>
            <span class="pill">${event.latency_ms ?? "-"} ms</span>
          </span>
        </button>`).join("");
      if (!events.length) return renderEmpty();
      const previousId = selectedId;
      if (!selectedId || !events.some(event => event.id === selectedId)) selectedId = events[0].id;
      if (selectedId !== previousId || signature !== detailSignature) await loadDetail(selectedId, signature);
    }

    async function loadDetail(id, signature = detailSignature) {
      selectedId = id;
      detailSignature = signature;
      const event = await fetch(`/aegis/events/${id}`).then(r => r.json());
      document.querySelectorAll(".event").forEach(el => el.classList.toggle("active", Number(el.dataset.id) === id));
      detailEl.className = "";
      detailEl.innerHTML = `
        <div class="toolbar">
          <div class="title"><h2>${esc(event.model || "unknown model")}</h2><p>${esc(event.upstream_url)}</p></div>
          <div class="stats">
            <span class="pill">status ${event.upstream_status || "pending"}</span>
            <span class="pill">${event.message_count} messages</span>
            <span class="pill">${event.response_bytes} bytes</span>
            <span class="pill">${event.latency_ms ?? "-"} ms</span>
          </div>
        </div>
        <div class="block"><h3>Messages</h3><pre>${event.messages.map((message, index) => `${index + 1}. [${message.role || "unknown"}]\\n${text(message.content)}`).map(esc).join("\\n\\n")}</pre></div>
        <div class="grid">
          <div class="block"><h3>Request Params</h3><pre>${esc(event.request_params)}</pre></div>
          <div class="block"><h3>Request JSON</h3><pre>${esc(event.request)}</pre></div>
        </div>`;
    }

    function renderEmpty() {
      eventsEl.innerHTML = "";
      detailEl.className = "empty";
      detailEl.textContent = "No context events yet";
    }

    eventsEl.addEventListener("click", event => {
      const button = event.target.closest("button[data-id]");
      if (button) loadDetail(Number(button.dataset.id));
    });
    document.querySelector("#refresh").addEventListener("click", loadEvents);
    loadEvents();
    setInterval(loadEvents, 5000);
  </script>
</body>
</html>
"""
