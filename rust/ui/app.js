// The window, wired to the core node through Tauri commands.

const T = () => window.__TAURI__;
const hasTauri = () => !!(T() && T().core);
const invoke = (cmd, args) =>
  hasTauri() ? T().core.invoke(cmd, args) : Promise.reject(new Error("design preview — not in the window"));

const $ = (id) => document.getElementById(id);
const footer = (m) => ($("footer-left").textContent = m);
function logLine(l) {
  const el = $("log");
  el.textContent += l + "\n";
  el.scrollTop = el.scrollHeight;
}
async function guard(p, ok) {
  try { const r = await p; if (ok) footer(ok); return r; }
  catch (e) { footer("" + (e && e.message ? e.message : e)); return undefined; }
}
const num = (id, d) => parseInt($(id).value, 10) || d;
// Text from the network (nicknames, folder and file names) is never markup.
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const isHidden = (t) => t.trim().toLowerCase().endsWith(".stalknet");

// ---- Window controls -------------------------------------------------------
function appWindow() {
  const t = T();
  return t && t.window && t.window.getCurrentWindow ? t.window.getCurrentWindow() : null;
}
document.querySelectorAll(".winbtn").forEach((b) =>
  b.addEventListener("click", async () => {
    const w = appWindow();
    if (!w) return;
    const a = b.dataset.win;
    if (a === "min") await w.minimize();
    else if (a === "max") await w.toggleMaximize();
    else if (a === "close") await w.close();
  })
);

// ---- Nav -------------------------------------------------------------------
$("nav").addEventListener("click", (e) => {
  const it = e.target.closest(".navitem");
  if (!it) return;
  document.querySelectorAll(".navitem").forEach((n) => n.classList.toggle("active", n === it));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${it.dataset.tab}`));
});

// ---- Node ------------------------------------------------------------------
$("btn-start").addEventListener("click", async () => {
  await guard(invoke("set_config", { network: $("net-name").value, publicHost: $("net-host").value, autoMapPort: $("opt-map").checked }));
  await guard(invoke("start_node", { port: num("net-port", 0), allowExit: $("opt-exit").checked, relay: $("opt-relay").checked }), "starting & joining — watch the LOG tab");
});
$("btn-stop").addEventListener("click", () => guard(invoke("stop_node"), "stopped"));
$("btn-reconnect").addEventListener("click", () => guard(invoke("reconnect", { viaTorrent: true }), "reconnecting…"));

// ---- Relays + trust --------------------------------------------------------
let lastRelays = "";
async function renderRelays() {
  if (!hasTauri()) return;
  let rows; try { rows = await invoke("relays"); } catch (_) { return; }
  // Rebuild only when the list changed, so a tick being clicked is not wiped.
  const key = JSON.stringify(rows);
  if (key === lastRelays) return;
  lastRelays = key;
  const tb = $("relay-rows");
  if (!rows.length) { tb.innerHTML = '<tr><td class="empty" colspan="4">none yet</td></tr>'; return; }
  tb.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(r.nickname)}${r.is_self ? " (you)" : ""}</td><td>${esc(r.address)}</td><td>${r.allows_exit ? "yes" : "—"}</td>`;
    const td = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.checked = r.trusted; cb.dataset.fp = r.fingerprint;
    cb.addEventListener("change", collectTrusted);
    td.appendChild(cb); tr.appendChild(td); tb.appendChild(tr);
  }
}
function collectTrusted() {
  const fps = Array.from($("relay-rows").querySelectorAll("input[type=checkbox]")).filter((c) => c.checked).map((c) => c.dataset.fp);
  guard(invoke("set_trusted_exits", { fingerprints: fps }), "trusted exits updated");
}

// ---- My folders ------------------------------------------------------------
$("btn-share-add").addEventListener("click", async () => {
  const ok = await guard(invoke("add_shared_folder", { path: $("sh-path").value, alias: $("sh-alias").value, public: $("sh-public").checked }), "folder added");
  if (ok !== undefined) renderShared();
});
async function renderShared() {
  if (!hasTauri()) return;
  let rows; try { rows = await invoke("shared_folders"); } catch (_) { return; }
  const tb = $("shared-rows");
  if (!rows.length) { tb.innerHTML = '<tr><td class="empty" colspan="3">none</td></tr>'; return; }
  tb.innerHTML = "";
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(f.alias)}</td><td>${f.public ? "public" : "account"}</td>`;
    const td = document.createElement("td");
    const btn = document.createElement("button"); btn.textContent = "remove";
    btn.addEventListener("click", async () => { await guard(invoke("remove_shared_folder", { alias: f.alias }), "removed"); renderShared(); });
    td.appendChild(btn); tr.appendChild(td); tb.appendChild(tr);
  }
}

// ---- Remote (visit) --------------------------------------------------------
$("btn-visit").addEventListener("click", async () => {
  const t = $("vi-target").value.trim();
  if (!isHidden(t)) { footer("enter a ….stalknet address"); return; }
  const folders = await guard(invoke("open_hidden_folders", { address: t }), "opened");
  if (folders) renderVisitFolders(folders);
});
$("btn-visit-login").addEventListener("click", () => guard(invoke("remote_login", { user: $("vi-user").value, password: $("vi-pass").value }), "signed in"));
function renderVisitFolders(folders) {
  const tb = $("visit-folders");
  if (!folders.length) { tb.innerHTML = '<tr><td class="empty" colspan="2">no folders</td></tr>'; return; }
  tb.innerHTML = "";
  for (const f of folders) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(f.alias)}${f.public ? "" : " (password)"}</td>`;
    const td = document.createElement("td");
    const btn = document.createElement("button"); btn.textContent = "files";
    btn.addEventListener("click", () => openFiles(f.alias));
    td.appendChild(btn); tr.appendChild(td); tb.appendChild(tr);
  }
}
async function openFiles(alias) {
  const files = await guard(invoke("remote_files", { alias }), "listing " + alias);
  const tb = $("visit-files");
  if (!files) return;
  if (!files.length) { tb.innerHTML = '<tr><td class="empty" colspan="3">empty</td></tr>'; return; }
  tb.innerHTML = "";
  for (const f of files) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(f.name)}</td><td>${esc(f.size)}</td>`;
    const td = document.createElement("td");
    const btn = document.createElement("button"); btn.textContent = "download";
    btn.addEventListener("click", () => {
      // Only the bare name from the other node; never its folders or "..".
      const bare = String(f.name).split(/[\\/:]/).pop();
      if (!bare || bare === "." || bare === "..") { footer("refused: the file name is not a plain name"); return; }
      const save = ($("vi-save").value || ".").replace(/[\\/]+$/, "") + "/" + bare;
      guard(invoke("remote_download", { alias, fileName: f.name, savePath: save }), "downloaded " + f.name);
    });
    td.appendChild(btn); tr.appendChild(td); tb.appendChild(tr);
  }
}

// ---- Torrent ---------------------------------------------------------------
$("btn-tor-share").addEventListener("click", async () => {
  const link = await guard(invoke("share", { path: $("to-path").value }), "shared");
  if (link) $("to-link").value = link;
});
$("btn-tor-dl").addEventListener("click", async () => {
  footer("downloading…");
  const name = await guard(invoke("download", { ontLink: $("to-dl-link").value, saveFolder: $("to-dl-save").value }));
  if (name !== undefined) { footer("downloaded " + name); renderBundles(); }
});
let lastBundles = "";
async function renderBundles() {
  if (!hasTauri()) return;
  let rows; try { rows = await invoke("bundles"); } catch (_) { return; }
  const key = JSON.stringify(rows);
  if (key === lastBundles) return;
  lastBundles = key;
  const tb = $("bundle-rows");
  if (!rows.length) { tb.innerHTML = '<tr><td class="empty" colspan="5">none</td></tr>'; return; }
  tb.innerHTML = "";
  for (const b of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(b.name)}</td><td>${esc(b.kind)}</td><td>${esc(b.size)}</td><td>${esc(b.progress)}</td>`;
    const td = document.createElement("td");
    const btn = document.createElement("button"); btn.textContent = "copy link";
    btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.link); footer("link copied"); } catch (_) { $("to-link").value = b.link; footer("link shown above"); }
    });
    td.appendChild(btn); tr.appendChild(td); tb.appendChild(tr);
  }
}

// ---- Sites -----------------------------------------------------------------
$("btn-si-publish").addEventListener("click", async () => {
  footer("publishing…");
  const addr = await guard(invoke("publish_site", { folder: $("si-folder").value }), "site published");
  if (addr) { $("si-address").value = addr; renderBundles(); }
});
$("btn-so-open").addEventListener("click", async () => {
  footer("opening…");
  const url = await guard(invoke("open_site", { address: $("so-address").value }), "site opened");
  if (url) { $("so-url").value = url; renderBundles(); }
});
$("btn-so-show").addEventListener("click", () => {
  const url = $("so-url").value;
  if (url.startsWith("http://127.0.0.1:")) guard(invoke("open_in_browser", { url }));
});

// ---- Anonymous exit --------------------------------------------------------
$("btn-ax-start").addEventListener("click", () => { footer("raising the exit…"); guard(invoke("start_anonymous_exit"), "anonymous exit up"); });
$("btn-ax-stop").addEventListener("click", () => guard(invoke("stop_anonymous_exit"), "anonymous exit stopped"));

// ---- Guest accounts --------------------------------------------------------
$("btn-ac-add").addEventListener("click", async () => {
  const ok = await guard(invoke("add_account", { user: $("ac-user").value, password: $("ac-pass").value }), "account saved");
  if (ok !== undefined) { $("ac-pass").value = ""; renderAccounts(); }
});
async function renderAccounts() {
  if (!hasTauri()) return;
  let names; try { names = await invoke("accounts"); } catch (_) { return; }
  const tb = $("account-rows");
  if (!names.length) { tb.innerHTML = '<tr><td class="empty" colspan="2">none</td></tr>'; return; }
  tb.innerHTML = "";
  for (const n of names) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(n)}</td>`;
    const td = document.createElement("td");
    const btn = document.createElement("button"); btn.textContent = "remove";
    btn.addEventListener("click", async () => { await guard(invoke("remove_account", { user: n }), "removed"); renderAccounts(); });
    td.appendChild(btn); tr.appendChild(td); tb.appendChild(tr);
  }
}

// ---- Ports -----------------------------------------------------------------
$("btn-expose").addEventListener("click", async () => {
  const ok = await guard(invoke("expose_port", { internal: num("ex-port", 1024), localHost: $("ex-host").value, localPort: num("ex-local", 0) }), "port offered");
  if (ok !== undefined) renderExposed();
});
async function renderExposed() {
  try { const ps = await invoke("exposed_ports"); $("ex-list").value = ps.length ? ps.join(", ") : "—"; } catch (_) {}
}
$("btn-forward").addEventListener("click", async () => {
  const t = $("fw-target").value.trim();
  if (!isHidden(t)) { footer("enter a ….stalknet address"); return; }
  const got = await guard(invoke("forward_hidden", { address: t, remotePort: num("fw-remote", 0), localPort: num("fw-local", 0) }), "forwarded");
  if (got !== undefined) $("fw-state").value = "127.0.0.1:" + got;
});

// ---- Services --------------------------------------------------------------
$("btn-hidden-start").addEventListener("click", async () => {
  const addr = await guard(invoke("start_hidden", { introPoints: num("hs-intro", 3) }), "hidden service up");
  if (addr) $("hs-addr").value = addr;
});
$("btn-hidden-stop").addEventListener("click", () => guard(invoke("stop_hidden"), "hidden service stopped"));
$("btn-tunnel").addEventListener("click", async () => {
  const got = await guard(invoke("open_tunnel", { localPort: num("wo-port", 9150) }), "way out open");
  if (got !== undefined) $("wo-state").value = "127.0.0.1:" + got;
});
$("btn-tunnel-close").addEventListener("click", async () => { await guard(invoke("close_tunnel"), "way out closed"); $("wo-state").value = "—"; });

// ---- Polling ---------------------------------------------------------------
let signedIn = false;
async function poll() {
  if (!hasTauri()) return;
  try {
    const s = await invoke("status");
    const lamp = $("lamp");
    if (s.running) {
      lamp.classList.add("on");
      $("state-text").textContent = s.relay ? "relay running" : "client running";
    } else {
      lamp.classList.toggle("on", signedIn);
      $("state-text").textContent = signedIn ? "signed in, node stopped" : "offline";
    }
    $("stats").textContent = `Relays: ${s.relay_count}   Circuits: ${s.own_circuits}   Records: ${s.kept_records}`;
    $("s-addr-field").value = s.folder_address || "—";
    $("hs-addr").value = s.hidden_address || "—";
    $("wo-state").value = s.way_out_port ? "127.0.0.1:" + s.way_out_port : "—";
    $("ax-state").value = s.anonymous_exit ? "letting others out" : "off";
  } catch (_) {}
  try { (await invoke("take_logs") || []).forEach(logLine); } catch (_) {}
  renderRelays();
  renderBundles();
}

function clock() {
  $("footer-right").textContent = new Date().toLocaleTimeString();
}

// ---- Boot ------------------------------------------------------------------
(async function boot() {
  try {
    const p = await invoke("default_identity_path");
    $("id-path").value = p;
    const ok = await guard(invoke("auto_identity", { path: p }));
    if (ok !== undefined && $("footer-left").textContent === "idle") footer("signed in");
    if (ok !== undefined) { $("id-state").textContent = "signed in — press START on this tab"; signedIn = true; }
    else $("id-state").textContent = "could not create an identity";
  } catch (_) {}
  renderShared();
  renderExposed();
  renderAccounts();
  setInterval(poll, 1500);
  setInterval(clock, 1000);
  clock();
})();
