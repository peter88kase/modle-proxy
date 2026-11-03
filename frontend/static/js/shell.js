import { api, toast, $, el, formatMs, setPageError } from "./app.js";

const state = { command: "curl_raw", busy: false, history: [], health: null };

const term = $("terminal");
const termTitle = $("term-title");
const termStatus = $("term-status");

function selectCommand(command) {
  state.command = command;
  document.querySelectorAll(".tabs [data-cmd]").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.cmd === command ? "true" : "false");
  });
  document.querySelectorAll("[data-pane]").forEach((pane) => {
    pane.classList.toggle("hidden", pane.dataset.pane !== command);
  });
  termTitle.textContent = `bedrock-shell — ${command}`;
}

function writeLine(text, className) {
  const line = el("span", "t-line" + (className ? " " + className : ""), text);
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function buildRequest() {
  if (state.command === "curl_raw") {
    const commandLine = $("raw-command").value.trim();
    if (!commandLine) throw new Error("请粘贴 curl 命令");
    const timeout = Number($("raw-timeout").value || 30);
    return { command: "curl_raw", params: { command_line: commandLine, timeout }, timeout };
  }
  if (state.command === "curl") {
    const url = $("curl-url").value.trim();
    if (!url) throw new Error("请填写目标 URL");
    return {
      command: "curl",
      params: {
        url,
        connect_timeout: Number($("curl-connect").value || 5),
        timeout: Number($("curl-max").value || 15),
        head_only: $("curl-head").checked,
      },
      timeout: Number($("curl-max").value || 15),
    };
  }
  if (state.command === "ping") {
    const host = $("ping-host").value.trim();
    if (!host) throw new Error("请填写目标主机");
    return {
      command: "ping",
      params: { host, count: Number($("ping-count").value || 3), timeout: Number($("ping-wait").value || 3) },
      timeout: 30,
    };
  }
  const host = $("dig-host").value.trim();
  if (!host) throw new Error("请填写域名");
  return { command: "dig", params: { host, rtype: $("dig-type").value }, timeout: 20 };
}

function describe(request) {
  if (request.command === "curl_raw") {
    return request.params.command_line;
  }
  if (request.command === "curl") {
    return `curl ${request.params.head_only ? "-I " : ""}${request.params.url}`;
  }
  if (request.command === "ping") {
    return `ping -c ${request.params.count} ${request.params.host}`;
  }
  return `dig ${request.params.host} ${request.params.rtype}`;
}

async function execute(event) {
  event.preventDefault();
  if (state.busy) return;

  let request;
  try {
    request = buildRequest();
  } catch (err) {
    toast(err.message, "error");
    return;
  }

  state.busy = true;
  $("shell-run").disabled = true;
  $("shell-run").textContent = "执行中…";

  const startedAt = Date.now();
  termTitle.textContent = `bedrock-shell — ${request.command}`;
  termStatus.textContent = "running";
  termStatus.className = "t-meta";
  termStatus.dataset.status = "running";
  term.dataset.status = "running";
  writeLine(`$ ${describe(request)}`, "t-cmd");

  try {
    const data = await api("/api/shell/exec", { method: "POST", body: request });
    const elapsed = data.duration_ms ?? Date.now() - startedAt;

    if (data.stdout) {
      writeLine(data.stdout.replace(/\n$/, ""), "");
    }
    if (data.stderr) {
      writeLine(data.stderr.replace(/\n$/, ""), "t-err");
    }
    // -L 跟随重定向时：跳转次数和最终地址必须可见。
    // 落在别的域名上不是错误，但用户有权知道请求最后去了哪里。
    if (data.redirect_count) {
      const note = data.redirect_left_host
        ? `[redirect] 跟随 ${data.redirect_count} 次跳转后落到其它主机：${data.redirect_final_url}`
        : `[redirect] 跟随 ${data.redirect_count} 次跳转：${data.redirect_final_url}`;
      writeLine(note, data.redirect_left_host ? "t-err" : "t-meta");
    }
    const statusText =
      data.status === "ok" ? "completed" : data.status === "timeout" ? "timeout" : "failed";
    writeLine(
      `[${statusText}] exit=${data.exit_code} elapsed=${elapsed}ms${data.truncated ? " output=truncated" : ""}`,
      data.status === "ok" ? "t-ok" : "t-err"
    );

    termStatus.textContent = statusText;
    termStatus.className = data.status === "ok" ? "t-ok" : "t-err";
    termStatus.dataset.status = data.status;
    term.dataset.status = data.status;
    setPageError("shell-error", "");

    $("exec-exit").textContent = String(data.exit_code ?? "—");
    $("exec-duration").textContent = formatMs(elapsed);
    $("exec-target").textContent = data.target_host || "—";
    $("exec-truncated").textContent = data.truncated ? "是（已达上限）" : "否";
    $("exec-timeout").textContent = data.timed_out ? `是（${data.timeout_seconds}s）` : "否";
    $("exec-meta").textContent = `${request.command} · ${elapsed}ms`;

    state.history.unshift({ command: request.command, target: data.target_host, status: data.status });
    state.history = state.history.slice(0, 20);
  } catch (err) {
    writeLine(`[error] ${err.message}`, "t-err");
    termStatus.textContent = "error";
    termStatus.className = "t-err";
    termStatus.dataset.status = "error";
    term.dataset.status = "error";
    setPageError("shell-error", err.message);
    toast(err.message, "error");
    $("exec-meta").textContent = `${request.command} · 失败`;
  } finally {
    state.busy = false;
    $("shell-run").disabled = false;
    $("shell-run").textContent = "执行命令";
    term.appendChild(el("span", "t-line", ""));
  }
}

function renderHealth(data) {
  const badge = $("worker-badge");
  const detail = data.detail || {};
  if (data.available) {
    badge.textContent = "工作进程在线";
    badge.className = "badge pass";
    const commands = detail.commands || {};
    $("w-user").textContent = detail.user || "—";
    $("w-uid").textContent = String(detail.uid ?? "—");
    $("w-ports").textContent = (detail.allowed_ports || []).join(", ") || "—";
    $("w-private").textContent = detail.allow_private ? "允许（已显式开启）" : "禁止（默认）";
    $("w-tools").textContent = Object.entries(commands)
      .map(([name, ok]) => `${name}:${ok ? "ok" : "missing"}`)
      .join("  ");
    $("w-conc").textContent = String(detail.max_concurrency ?? "—");
    $("w-hint").textContent = `版本 ${detail.version || "—"}；输出上限 ${detail.output_limit || "—"} 字节；单命令上限 ${detail.timeout_max || "—"} 秒。`;
  } else {
    badge.textContent = "工作进程离线";
    badge.className = "badge fail";
    $("w-user").textContent = "—";
    $("w-uid").textContent = "—";
    $("w-ports").textContent = "—";
    $("w-private").textContent = "—";
    $("w-tools").textContent = "—";
    $("w-conc").textContent = "—";
    $("w-hint").textContent = data.detail?.error || "无法连接工作进程，请检查 bedrock-shell 服务状态。";
  }
}

async function refreshHealth() {
  try {
    const data = await api("/api/shell/health");
    state.health = data;
    renderHealth(data);
  } catch (err) {
    $("worker-badge").textContent = "状态未知";
    $("worker-badge").className = "badge skip";
    setPageError("shell-error", `工作进程状态未知：${err.message}`);
    toast(err.message, "error");
  }
}

document.querySelectorAll(".tabs [data-cmd]").forEach((button) => {
  button.addEventListener("click", () => selectCommand(button.dataset.cmd));
});
$("shell-form").addEventListener("submit", execute);
$("refresh-health").addEventListener("click", refreshHealth);
$("shell-clear").addEventListener("click", () => {
  term.replaceChildren();
  termStatus.textContent = "等待执行";
  termStatus.className = "t-dim";
  termStatus.dataset.status = "idle";
  term.dataset.status = "idle";
  ["exec-exit", "exec-duration", "exec-target", "exec-truncated", "exec-timeout"].forEach((id) => {
    $(id).textContent = "—";
  });
  $("exec-meta").textContent = "—";
});
$("shell-copy").addEventListener("click", async () => {
  const text = term.innerText;
  if (!text.trim()) {
    toast("暂无可复制的输出", "error");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    toast("输出已复制", "ok");
  } catch (err) {
    toast("浏览器拒绝访问剪贴板", "error");
  }
});

refreshHealth();
