import { api, toast, $, el, setPageError } from "./app.js";

const ENV_LABELS = [
  ["运行环境", "env"],
  ["监听地址", "bind"],
  ["数据库", "db_path"],
  ["Cookie Secure", "cookie_secure"],
  ["会话空闲超时", "session_idle_seconds"],
  ["会话绝对超时", "session_absolute_seconds"],
  ["登录失败锁定阈值", "login_max_failures"],
  ["锁定时长", "login_lock_seconds"],
  ["连接超时", "model_connect_timeout"],
  ["首内容超时", "model_first_token_timeout"],
  ["请求总超时", "model_total_timeout"],
  ["模型测试并发", "model_max_concurrency"],
  ["响应体上限", "model_max_body_bytes"],
  ["允许内网上游", "allow_private_upstream"],
  ["Shell 套接字", "shell_socket"],
  ["Shell 频率限制", "shell_rate_per_minute"],
];

let providers = [];
let adapters = [];

function fillKv(target, rows) {
  const host = $(target);
  host.replaceChildren();
  rows.forEach(([label, value]) => {
    host.appendChild(el("dt", null, label));
    host.appendChild(el("dd", null, value === null || value === undefined || value === "" ? "—" : String(value)));
  });
}

function renderEnv(env) {
  fillKv(
    "env-list",
    ENV_LABELS.map(([label, key]) => {
      let value = env[key];
      if (key.endsWith("_seconds")) value = `${value} 秒`;
      if (typeof value === "boolean") value = value ? "已开启" : "未开启";
      if (Array.isArray(value)) value = value.length ? value.join(", ") : "—";
      return [label, value];
    })
  );
}

function renderShell(shell) {
  const commands = (shell.detail && shell.detail.commands) || {};
  fillKv("shell-list", [
    ["状态", shell.available ? "在线" : "离线"],
    ["运行账号", shell.detail?.user || "—"],
    ["UID", shell.detail?.uid ?? "—"],
    ["允许端口", (shell.detail?.allowed_ports || []).join(", ") || "—"],
    ["允许内网", shell.detail?.allow_private ? "是" : "否"],
    ["工具", Object.entries(commands).map(([k, v]) => `${k}:${v ? "ok" : "missing"}`).join("  ") || "—"],
    ["错误", shell.available ? "—" : shell.detail?.error || "—"],
  ]);
}

function renderAudit(items) {
  const body = $("audit-body");
  body.replaceChildren();
  if (!items.length) {
    const tr = el("tr");
    const td = el("td", "table-empty", "暂无审计记录");
    td.dataset.testid = "t-settings-empty-audit";
    td.colSpan = 4;
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  items.forEach((item) => {
    const tr = el("tr");
    tr.dataset.testid = "t-settings-row-audit";
    tr.appendChild(el("td", "mono small", item.ts));
    tr.appendChild(el("td", null, item.username || "—"));
    tr.appendChild(el("td", "mono small", item.action));
    tr.appendChild(el("td", "mono small", item.ip || "—"));
    body.appendChild(tr);
  });
}

async function loadSettings() {
  try {
    const data = await api("/api/settings");
    $("settings-version").textContent = `v${data.version}`;
    renderEnv(data.environment);
    renderShell(data.shell);
    renderAudit(data.recent_audit || []);
    fillKv("count-list", [
      ["账号数", data.counts.users],
      ["供应商配置", data.counts.providers],
      ["测试批次", data.counts.suite_runs],
      ["活跃会话", data.counts.active_sessions],
      ["服务器时间", data.server_time],
    ]);
    $("test-repeat").value = data.runtime.test_repeat || 3;
    $("default-prompt").value = data.runtime.default_prompt || "只回复 CONNECT_OK";
    setPageError("settings-error", "");
  } catch (err) {
    setPageError("settings-error", `配置加载失败：${err.message}`);
    toast(err.message, "error");
  }
}

async function loadProviders() {
  try {
    const [list, meta] = await Promise.all([api("/api/providers"), api("/api/providers/adapters")]);
    providers = list.items || [];
    adapters = meta.items || [];
    const select = $("p-adapter");
    select.replaceChildren();
    adapters.forEach((adapter) => {
      const option = el("option", null, `${adapter.label}（${adapter.id}）`);
      option.value = adapter.id;
      select.appendChild(option);
    });
    syncAuthOptions();

    const body = $("provider-body");
    body.replaceChildren();
    providers.forEach((provider) => {
      const tr = el("tr", "clickable");
      tr.dataset.testid = "t-settings-row-provider";
      tr.dataset.providerId = provider.id;
      tr.appendChild(el("td", "mono", provider.id));
      tr.appendChild(el("td", null, provider.name));
      tr.appendChild(el("td", "mono small", provider.adapter));
      tr.appendChild(el("td", "mono small", provider.direct_base_url || "—"));
      tr.appendChild(el("td", "mono small", provider.forward_base_url || "—"));
      tr.appendChild(el("td", "mono small", provider.auth_style || "—"));
      const status = el("td");
      status.dataset.testid = "t-settings-cell-provider-status";
      status.dataset.enabled = provider.enabled ? "true" : "false";
      status.appendChild(el("span", `badge ${provider.enabled ? "pass" : "neutral"}`, provider.enabled ? "启用" : "停用"));
      tr.appendChild(status);
      tr.appendChild(el("td", "small", "编辑"));
      tr.addEventListener("click", () => fillProviderForm(provider));
      body.appendChild(tr);
    });
    if (!providers.length) {
      const tr = el("tr");
      const td = el("td", "table-empty", "暂无供应商配置");
      td.dataset.testid = "t-settings-empty-provider";
      td.colSpan = 8;
      tr.appendChild(td);
      body.appendChild(tr);
    }
  } catch (err) {
    setPageError("settings-error", `供应商配置加载失败：${err.message}`);
    toast(err.message, "error");
  }
}

function currentAdapter() {
  return adapters.find((item) => item.id === $("p-adapter").value);
}

function syncAuthOptions() {
  const adapter = currentAdapter();
  const select = $("p-auth");
  const previous = select.value;
  select.replaceChildren();
  const styles = adapter ? adapter.auth_styles : ["bearer"];
  styles.forEach((style) => {
    const option = el("option", null, style);
    option.value = style;
    select.appendChild(option);
  });
  if (styles.includes(previous)) select.value = previous;
}

function fillProviderForm(provider) {
  $("p-id").value = provider.id;
  $("p-id").dataset.editing = provider.id;
  $("p-name").value = provider.name;
  $("p-adapter").value = provider.adapter;
  syncAuthOptions();
  $("p-direct").value = provider.direct_base_url || "";
  $("p-forward").value = provider.forward_base_url || "";
  $("p-auth").value = provider.auth_style || "bearer";
  // 版本号位置是协议变体：Bedrock invoke_model 放 body，Anthropic 直连放 header。
  $("p-version-mode").value = provider.version_in_body ? "body" : "header";
  $("p-api-version").value = provider.api_version || "";
  $("p-model").value = provider.default_model || "";
  $("p-notes").value = provider.notes || "";
  $("p-enabled").checked = Boolean(provider.enabled);
  $("p-id").focus();
}

function resetForm() {
  ["p-id", "p-name", "p-direct", "p-forward", "p-model", "p-notes", "p-api-version"].forEach((id) => {
    $(id).value = "";
  });
  delete $("p-id").dataset.editing;
  $("p-enabled").checked = true;
}

/* ---------------------------------------------------------------- events */
$("p-adapter").addEventListener("change", syncAuthOptions);
$("p-reset").addEventListener("click", resetForm);

$("provider-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    id: $("p-id").value.trim(),
    name: $("p-name").value.trim(),
    adapter: $("p-adapter").value,
    direct_base_url: $("p-direct").value.trim(),
    forward_base_url: $("p-forward").value.trim(),
    auth_style: $("p-auth").value,
    api_version: $("p-api-version").value.trim(),
    version_in_body: $("p-version-mode").value === "body",
    default_model: $("p-model").value.trim(),
    notes: $("p-notes").value.trim(),
    enabled: $("p-enabled").checked,
  };
  if (!payload.id || !payload.name) {
    toast("标识与名称不能为空", "error");
    return;
  }
  try {
    await api("/api/providers", { method: "POST", body: payload });
    toast("供应商配置已保存", "ok");
    resetForm();
    loadProviders();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("p-delete").addEventListener("click", async () => {
  const id = $("p-id").value.trim();
  if (!id) {
    toast("请先选择要删除的供应商", "error");
    return;
  }
  if (!window.confirm(`确认删除供应商配置 ${id}？历史测试记录不会删除。`)) return;
  try {
    await api(`/api/providers/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("已删除", "ok");
    resetForm();
    loadProviders();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("runtime-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/settings", {
      method: "POST",
      body: {
        test_repeat: Number($("test-repeat").value || 3),
        default_prompt: $("default-prompt").value.trim() || "只回复 CONNECT_OK",
      },
    });
    toast("运行参数已保存", "ok");
    loadSettings();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/auth/password", {
      method: "POST",
      body: {
        current_password: $("cur-password").value,
        new_password: $("new-password").value,
      },
    });
    $("cur-password").value = "";
    $("new-password").value = "";
    toast("密码已修改，其他会话已失效", "ok");
  } catch (err) {
    toast(err.message, "error");
  }
});

$("revoke-sessions").addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/sessions/revoke-others", { method: "POST" });
    toast(`已注销 ${data.revoked} 个其他会话`, "ok");
    loadSettings();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("reload-settings").addEventListener("click", () => {
  loadSettings();
  loadProviders();
});

loadSettings();
loadProviders();
