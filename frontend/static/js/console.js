import { api, streamRequest, toast, $, el, formatMs } from "./app.js";

const state = {
  models: [],
  providers: [],
  adapters: [],
  meta: null,
  mode: "single",
  busy: false,
  controller: null,
  runId: null,
  counts: { pass: 0, fail: 0, skip: 0 },
};

const F = {
  provider: $("provider"),
  adapter: $("adapter"),
  adapterNote: $("adapter-note"),
  baseUrl: $("base-url"),
  link: $("link"),
  linkDirect: $("link-direct"),
  linkForward: $("link-forward"),
  forwardFields: $("forward-fields"),
  forwardBase: $("forward-base"),
  forwardModel: $("forward-model"),
  forwardKey: $("forward-key"),
  repeat: $("repeat"),
  interval: $("suite-interval"),
  mockNoContent: $("mock-no-content"),
  mockHeartbeat: $("mock-heartbeat"),
  unreachable: $("unreachable"),
  authStyle: $("auth-style"),
  apiKey: $("api-key"),
  toggleKey: $("toggle-key"),
  model: $("model"),
  modelOptions: $("model-options"),
  prompt: $("prompt"),
  system: $("system"),
  maxTokens: $("max-tokens"),
  temperature: $("temperature"),
  connectTimeout: $("connect-timeout"),
  firstTimeout: $("first-timeout"),
  totalTimeout: $("total-timeout"),
  streamMode: $("stream-mode"),
  streamUsage: $("stream-usage"),
  runBtn: $("run-btn"),
  runHint: $("run-hint"),
  envBadge: $("env-badge"),
  resultMeta: $("result-meta"),
  rHttp: $("r-http"),
  rLatency: $("r-latency"),
  rTtft: $("r-ttft"),
  rVerdict: $("r-verdict"),
  resultError: $("result-error"),
  answer: $("answer"),
  rModel: $("r-model"),
  rFinish: $("r-finish"),
  rUsage: $("r-usage"),
  rContentType: $("r-content-type"),
  rHost: $("r-host"),
  rRequestId: $("r-request-id"),
  rChars: $("r-chars"),
  rChunks: $("r-chunks"),
  reqLine: $("req-line"),
  reqAuth: $("req-auth"),
  reqHeaders: $("req-headers"),
  reqBody: $("req-body"),
  singlePanel: $("single-panel"),
  suitePanel: $("suite-panel"),
  suiteMeta: $("suite-meta"),
  sPass: $("s-pass"),
  sFail: $("s-fail"),
  sSkip: $("s-skip"),
  sRun: $("s-run"),
  sProgress: $("s-progress"),
  caseList: $("case-list"),
  suiteFoot: $("suite-foot"),
  exportMd: $("export-md"),
  exportCsv: $("export-csv"),
  standardVersion: $("standard-version"),
};

/* ------------------------------------------------------------------ boot */
async function loadStandards() {
  try {
    const data = await api("/api/standards");
    const options = ['<option value="">不绑定标准</option>'];
    for (const version of data.versions) {
      options.push(
        `<option value="${version.id}">v${version.id} · ${version.version} · ${version.item_count} 项（${version.checksum}）</option>`
      );
    }
    F.standardVersion.innerHTML = options.join("");
  } catch (err) {
    F.standardVersion.innerHTML = '<option value="">标准加载失败</option>';
  }
}

async function boot() {
  bindTabs();
  bindActions();
  loadStandards();

  try {
    state.meta = await api("/api/meta");
  } catch (err) {
    toast(err.message, "error");
    return;
  }
  state.adapters = state.meta.adapters;
  fillAdapters();
  applyLimits();

  await loadProviders();
  await loadModelGroups();
  bindForm();
}

function bindTabs() {
  document.querySelectorAll(".tabs [data-tab]").forEach((button) => {
    button.addEventListener("click", () => setMode(button.dataset.tab));
  });
}

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll(".tabs [data-tab]").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.tab === mode ? "true" : "false");
  });
  document.querySelectorAll(".single-only").forEach((node) => node.classList.toggle("hidden", mode !== "single"));
  document.querySelectorAll(".suite-only").forEach((node) => node.classList.toggle("hidden", mode !== "suite"));
  F.singlePanel.classList.toggle("hidden", mode !== "single");
  F.suitePanel.classList.toggle("hidden", mode !== "suite");
  F.runBtn.textContent = mode === "single" ? "发送测试请求" : "运行验收套件";
  F.runHint.textContent =
    mode === "single"
      ? "单次测试仅发送 1 个请求；验收套件按链路与重复次数执行完整用例。"
      : "套件执行时间取决于链路数与超时预算，可随时停止；已完成的用例会保留在记录中。";
}

function applyLimits() {
  const limits = state.meta.limits || {};
  F.envBadge.textContent = limits.allow_private_upstream ? "允许内网目标" : "仅公网目标";
  F.envBadge.className = "badge " + (limits.allow_private_upstream ? "skip" : "neutral");

  const runtime = state.meta.runtime_settings || {};
  if (runtime.default_prompt) F.prompt.value = runtime.default_prompt;
  if (runtime.test_repeat) F.repeat.value = runtime.test_repeat;
  if (limits.model_total_timeout) F.totalTimeout.value = limits.model_total_timeout;
  if (limits.model_first_token_timeout) F.firstTimeout.value = limits.model_first_token_timeout;
  if (limits.model_connect_timeout) F.connectTimeout.value = limits.model_connect_timeout;
}

function fillAdapters() {
  F.adapter.replaceChildren();
  state.adapters.forEach((adapter) => {
    const option = el("option", null, `${adapter.label}（${adapter.id}）`);
    option.value = adapter.id;
    F.adapter.appendChild(option);
  });
  applyAdapter();
}

function applyAdapter() {
  const adapter = state.adapters.find((item) => item.id === F.adapter.value);
  if (!adapter) return;
  F.adapterNote.textContent = adapter.protocols.join(" · ");
  const previous = F.authStyle.value;
  F.authStyle.replaceChildren();
  adapter.auth_styles.forEach((style) => {
    const option = el("option", null, style);
    option.value = style;
    F.authStyle.appendChild(option);
  });
  if (adapter.auth_styles.includes(previous)) F.authStyle.value = previous;
  $("fetch-models").disabled = !adapter.supports_models_list;
  // 换协议/端点后，上一批模型清单不再可信：直接收起来，避免误填到别的渠道。
  if (state.models && state.models.length) {
    state.models = [];
    $("model-picker").classList.add("hidden");
  }
  $("model-hint").textContent = adapter.parameter_notes || "模型 ID 需按供应商实际支持填写。";
}

/** 把取回的模型清单渲染成可见面板：datalist 只在输入时弹，几十个模型等于看不见。 */
function renderModelPicker(items, keyword = "") {
  const panel = $("model-picker");
  const list = $("model-picker-list");
  if (!panel || !list) return;
  const kw = String(keyword || "").trim().toLowerCase();
  const matches = kw ? items.filter((id) => String(id).toLowerCase().includes(kw)) : items;
  list.replaceChildren();
  if (!matches.length) {
    list.appendChild(el("span", "hint", "没有匹配的模型 ID"));
  }
  matches.slice(0, 300).forEach((id) => {
    const chip = el("button", "model-chip", String(id));
    chip.type = "button";
    chip.dataset.testid = "t-console-model-chip";
    chip.dataset.model = id;
    if (F.model.value === id) chip.classList.add("is-active");
    chip.addEventListener("click", () => {
      F.model.value = id;
      list.querySelectorAll(".model-chip").forEach((node) => node.classList.remove("is-active"));
      chip.classList.add("is-active");
      toast(`已填入模型 ${id}`, "ok");
    });
    list.appendChild(chip);
  });
  const count = $("model-picker-count");
  if (count) {
    count.textContent = kw
      ? `共 ${items.length} 个，匹配 ${matches.length} 个`
      : `共 ${items.length} 个模型 ID，点击填入`;
  }
  panel.classList.remove("hidden");
}

function bindModelPicker() {
  const panel = $("model-picker");
  if (!panel) return;
  $("model-picker-close").addEventListener("click", () => panel.classList.add("hidden"));
  $("model-picker-filter").addEventListener("input", (event) => {
    renderModelPicker(state.models || [], event.target.value);
    panel.classList.remove("hidden");
  });
}

function bindForm() {
  bindModelPicker();
  F.adapter.addEventListener("change", applyAdapter);
  F.authStyle.addEventListener("change", () => {
    const none = F.authStyle.value === "none";
    F.apiKey.disabled = none;
    F.apiKey.placeholder = none ? "该方式无需密钥" : "sk-…";
    if (none) F.apiKey.value = "";
  });

  F.provider.addEventListener("change", () => applyProvider(F.provider.value));
  F.linkForward.addEventListener("change", () => {
    F.forwardFields.classList.toggle("hidden", !F.linkForward.checked);
  });
}

function applyProvider(id) {
  const provider = state.providers.find((item) => item.id === id);
  if (!provider) return;
  F.adapter.value = provider.adapter;
  applyAdapter();
  F.baseUrl.value = provider.direct_base_url || "";
  F.forwardBase.value = provider.forward_base_url || "";
  if (provider.default_model && !F.model.value) F.model.value = provider.default_model;
  if (provider.auth_style) F.authStyle.value = provider.auth_style;
  // 版本号位置是 **provider 级的协议变体**（Bedrock invoke_model 用 body，
  // Anthropic 直连用 header），不在任务表单里重复问一次；提交时从 provider 取。
  state.currentProvider = provider;
}

// ---------------------------------------------------------------- 批量模型组
// 组清单来自 /api/models/groups，只是常见 ID 的提示，不是白名单。
// 勾选后提交会为每个模型各建一个任务（后端顺序执行，避免 RPM 限流）。

function renderModelGroups(groups) {
  const box = $("model-groups");
  if (!box) return;
  box.replaceChildren();
  if (!groups.length) {
    box.appendChild(el("p", "hint", "未能加载模型组，可手动填写上方模型 ID。"));
    return;
  }
  groups.forEach((g) => {
    const wrap = el("div", "model-group");
    const head = el("label", "model-group-head");
    const all = el("input");
    all.type = "checkbox";
    head.appendChild(all);
    head.appendChild(document.createTextNode(g.label || g.id));
    wrap.appendChild(head);

    const items = el("div", "model-group-items");
    (g.models || []).forEach((m) => {
      const row = el("label", "model-item");
      const cb = el("input");
      cb.type = "checkbox";
      cb.value = m;
      cb.dataset.model = m;
      row.appendChild(cb);
      row.appendChild(document.createTextNode(m));
      items.appendChild(row);
    });
    wrap.appendChild(items);
    box.appendChild(wrap);

    all.addEventListener("change", () => {
      items.querySelectorAll('input[type="checkbox"]').forEach((c) => {
        c.checked = all.checked;
      });
    });
  });
}

/** 已勾选的模型（去重、去空）。 */
function selectedModels() {
  const seen = new Set();
  const out = [];
  document.querySelectorAll("#model-groups input[data-model]:checked").forEach((c) => {
    const v = (c.value || "").trim();
    if (v && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  });
  return out;
}

async function loadModelGroups() {
  try {
    const data = await api("/api/models/groups");
    renderModelGroups(data.groups || []);
  } catch (err) {
    const box = $("model-groups");
    if (box) box.replaceChildren(el("p", "hint", "模型组加载失败：" + err.message));
  }
}

async function loadProviders() {
  const data = await api("/api/providers");
  state.providers = data.items || [];
  F.provider.replaceChildren();
  state.providers
    .filter((item) => item.enabled)
    .forEach((provider) => {
      const option = el("option", null, provider.name);
      option.value = provider.id;
      F.provider.appendChild(option);
    });
  if (state.providers.length) {
    applyProvider(F.provider.value);
  }
}

function bindActions() {
  $("reload-providers").addEventListener("click", async () => {
    try {
      await loadProviders();
      toast("供应商列表已刷新", "ok");
    } catch (err) {
      toast(err.message, "error");
    }
  });

  F.toggleKey.addEventListener("click", () => {
    const visible = F.apiKey.type === "text";
    F.apiKey.type = visible ? "password" : "text";
    F.toggleKey.textContent = visible ? "显示" : "隐藏";
  });

  $("fetch-models").addEventListener("click", async () => {
    const baseUrl = F.baseUrl.value.trim();
    if (!baseUrl) {
      toast("请先填写 Endpoint", "error");
      return;
    }
    const button = $("fetch-models");
    button.disabled = true;
    try {
      const data = await api("/api/models/list", {
        method: "POST",
        body: {
          provider_id: F.provider.value,
          base_url: baseUrl,
          adapter: F.adapter.value,
          auth_style: F.authStyle.value,
          api_key: F.apiKey.value,
        },
      });
      const items = data.items || [];
      state.models = items;
      F.modelOptions.replaceChildren();
      items.forEach((id) => {
        const option = el("option");
        option.value = id;
        F.modelOptions.appendChild(option);
      });
      renderModelPicker(items);
      if (!F.model.value && items.length) F.model.value = items[0];
      const hint = $("model-hint");
      if (hint) {
        hint.textContent = items.length
          ? `已从上游获取 ${items.length} 个模型 ID，点下方列表任一模型即可填入。`
          : "上游没有返回任何模型 ID，请手动填写。";
      }
      toast(`已从上游获取 ${data.count} 个模型 ID`, "ok");
    } catch (err) {
      toast(err.message, "error");
    } finally {
      button.disabled = false;
      F.apiKey.value = "";
    }
  });

  document.getElementById("test-form").addEventListener("submit", onSubmit);
  F.exportMd.addEventListener("click", (event) => {
    if (!state.runId) event.preventDefault();
  });
  F.exportCsv.addEventListener("click", (event) => {
    if (!state.runId) event.preventDefault();
  });
}

/* --------------------------------------------------------------- payload */
// 请求间隔：允许 0（不限速），空值按默认 2s。
// 不能用 `|| 2` 兜底——那会把用户填的 0 悄悄改成 2。
function toInterval(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return 2;
  const value = Number(text);
  if (!Number.isFinite(value)) return 2;
  return Math.min(30, Math.max(0, value));
}

function collect() {
  const payload = {
    provider_id: F.provider.value,
    adapter: F.adapter.value,
    link: F.link.value,
    base_url: F.baseUrl.value.trim(),
    model: F.model.value.trim(),
    auth_style: F.authStyle.value,
    version_in_body: Boolean(state.currentProvider && state.currentProvider.version_in_body),
    api_version: (state.currentProvider && state.currentProvider.api_version) || "",
    // 批量模型：每个模型后端各建一个任务（顺序执行）。空数组 = 只跑上面的主模型。
    models: selectedModels(),
    api_key: F.apiKey.value,
    system: F.system.value,
    prompt: F.prompt.value,
    max_tokens: Number(F.maxTokens.value || 32),
    temperature: F.temperature.value === "" ? null : Number(F.temperature.value),
    stream: F.streamMode.checked,
    stream_usage: F.streamUsage.checked,
    total_timeout: Number(F.totalTimeout.value || 60),
    connect_timeout: Number(F.connectTimeout.value || 10),
    first_token_timeout: Number(F.firstTimeout.value || 30),
  };

  if (!payload.base_url) throw new Error("请填写 Endpoint");
  if (!payload.model) throw new Error("请填写模型 ID");
  if (!payload.api_key && F.authStyle.value !== "none") throw new Error("请填写 API Key");

  if (state.mode === "suite") {
    const links = [];
    if (F.linkDirect.checked) links.push("direct");
    if (F.linkForward.checked) links.push("forward");
    if (!links.length) throw new Error("请至少选择一条测试链路");
    Object.assign(payload, {
      links,
      repeat: Number(F.repeat.value || 3),
      // 0 是合法值（不限速），不能用 || 兜底
      request_interval: toInterval(F.interval.value),
      forward_base_url: F.forwardBase.value.trim(),
      forward_model: F.forwardModel.value.trim(),
      forward_api_key: F.forwardKey.value,
      mock_no_content_url: F.mockNoContent.value.trim(),
      mock_heartbeat_url: F.mockHeartbeat.value.trim(),
      unreachable_url: F.unreachable.value.trim(),
    });
    if (F.standardVersion.value) payload.standard_version_id = Number(F.standardVersion.value);
    if (links.includes("forward") && !payload.forward_base_url) {
      throw new Error("已选择转发链路，请填写转发地址");
    }
  }
  return payload;
}

async function onSubmit(event) {
  event.preventDefault();
  if (state.busy) {
    if (state.mode === "suite" && state.controller) {
      state.controller.abort();
      toast("已请求停止，等待当前用例收尾");
    }
    return;
  }

  let payload;
  try {
    payload = collect();
  } catch (err) {
    toast(err.message, "error");
    return;
  }

  setBusy(true);
  state.controller = new AbortController();
  try {
    if (state.mode === "single") {
      resetResult();
      if (payload.stream) await runStreaming(payload);
      else await runOnce(payload);
    } else {
      await runSuite(payload);
    }
  } catch (err) {
    if (err.name === "AbortError") {
      toast("已停止", "info");
    } else {
      showError(err.message || "请求失败");
      toast(err.message || "请求失败", "error");
    }
  } finally {
    setBusy(false);
    // credentials are never kept in the form after a submission
    F.apiKey.value = "";
    F.forwardKey.value = "";
    state.controller = null;
  }
}

function setBusy(busy) {
  state.busy = busy;
  F.runBtn.disabled = false;
  if (busy) {
    F.runBtn.textContent = state.mode === "suite" ? "停止运行" : "请求中…";
    F.runBtn.classList.toggle("btn-danger", state.mode === "suite");
    F.runBtn.classList.toggle("btn-primary", state.mode !== "suite");
  } else {
    F.runBtn.textContent = state.mode === "single" ? "发送测试请求" : "运行验收套件";
    F.runBtn.classList.remove("btn-danger");
    F.runBtn.classList.add("btn-primary");
  }
}

/* ------------------------------------------------------------ single run */
function resetResult() {
  F.answer.textContent = "";
  F.resultError.classList.add("hidden");
  F.resultMeta.textContent = "请求中…";
  [F.rHttp, F.rLatency, F.rTtft].forEach((node) => {
    node.textContent = "—";
    node.className = "v muted";
  });
  F.rVerdict.textContent = "…";
  F.rVerdict.className = "v muted";
  [F.rModel, F.rFinish, F.rUsage, F.rContentType, F.rHost, F.rRequestId, F.rChars, F.rChunks].forEach((node) => {
    node.textContent = "—";
  });
  F.reqLine.textContent = "—";
  F.reqAuth.textContent = "—";
  F.reqHeaders.textContent = "—";
  F.reqBody.textContent = "—";
}

function formatUsage(usage) {
  if (!usage || !Object.keys(usage).length) return "—";
  return Object.entries(usage)
    .map(([key, value]) => `${key}=${value}`)
    .join("   ");
}

function renderResult(data) {
  F.rHttp.textContent = data.http_status || "—";
  F.rHttp.className = "v " + (data.http_status && data.http_status < 400 ? "ok" : "bad");
  F.rLatency.textContent = formatMs(data.latency_ms);
  F.rTtft.textContent = data.ttft_ms === null || data.ttft_ms === undefined ? "—" : formatMs(data.ttft_ms);
  F.rVerdict.textContent = data.ok ? "成功" : "失败";
  F.rVerdict.className = "v " + (data.ok ? "ok" : "bad");
  F.rVerdict.dataset.status = data.ok ? "ok" : "fail";
  F.answer.textContent = data.text || (data.ok ? "" : "（无响应正文）");
  F.rModel.textContent = data.reported_model || "未返回";
  F.rFinish.textContent = data.finish_reason || "—";
  F.rUsage.textContent = formatUsage(data.usage);
  F.rContentType.textContent = data.content_type || "—";
  F.rHost.textContent = data.endpoint_host || "—";
  F.rRequestId.textContent = data.request_id || "—";
  F.rChars.textContent = data.answer_chars ?? (data.text ? data.text.length : 0);
  F.rChunks.textContent = data.chunk_count ?? "—";
  F.resultMeta.textContent = `${data.model || ""} · ${data.link === "forward" ? "转发链路" : "上游直连"}`;

  const req = data.request || {};
  F.reqLine.textContent = req.method ? `${req.method} ${req.url}` : "—";
  F.reqAuth.textContent = (req.auth_headers || []).length
    ? req.auth_headers.map((name) => `${name}: ***`).join("    ")
    : "未发送认证头";
  F.reqHeaders.textContent =
    Object.entries(req.headers || {})
      .map(([name, value]) => `${name}: ${value}`)
      .join("    ") || "—";
  F.reqBody.textContent =
    req.body && Object.keys(req.body).length ? JSON.stringify(req.body, null, 2) : "（无请求体）";

  if (data.error_code || data.error_message) {
    showError(`[${data.error_code || "error"}] ${data.error_message || ""}`);
  }
}

function showError(message) {
  F.resultError.textContent = message;
  F.resultError.dataset.state = "error";
  F.resultError.classList.remove("hidden");
}

async function runOnce(payload) {
  const data = await api("/api/test/run", { method: "POST", body: payload });
  renderResult(data);
  if (data.ok) toast("请求成功", "ok");
}

async function runStreaming(payload) {
  let chars = 0;
  let started = performance.now();
  await streamRequest("/api/test/stream", payload, {
    signal: state.controller.signal,
    onEvent: (event, data) => {
      if (event === "start") {
        F.resultMeta.textContent = `流式 · ${data.model}`;
        F.rTtft.textContent = "等待首内容…";
      } else if (event === "delta") {
        chars += (data.text || "").length;
        F.answer.textContent += data.text || "";
        F.answer.scrollTop = F.answer.scrollHeight;
        if (F.rTtft.textContent === "等待首内容…") {
          F.rTtft.textContent = formatMs(Math.round(performance.now() - started));
        }
      } else if (event === "usage") {
        F.rUsage.textContent = formatUsage(data.usage);
      } else if (event === "error") {
        showError(`[${data.code || "stream_error"}] ${data.message || ""}`);
      } else if (event === "done") {
        renderResult({
          ...data,
          text: F.answer.textContent,
          model: payload.model,
          link: payload.link,
          answer_chars: chars,
        });
      }
    },
  });
}

/* ------------------------------------------------------------- suite run */
function resetSuite() {
  state.runId = null;
  state.counts = { pass: 0, fail: 0, skip: 0 };
  const building = el("div", "table-empty", "正在建立测试批次…");
  building.dataset.testid = "t-console-empty";
  F.caseList.replaceChildren(building);
  F.sPass.textContent = "0";
  F.sFail.textContent = "0";
  F.sSkip.textContent = "0";
  F.sRun.textContent = "—";
  F.suiteMeta.textContent = "运行中…";
  F.sProgress.style.width = "2%";
  F.exportMd.setAttribute("aria-disabled", "true");
  F.exportCsv.setAttribute("aria-disabled", "true");
  F.exportMd.setAttribute("href", "#");
  F.exportCsv.setAttribute("href", "#");
}

function appendCase(item) {
  if (F.caseList.querySelector(".table-empty")) F.caseList.replaceChildren();
  const row = el("div", "case-row");
  row.dataset.testid = "t-console-row";
  row.dataset.caseId = item.case_id;
  row.dataset.result = item.result;
  row.appendChild(el("span", "cid", item.case_id));
  const body = el("div");
  body.appendChild(el("div", null, item.title));
  if (item.evidence) body.appendChild(el("div", "ev", item.evidence));
  row.appendChild(body);
  const badge = el("span", `badge ${item.result === "PASS" ? "pass" : item.result === "FAIL" ? "fail" : "skip"}`, item.result);
  row.appendChild(badge);
  F.caseList.appendChild(row);
  F.caseList.scrollTop = F.caseList.scrollHeight;

  if (item.result === "PASS") state.counts.pass += 1;
  else if (item.result === "FAIL") state.counts.fail += 1;
  else state.counts.skip += 1;
  F.sPass.textContent = String(state.counts.pass);
  F.sFail.textContent = String(state.counts.fail);
  F.sSkip.textContent = String(state.counts.skip);

  const total = state.counts.pass + state.counts.fail + state.counts.skip;
  F.suiteMeta.textContent = `运行中 · 已执行 ${total} 条`;
  F.sProgress.style.width = `${Math.min(95, 4 + total * 2.4)}%`;
}

async function runSuite(payload) {
  resetSuite();
  await streamRequest("/api/suite/run", payload, {
    signal: state.controller.signal,
    onEvent: (event, data) => {
      if (event === "start") {
        state.runId = data.run_id;
        F.sRun.textContent = `#${data.run_id}`;
        F.suiteMeta.textContent = `${data.provider} · ${data.model} · ${data.links.join(" + ")}`;
      } else if (event === "case") {
        appendCase(data);
      } else if (event === "conclusion") {
        F.suiteMeta.textContent = `完成 · 标准 ${data.standard_version} · ${data.verdict}`;
        F.suiteFoot.innerHTML = `批次 #${data.run_id} 判定：<strong>${data.verdict}</strong>（${data.reason}）。前往 <a href="/records?run=${data.run_id}">验收记录</a> 补充人工确认并导出 PDF 报告。`;
      } else if (event === "done") {
        state.runId = data.run_id;
        F.sRun.textContent = `#${data.run_id}`;
        F.suiteMeta.textContent = `完成 · PASS ${data.passed} / FAIL ${data.failed} / SKIP ${data.skipped}`;
        F.suiteFoot.textContent = `批次 #${data.run_id} 已保存，可导出记录或前往验收记录查看。`;
        F.sProgress.style.width = "100%";
        F.exportMd.setAttribute("aria-disabled", "false");
        F.exportCsv.setAttribute("aria-disabled", "false");
        F.exportMd.setAttribute("href", `/api/suite/runs/${data.run_id}/export?format=md`);
        F.exportCsv.setAttribute("href", `/api/suite/runs/${data.run_id}/export?format=csv`);
        if (data.failed > 0) toast(`套件完成，${data.failed} 条用例未通过`, "error");
        else toast("套件完成，无失败用例", "ok");
      } else if (event === "error") {
        showError(data.message || "套件执行失败");
        toast(data.message || "套件执行失败", "error");
      }
    },
  });
}

boot();
