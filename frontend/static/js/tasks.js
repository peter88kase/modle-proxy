/* 自动验收任务页：创建任务、轮询进度、查看判定、单项重测、人工确认与证据上传。
 *
 * 安全约定：API Key 只存在于输入框和本次请求的 JSON 里，不写入 localStorage /
 * sessionStorage / IndexedDB，也不缓存到模块变量；用完立即清空输入框。 */

import { api, toast, $, el, setPageError, formatMs } from "/static/js/app.js";

const state = {
  adapters: [],
  standards: [],
  statusLabels: {},
  tasks: [],
  taskId: null,
  selectedModel: "",
  detail: null,
  itemSignature: "",
  timer: null,
  keyResolver: null,
  manualItem: null,
  // 多选删除：只存任务 id，列表刷新后按 id 恢复勾选状态
  selected: new Set(),
  // 后端可见的真实任务总数（不受 limit 影响）。列表只拉最近 50 条，
  // 删除全部时必须按这个数说影响范围，否则会把“删 205 条”说成“删 50 条”。
  total: 0,
};

const STATUS_BADGE = {
  pass: "pass",
  fail: "fail",
  blocked: "blocked",
  pending: "pending",
  not_tested: "not-tested",
  undefined: "undefined",
  not_applicable: "na",
};

const TASK_BADGE = {
  running: "run",
  queued: "run",
  succeeded: "pass",
  failed: "fail",
  cancelled: "skip",
  interrupted: "skip",
};

// 请求间隔：允许 0（不限速），空值按默认 2s。
// 不能用 `|| 2` 兜底——那会把用户填的 0 悄悄改成 2。
function intervalValue(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return 2;
  const value = Number(text);
  if (!Number.isFinite(value)) return 2;
  return Math.min(30, Math.max(0, value));
}

function fmtTime(value) {
  if (!value) return "—";
  return String(value).replace("T", " ").replace("+08:00", "");
}

function short(text, limit) {
  const value = String(text || "").replace(/\s+/g, " ").trim();
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function badge(text, kind) {
  const node = el("span", `badge ${kind || "neutral"}`, text);
  return node;
}

/* ------------------------------------------------------------------ 初始化 */
// ---------------------------------------------------------------- 常用模型组
// 组清单来自 /api/models/groups，只是常见 ID 的提示，不是白名单。
// 勾选只把模型 ID 追加到模型输入框；多个模型最终提交到同一个任务。

function parseModelInput(text) {
  const seen = new Set();
  const out = [];
  String(text || "")
    .split(/[\s,，、;；]+/)
    .map((v) => v.trim())
    .filter(Boolean)
    .forEach((v) => {
      if (!seen.has(v)) {
        seen.add(v);
        out.push(v);
      }
    });
  return out;
}

function setModelInput(models) {
  const box = $("t-model");
  if (box) box.value = models.join(", ");
}

/** 组头复选框状态：全选 / 半选 / 未选，必须与子项一致。 */
function updateGroupState(all, boxes) {
  if (!all) return;
  const checked = boxes.filter((c) => c.checked).length;
  all.checked = boxes.length > 0 && checked === boxes.length;
  all.indeterminate = checked > 0 && checked < boxes.length;
}

/** 手工编辑模型输入框后，把勾选状态同步回模型组（含组头三态）。 */
function syncGroupChecks() {
  const chosen = new Set(parseModelInput($("t-model").value));
  document.querySelectorAll("#t-model-groups .model-group").forEach((wrap) => {
    const all = wrap.querySelector(".model-group-head input[type='checkbox']");
    const boxes = Array.from(wrap.querySelectorAll("input[data-model]"));
    boxes.forEach((c) => {
      c.checked = chosen.has(c.value);
    });
    updateGroupState(all, boxes);
  });
}

function renderModelGroups(groups) {
  const box = $("t-model-groups");
  if (!box) return;
  box.replaceChildren();
  if (!groups.length) {
    box.appendChild(el("p", "hint", "未能加载模型组，可只填上方模型 ID。"));
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
      cb.addEventListener("change", () => {
        const chosen = parseModelInput($("t-model").value);
        if (cb.checked && !chosen.includes(m)) chosen.push(m);
        if (!cb.checked) {
          const index = chosen.indexOf(m);
          if (index >= 0) chosen.splice(index, 1);
        }
        setModelInput(chosen);
        updateGroupState(all, Array.from(items.querySelectorAll("input[data-model]")));
      });
      row.appendChild(cb);
      row.appendChild(document.createTextNode(m));
      items.appendChild(row);
    });
    wrap.appendChild(items);
    box.appendChild(wrap);

    // 组头勾选/取消：先把子项改成同一状态，再逐个触发 change（子项处理器负责写输入框）。
    // 这里必须先 set 再 dispatch：只 dispatch 不改状态的话，"取消全选"永远无效。
    // 也刻意**不**在 wrap 上挂 click → syncGroupChecks：checkbox 的 change 是在
    // click 冒泡**之后**才触发的，那个监听会抢先把刚勾上的子项按旧输入框重置掉，
    // 表现就是"点了没反应、组头却显示已勾选"。
    all.addEventListener("change", () => {
      const target = all.checked;
      const boxes = Array.from(items.querySelectorAll("input[data-model]"));
      boxes.forEach((c) => {
        c.checked = target;
      });
      boxes.forEach((c) => c.dispatchEvent(new Event("change")));
      updateGroupState(all, boxes);
    });
  });
  syncGroupChecks();
}

/** 已填写的模型（去重、去空）；多个模型放进同一个任务。 */
function selectedModels() {
  return parseModelInput($("t-model").value);
}

async function loadModelGroups() {
  try {
    const data = await api("/api/models/groups");
    renderModelGroups(data.groups || []);
  } catch (err) {
    const box = $("t-model-groups");
    if (box) box.replaceChildren(el("p", "hint", "模型组加载失败：" + err.message));
  }
}

async function boot() {
  bindEvents();
  loadModelGroups();
  try {
    const meta = await api("/api/meta");
    state.adapters = meta.adapters || [];
    fillAdapters();
  } catch (err) {
    toast(err.message, "error");
  }
  try {
    const data = await api("/api/standards");
    state.standards = data.versions || [];
    fillStandards();
  } catch (err) {
    toast(`测试标准加载失败：${err.message}`, "error");
  }
  await loadList();
  const wanted = new URLSearchParams(window.location.search).get("task");
  if (wanted) openDetail(Number(wanted));
  state.timer = window.setInterval(tick, 3000);
}

function fillAdapters() {
  const select = $("t-adapter");
  select.innerHTML = '<option value="">请选择协议</option>';
  for (const adapter of state.adapters) {
    select.appendChild(new Option(`${adapter.label}（${adapter.id}）`, adapter.id));
  }
  const type = $("t-type");
  type.innerHTML = '<option value="bearer">Bearer Token</option><option value="x-api-key">x-api-key</option><option value="api-key">api-key（Gemini）</option>';
}

function fillStandards() {
  const select = $("t-standard");
  select.innerHTML = "";
  for (const version of state.standards) {
    select.appendChild(new Option(`v${version.id} · ${version.version} · ${version.item_count} 项`, version.id));
  }
  if (!state.standards.length) select.appendChild(new Option("没有可用标准", ""));
}

/* ------------------------------------------------------------------ 任务列表 */
/** 删除任务（连带执行记录与证据目录）。后端要求 admin，且运行中的任务会 409。 */
async function deleteTask(task) {
  const label = `TASK-${String(task.id).padStart(3, "0")}`;
  const ok = window.confirm(
    `删除 ${label}？\n\n` +
      `· 会一并删除该任务的执行记录与证据文件，不可恢复\n` +
      `· 需要管理员权限`
  );
  if (!ok) return;
  try {
    await api(`/api/tasks/${task.id}`, { method: "DELETE" });
    toast(`${label} 已删除`, "ok");
    state.selected.delete(task.id);
    // 删的是当前打开的详情就收起面板，否则详情会指向一个不存在的任务。
    if (state.taskId === task.id) {
      state.taskId = null;
      state.detail = null;
      $("detail-panel").classList.add("hidden");
    }
    await loadList();
  } catch (err) {
    if (err.status === 403) {
      toast("删除任务需要管理员权限", "error");
    } else if (err.status === 409) {
      toast("任务正在执行，先停止再删除", "error");
    } else {
      toast(`删除失败：${err.message}`, "error");
    }
  }
}

/* -------------------------------------------------------- 多选与批量删除 */
/** 运行中/排队中的任务后端会 409 拒绝删除，前端统一按“不可选”处理。 */
function isSelectable(task) {
  return task.status !== "running" && task.status !== "queued";
}

function selectableTasks() {
  return state.tasks.filter(isSelectable);
}

/** 全选框三态、已选文案、删除选中按钮的可用性，都在这里统一算。 */
function syncSelectionUi() {
  // 只保留仍在列表里且可选中的 id：否则会出现“选中了 N 项，但列表里一个都没勾”
  const visible = new Set(selectableTasks().map((task) => task.id));
  for (const id of [...state.selected]) {
    if (!visible.has(id)) state.selected.delete(id);
  }
  const total = visible.size;
  const count = state.selected.size;
  const all = $("task-check-all");
  if (all) {
    all.disabled = total === 0;
    all.checked = total > 0 && count === total;
    all.indeterminate = count > 0 && count < total;
  }
  const label = $("task-selected");
  if (label) label.textContent = count ? `已选 ${count} 项` : "未选择";
  const delBtn = $("task-delete-selected");
  if (delBtn) delBtn.disabled = count === 0;
}

function handleBulkDeleteError(err) {
  if (err.status === 403) {
    toast("批量删除任务需要管理员权限", "error");
  } else if (err.status === 400 && err.code === "confirm_required") {
    toast("确认词不正确，未执行删除", "error");
  } else if (err.status === 400 && err.code === "empty_selection") {
    toast("没有选中任何任务", "error");
  } else if (err.status === 400 && err.code === "too_many") {
    // 上限以后端为准（MAX_BULK_DELETE），文案里带本次目标数，前端不再硬编码 200
    toast(err.message || "一次删除的任务过多，请分批操作", "error");
  } else {
    toast(`删除失败：${err.message}`, "error");
  }
}

/** 批量删除成功后的收尾：清选择、按需收起详情、提示跳过项、刷新列表。 */
async function finishBulkDelete(data) {
  const deleted = Array.isArray(data.deleted) ? data.deleted : [];
  state.selected.clear();
  if (state.taskId !== null && deleted.includes(state.taskId)) {
    state.taskId = null;
    state.detail = null;
    $("detail-panel").classList.add("hidden");
  }
  const skipped = Array.isArray(data.skipped_running) ? data.skipped_running : [];
  const missing = Array.isArray(data.skipped_missing) ? data.skipped_missing : [];
  if (skipped.length) toast(`${skipped.length} 个任务正在执行，已跳过`, "error");
  if (missing.length) toast(`${missing.length} 个任务已不存在或无权删除，已跳过`, "error");
  toast(`已删除 ${deleted.length} 个任务`, "ok");
  await loadList();
}

async function deleteSelected() {
  const ids = [...state.selected];
  if (!ids.length) {
    toast("请先勾选要删除的任务", "error");
    return;
  }
  const ok = window.confirm(
    `删除选中的 ${ids.length} 个任务？\n\n` +
      `· 会一并删除这些任务的执行记录与证据文件，不可恢复\n` +
      `· 正在执行的任务会被跳过（先停止再删除）\n` +
      `· 需要管理员权限`
  );
  if (!ok) return;
  const button = $("task-delete-selected");
  if (button) button.disabled = true;
  try {
    const data = await api("/api/tasks/bulk-delete", { method: "POST", body: { task_ids: ids } });
    await finishBulkDelete(data);
  } catch (err) {
    handleBulkDeleteError(err);
  } finally {
    syncSelectionUi();
  }
}

async function deleteAll() {
  // 必须用后端返回的真实总数：state.tasks 只有最近 50 条，
  // 用它写文案会把“删 205 条”说成“删 50 条”，用户是在说小的数字上按的确认。
  // 拿不到总数就**不执行**：影响范围未知的不可逆操作不允许继续。
  if (!Number.isFinite(state.total)) {
    toast("没有取得任务总数，为避免误删已阻止“删除全部”", "error");
    return;
  }
  const total = state.total;
  if (!total) {
    toast("没有可删除的任务", "error");
    return;
  }
  const shown = state.tasks.length;
  const partial =
    total > shown
      ? `列表只显示最近 ${shown} 条，其余 ${total - shown} 条同样会被删除。\n`
      : "";
  const scope = total > shown ? `库中全部 ${total} 个任务` : `全部 ${total} 个任务`;
  const answer = window.prompt(
    `此操作会删除${scope}且不可恢复（含执行记录与证据文件）。\n` +
      partial +
      `正在执行的任务会被跳过。\n\n请输入 DELETE 确认：`
  );
  if (answer === null) {
    toast("已取消", "info");
    return;
  }
  if (answer.trim() !== "DELETE") {
    toast("确认词不正确，未执行删除", "error");
    return;
  }
  const button = $("task-delete-all");
  if (button) button.disabled = true;
  try {
    const data = await api("/api/tasks/bulk-delete", {
      method: "POST",
      body: { all: true, confirm: "DELETE" },
    });
    await finishBulkDelete(data);
    // 全部删除后当前详情一定不存在了
    state.taskId = null;
    state.detail = null;
    $("detail-panel").classList.add("hidden");
  } catch (err) {
    handleBulkDeleteError(err);
  } finally {
    if (button) button.disabled = false;
    syncSelectionUi();
  }
}

async function loadList() {
  try {
    const data = await api("/api/tasks?limit=50");
    state.tasks = data.items || [];
    // total 是“当前身份可见的全部任务数”，**只有后端明确给了才认**。
    // 绝不退回 data.items.length：那会把“未知的影响范围”猜成“本页这 50 条”，
    // 而删除全部是不可逆操作，宁可禁用按钮也不能用一个猜出来的数字。
    state.total = typeof data.total === "number" ? data.total : null;
    if (data.labels) Object.assign(state.statusLabels, data.labels);
    setPageError("tasks-error", "");
    renderList();
  } catch (err) {
    setPageError("tasks-error", `任务列表加载失败：${err.message}`);
    if (err.status !== 401) toast(`任务列表加载失败：${err.message}`, "error");
  }
}

function renderList() {
  const body = $("task-body");
  body.innerHTML = "";
  if (!state.tasks.length) {
    const tr = el("tr");
    const td = el("td", "table-empty", "还没有任务。填写上面的表单即可开始第一次自动验收。");
    td.dataset.testid = "t-tasks-empty";
    td.colSpan = 8;
    tr.appendChild(td);
    body.appendChild(tr);
    renderListMeta();
    syncSelectionUi();
    return;
  }
  for (const task of state.tasks) {
    const tr = el("tr");
    tr.dataset.id = String(task.id);
    tr.dataset.testid = "t-tasks-row";
    tr.dataset.taskId = String(task.id);
    tr.dataset.status = task.status;
    if (state.taskId === task.id) tr.className = "is-selected";
    tr.addEventListener("click", () => openDetail(task.id));

    const checkCell = el("td", "check-col");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.dataset.testid = "t-tasks-check-row";
    box.dataset.taskId = String(task.id);
    box.checked = state.selected.has(task.id);
    if (isSelectable(task)) {
      box.setAttribute("aria-label", `选择 TASK-${String(task.id).padStart(3, "0")}`);
    } else {
      box.disabled = true;
      box.title = "任务执行中，先停止再删除";
    }
    // 行上绑了 click → openDetail，复选框必须自己吞掉 click，否则勾选会顺带打开详情
    box.addEventListener("click", (event) => event.stopPropagation());
    box.addEventListener("change", () => {
      if (box.checked) state.selected.add(task.id);
      else state.selected.delete(task.id);
      syncSelectionUi();
    });
    checkCell.appendChild(box);

    const nameCell = el("td");
    nameCell.appendChild(el("div", "mono small", `TASK-${String(task.id).padStart(3, "0")}`));
    nameCell.appendChild(el("div", "task-name", short(task.name, 28)));
    if (task.parent_task_id) nameCell.appendChild(el("div", "small muted", `重测自 #${task.parent_task_id}`));

    const modelCell = el("td");
    const modelList = Array.isArray(task.models) && task.models.length ? task.models : [task.model];
    modelCell.appendChild(el("div", "mono small", short(modelList[0] || "—", 26)));
    modelCell.appendChild(el("div", "small muted",
      modelList.length > 1 ? `${modelList.length} 个模型 · ${task.adapter}` : `${task.adapter} · ${task.link}`));

    const statusCell = el("td");
    statusCell.dataset.testid = "t-tasks-cell-status";
    statusCell.dataset.status = task.status;
    statusCell.appendChild(badge(task.status_label || task.status, TASK_BADGE[task.status] || "neutral"));
    statusCell.appendChild(el("div", "small muted", task.phase_label || ""));

    const progressCell = el("td", "mono small", `${task.progress_done || 0} / ${task.progress_total || 0}`);
    progressCell.dataset.testid = "t-tasks-cell-progress";

    const verdictCell = el("td");
    const verdictText = task.conclusion || "—";
    const verdictKind =
      verdictText === "达标" ? "pass" : verdictText === "不达标" ? "fail" : verdictText === "—" ? "neutral" : "skip";
    verdictCell.dataset.testid = "t-tasks-cell-verdict";
    verdictCell.dataset.verdict = verdictText;
    verdictCell.appendChild(badge(verdictText, verdictKind));

    const timeCell = el("td", "small muted", fmtTime(task.created_at));

    const actionCell = el("td", "actions");
    const openBtn = el("button", "btn btn-sm", "查看");
    openBtn.dataset.testid = "t-tasks-btn-open";
    openBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      openDetail(task.id);
    });
    actionCell.appendChild(openBtn);

    // 执行中的任务不给删除按钮：后端会 409 拒绝（`tasks.is_running`），
    // 前端提前隐藏比点了再报错更清楚。
    if (task.status !== "running" && task.status !== "queued") {
      const delBtn = el("button", "btn btn-sm btn-danger", "删除");
      delBtn.dataset.testid = "t-tasks-btn-delete";
      delBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        deleteTask(task);
      });
      actionCell.appendChild(delBtn);
    }

    tr.append(checkCell, nameCell, modelCell, statusCell, progressCell, verdictCell, timeCell, actionCell);
    body.appendChild(tr);
  }
  renderListMeta();
  syncSelectionUi();
}

/** 列表计数：列表只是“最近 N 条”时必须说清楚，否则用户会以为库里就这么多。 */
function renderListMeta() {
  const shown = state.tasks.length;
  const known = Number.isFinite(state.total);
  const total = known ? state.total : shown;
  const suffix = known && shown > 0 && total > shown ? `（显示最近 ${shown} 条）` : "";
  $("list-meta").textContent = known
    ? `共 ${total} 个任务${suffix}`
    : `共 ${shown} 个任务（总数未知，已停用“删除全部”）`;
  // 总数未知时禁用“删除全部”：不知道会删多少，就不给这个按钮
  const allBtn = $("task-delete-all");
  if (allBtn) allBtn.disabled = !known;
}

/** 渠道指标摘要：没有前置必测数据时显示“—”，不伪造 0。 */
function channelMetricsText(metrics) {
  const latency = (metrics && metrics.latency) || {};
  const cache = (metrics && metrics.cache) || {};
  if (latency.p50_ms === null || latency.p50_ms === undefined) return "—";
  const parts = [
    `中位 ${formatMs(latency.p50_ms)}`,
    `P95 ${formatMs(latency.p95_ms)}`,
    `P5 ${formatMs(latency.p5_ms)}`,
  ];
  if (cache.hit_rate !== null && cache.hit_rate !== undefined) {
    parts.push(`缓存命中 ${cache.hits}/${cache.calls}`);
  }
  return parts.join(" · ");
}

/* ------------------------------------------------------------------ 任务详情 */
async function openDetail(taskId, model = "") {
  state.taskId = taskId;
  state.selectedModel = model || "";
  state.itemSignature = "";
  await refreshDetail(true);
  $("detail-panel").classList.remove("hidden");
  $("detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  renderList();
}

async function refreshDetail(force = false) {
  if (!state.taskId) return;
  let data;
  const query = state.selectedModel ? `?model=${encodeURIComponent(state.selectedModel)}` : "";
  try {
    data = await api(`/api/tasks/${state.taskId}${query}`);
  } catch (err) {
    setPageError("tasks-error", `任务详情加载失败：${err.message}`);
    if (err.status !== 401) toast(`任务详情加载失败：${err.message}`, "error");
    return;
  }
  state.detail = data;
  state.selectedModel = data.selected_model || state.selectedModel;
  renderDetail(data, force);
  if (state.tasks.length) {
    const row = state.tasks.find((t) => t.id === data.task.id);
    if (row) {
      Object.assign(row, data.task);
      renderList();
    }
  }
}


// 多模型批次：列出同批次每个模型的结论，失败的排前面并单独点名。
// 只有真的存在 2 个以上模型时才显示，单模型任务不留空块。
function renderBatch(batch) {
  const block = $("batch-block");
  const body = $("batch-body");
  if (!block || !body) return;
  body.textContent = "";
  if (!batch || !batch.models || batch.models.length < 2) {
    block.classList.add("hidden");
    $("pdf-batch-btn").classList.add("hidden");
    $("batch-failed").textContent = "";
    return;
  }
  block.classList.remove("hidden");
  $("pdf-batch-btn").classList.remove("hidden");

  const failed = (m) => Number((m.counts || {}).fail || 0) > 0 || m.conclusion === "不达标";
  // 失败的排最前，其余保持原顺序
  const ordered = [...batch.models].sort((a, b) => Number(failed(b)) - Number(failed(a)));

  $("batch-meta").textContent = batch.kind === "task"
    ? `同一任务的 ${batch.size} 个模型`
    : `${batch.batch_id} · 共 ${batch.size} 个模型`;
  const failedModels = ordered.filter(failed).map((m) => m.model);
  $("batch-failed").textContent = failedModels.length
    ? `失败的模型：${failedModels.join("、")}`
    : "整批没有不通过项";

  for (const model of ordered) {
    const row = el("tr");
    if (failed(model)) row.classList.add("is-fail");
    if (model.is_current) row.classList.add("is-selected");
    row.append(el("td", "mono", model.model || "—"));
    row.append(el("td", "small", model.status_label || model.status || "—"));
    const verdict = el("td");
    verdict.append(
      badge(model.conclusion || "—", model.conclusion === "达标" ? "pass" : model.conclusion === "不达标" ? "fail" : "skip")
    );
    row.append(verdict);
    const counts = model.counts || {};
    row.append(el("td", "num", String(counts.fail ?? 0)));
    row.append(el("td", "num", String(counts.not_tested ?? 0)));
    row.append(el("td", "num", String(counts.blocked ?? 0)));
    const action = el("td", "actions");
    if (!model.is_current) {
      const open = el("button", "btn btn-sm", "查看");
      open.type = "button";
      open.addEventListener("click", () => openDetail(model.task_id, model.model));
      action.append(open);
    } else {
      action.append(el("span", "small muted", "当前"));
    }
    row.append(action);
    body.append(row);
  }
}

function renderDetail(data, force) {
  const task = data.task;
  $("detail-title").textContent = `TASK-${String(task.id).padStart(3, "0")} · ${task.name}`;
  $("detail-meta").innerHTML = "";
  const modelList = Array.isArray(data.models) && data.models.length ? data.models : [task.model];
  const pairs = [
    ["被测模型", modelList.length > 1
      ? `${data.selected_model || modelList[0]}（共 ${modelList.length} 个：${modelList.join("、")}）`
      : (data.selected_model || task.model)],
    ["接口协议", task.adapter],
    ["端点", task.endpoint_masked || task.endpoint_host],
    ["测试链路", task.link],
    ["执行状态", task.status_label],
    ["标准版本", task.standard_version ? `v${task.standard_version_id} · ${task.standard_version}` : "未绑定"],
    ["开始", fmtTime(task.started_at)],
    ["结束", fmtTime(task.finished_at)],
    ["重测次数", `第 ${task.attempt || 1} 次`],
    ["预算", budgetText(task.budget)],
    // 前置必测量出的渠道指标：中位/P95 延时与缓存命中率，作为该渠道的权重依据。
    ["渠道指标", channelMetricsText(data.metrics)],
    ["结论", task.conclusion || "—"],
    ["停止原因", task.stop_reason || "—"],
  ];
  for (const [label, value] of pairs) {
    const dt = el("dt", null, label);
    const dd = el("dd", null, String(value ?? "—"));
    $("detail-meta").append(dt, dd);
  }

  const total = task.progress_total || 0;
  const done = task.progress_done || 0;
  const percent = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
  $("progress-bar").style.width = `${percent}%`;
  $("progress-text").textContent =
    total > 0 ? `自动执行 ${done} / ${total} 项（${percent}%）` : "尚未开始统计";

  $("counts-row").innerHTML = "";
  const counts = task.counts || {};
  for (const [key, label] of [
    ["pass", "通过"],
    ["fail", "不通过"],
    ["blocked", "阻塞"],
    ["pending", "待确认"],
    ["not_tested", "未测试"],
    ["undefined", "标准未定义"],
    ["not_applicable", "不适用"],
  ]) {
    if (!counts[key] && key !== "pass" && key !== "fail") continue;
    const chip = el("span", `count-chip ${STATUS_BADGE[key] || ""}`);
    chip.append(el("b", null, String(counts[key] || 0)), document.createTextNode(` ${label}`));
    $("counts-row").appendChild(chip);
  }

  $("stop-reason").textContent = task.stop_reason ? `停止/阻塞原因：${task.stop_reason}` : "";

  $("phase-row").innerHTML = "";
  for (const phase of data.phases || []) {
    const node = el("div", `phase-chip ${phase.status}`);
    node.append(el("span", "phase-label", phase.label));
    node.append(el("span", "mono small", `${phase.done}/${phase.total}`));
    $("phase-row").appendChild(node);
  }

  const running = task.status === "running" || task.status === "queued";
  $("cancel-btn").classList.toggle("hidden", !running);
  $("retest-all-btn").classList.toggle("hidden", running);
  $("retest-chapter-btn").classList.toggle("hidden", running);
  if (task.run_id) {
    $("pdf-btn").href = `/api/runs/${task.run_id}/report.pdf`;
    $("pdf-btn").setAttribute("aria-disabled", "false");
    // 整批报告：同一次提交里的所有模型合并成一份 PDF
    $("pdf-batch-btn").href = `/api/runs/${task.run_id}/report.pdf?scope=batch`;
    $("pdf-batch-btn").setAttribute("aria-disabled", "false");
  } else {
    $("pdf-btn").href = "#";
    $("pdf-btn").setAttribute("aria-disabled", "true");
    $("pdf-batch-btn").href = "#";
    $("pdf-batch-btn").setAttribute("aria-disabled", "true");
  }
  renderBatch(data.batch);

  renderStatusFilter(data);
  const signature = (data.entries || [])
    .map((e) => `${e.item_id}:${e.status}:${(e.actual || "").length}`)
    .join("|");
  if (force || signature !== state.itemSignature) {
    state.itemSignature = signature;
    renderItems();
  }
}

function budgetText(budget) {
  if (!budget || !budget.max_requests) return "—";
  return `${budget.used_requests || 0}/${budget.max_requests} 次 · ${Math.round(budget.elapsed_seconds || 0)}/${Math.round(budget.max_seconds || 0)}s`;
}

function renderStatusFilter(data) {
  const select = $("f-status");
  const labels = data.status_labels || state.statusLabels || {};
  const current = select.value;
  select.innerHTML = '<option value="">全部状态</option>';
  for (const [key, label] of Object.entries(labels)) {
    select.appendChild(new Option(label, key));
  }
  select.value = current;
}

function renderItems() {
  const data = state.detail;
  if (!data) return;
  const chapter = $("f-chapter").value;
  const status = $("f-status").value;
  const attention = $("f-attention").checked;
  const attentionSet = new Set(["fail", "blocked", "pending", "not_tested", "undefined"]);
  const body = $("item-body");
  body.innerHTML = "";

  let shown = 0;
  for (const entry of data.entries || []) {
    if (chapter && String(entry.chapter) !== chapter) continue;
    if (status && entry.status !== status) continue;
    if (attention && !attentionSet.has(entry.status)) continue;
    shown += 1;

    const tr = el("tr");
    tr.dataset.testid = "t-tasks-row-item";
    tr.dataset.itemId = entry.item_id;
    tr.dataset.status = entry.status;
    tr.dataset.execution = entry.execution === "auto" ? "auto" : "manual";
    if (entry.status === "fail") tr.className = "is-fail";

    tr.appendChild(el("td", "mono small", entry.item_id));
    tr.appendChild(el("td", "small", `第${entry.chapter}章`));

    const nameCell = el("td");
    nameCell.appendChild(el("div", "small", entry.name));
    nameCell.appendChild(el("div", "small muted", short(entry.criteria || entry.expected, 90)));
    tr.appendChild(nameCell);

    tr.appendChild(el("td", "small", entry.execution === "auto" ? "自动" : "人工"));

    const actualCell = el("td", "small");
    actualCell.textContent = short(entry.actual || entry.reason || "—", 160);
    if (entry.note) actualCell.appendChild(el("div", "small muted", short(entry.note, 100)));
    tr.appendChild(actualCell);

    const statusCell = el("td");
    statusCell.dataset.testid = "t-tasks-cell-item-status";
    statusCell.dataset.status = entry.status;
    statusCell.appendChild(badge(entry.status_label || entry.status, STATUS_BADGE[entry.status] || "neutral"));
    if (entry.operator) statusCell.appendChild(el("div", "small muted", entry.operator));
    tr.appendChild(statusCell);

    const actionCell = el("td", "actions");
    if (entry.execution === "auto" && Number(entry.chapter) > 1) {
      const runBtn = el("button", "btn btn-sm", "立即测试");
      runBtn.dataset.testid = "t-tasks-btn-run-item";
      runBtn.addEventListener("click", () => runSingle(entry.item_id));
      actionCell.appendChild(runBtn);
    }
    const manualBtn = el("button", "btn btn-sm", "人工确认");
    manualBtn.dataset.testid = "t-tasks-btn-manual";
    manualBtn.addEventListener("click", () => openManual(entry));
    actionCell.appendChild(manualBtn);

    const files = (data.evidence || []).filter((item) => item.item_id === entry.item_id);
    if (files.length) {
      const link = el("a", "btn btn-sm", `证据 ${files.length}`);
      link.dataset.testid = "t-tasks-link-evidence";
      link.dataset.itemId = entry.item_id;
      link.href = `/api/tasks/${data.task.id}/evidence/${files[0].id}`;
      link.target = "_blank";
      link.rel = "noopener";
      actionCell.appendChild(link);
    }
    tr.appendChild(actionCell);
    body.appendChild(tr);
  }

  if (!shown) {
    const tr = el("tr");
    const td = el("td", "table-empty", "没有符合筛选条件的测试项。");
    td.dataset.testid = "t-tasks-item-empty";
    td.colSpan = 7;
    tr.appendChild(td);
    body.appendChild(tr);
  }
}

/* ------------------------------------------------------------------ 交互 */
function bindEvents() {
  $("create-btn").addEventListener("click", createTask);
  $("task-check-all").addEventListener("change", (event) => {
    state.selected.clear();
    if (event.target.checked) selectableTasks().forEach((task) => state.selected.add(task.id));
    renderList();
  });
  $("task-delete-selected").addEventListener("click", deleteSelected);
  $("task-delete-all").addEventListener("click", deleteAll);
  $("t-model").addEventListener("input", syncGroupChecks);
  $("detect-btn").addEventListener("click", detectAdapter);
  $("t-forward").addEventListener("change", (event) => {
    $("forward-row").classList.toggle("hidden", !event.target.checked);
  });
  $("f-chapter").addEventListener("change", renderItems);
  $("f-status").addEventListener("change", renderItems);
  $("f-attention").addEventListener("change", renderItems);
  $("cancel-btn").addEventListener("click", cancelTask);
  $("retest-all-btn").addEventListener("click", () => retest("task"));
  $("retest-chapter-btn").addEventListener("click", () => retest("chapter"));
  // close 事件在 <dialog> 上触发且不冒泡，必须监听 dialog 本身
  $("key-dialog").addEventListener("close", () => {
    const dialog = $("key-dialog");
    const value = dialog.returnValue;
    const key = $("key-input").value;
    const forward = $("key-forward").value;
    $("key-input").value = "";
    $("key-forward").value = "";
    const resolver = state.keyResolver;
    state.keyResolver = null;
    if (resolver) resolver(value === "ok" ? { key, forward } : null);
  });
  $("manual-dialog").addEventListener("close", submitManual);
}

function askKey({ title, hint, forward = false }) {
  $("key-title").textContent = title || "需要 API Key";
  $("key-hint").textContent = hint || "平台不保存明文密钥，执行时需重新输入。";
  $("key-forward-field").classList.toggle("hidden", !forward);
  $("key-dialog").showModal();
  return new Promise((resolve) => {
    state.keyResolver = resolve;
  });
}

async function createTask() {
  const baseUrl = $("t-base").value.trim();
  const models = selectedModels();
  const apiKey = $("t-key").value;
  const adapter = $("t-adapter").value;
  const noAuth = $("t-noauth").checked;
  const forward = $("t-forward").checked;
  const message = $("create-msg");

  if (!baseUrl || !models.length) {
    message.textContent = "请先填写接口地址和至少一个模型 ID（多个模型用逗号分隔）";
    return;
  }
  if (!adapter) {
    message.textContent = "请选择接口协议（或点“识别”）";
    return;
  }
  if (!noAuth && !apiKey.trim()) {
    message.textContent = "请填写 API Key，或勾选“该端点无需鉴权”";
    return;
  }
  if (forward && !$("t-fwd-url").value.trim()) {
    message.textContent = "勾选转发链路后必须填写 Fluxlane 地址";
    return;
  }

  const body = {
    name: $("t-name").value.trim(),
    adapter,
    base_url: baseUrl,
    model: models[0],
    // 多个模型放进同一个任务，任务内按顺序执行；不再是“每个模型一个任务”。
    models,
    api_key: apiKey,
    auth_style: $("t-type").value,
    standard_version_id: Number($("t-standard").value) || null,
    options: {
      links: forward ? ["direct", "forward"] : ["direct"],
      forward_base_url: $("t-fwd-url").value.trim(),
      forward_api_key: $("t-fwd-key").value,
      repeat: Number($("t-repeat").value) || 3,
      total_timeout: Number($("t-total").value) || 60,
      first_token_timeout: Number($("t-ttft").value) || 30,
      // 0 是合法值（不限速），不能用 || 兜底
      request_interval: intervalValue($("t-interval").value),
      max_tokens: Number($("t-maxtok").value) || 64,
      cache_tests: $("t-cache").checked,
      capability_tests: $("t-cap").checked,
      no_auth: noAuth,
    },
    budget: {
      max_requests: Number($("t-maxreq").value) || 150,
      max_seconds: Number($("t-maxsec").value) || 900,
    },
  };

  $("create-btn").disabled = true;
  message.textContent = "正在创建任务…";
  try {
    const data = await api("/api/tasks", { method: "POST", body });
    $("t-key").value = "";
    $("t-fwd-key").value = "";
    const count = (data.models || []).length || 1;
    if (count > 1) {
      message.textContent = `已创建 1 个任务，包含 ${count} 个模型，按顺序执行。`;
      toast(`任务已创建，开始依次测试 ${count} 个模型`, "ok");
    } else {
      message.textContent = "任务已创建，正在后台执行。";
      toast("任务已创建，开始自动测试", "ok");
    }
    await loadList();
    await openDetail(data.task.id);
  } catch (err) {
    message.textContent = err.message;
    toast(err.message, "error");
  } finally {
    $("create-btn").disabled = false;
  }
}

async function detectAdapter() {
  const baseUrl = $("t-base").value.trim();
  if (!baseUrl) {
    toast("请先填写接口地址", "error");
    return;
  }
  const button = $("detect-btn");
  button.disabled = true;
  $("detect-hint").textContent = "正在探测…";
  try {
    const data = await api("/api/tasks/detect", {
      method: "POST",
      body: { base_url: baseUrl, api_key: $("t-key").value },
    });
    if (data.adapter) {
      $("t-adapter").value = data.adapter;
      $("detect-hint").textContent = `已识别为 ${data.adapter}`;
    } else {
      $("detect-hint").textContent = data.message || "无法识别，请手动选择协议";
    }
  } catch (err) {
    $("detect-hint").textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

async function cancelTask() {
  if (!state.taskId) return;
  if (!window.confirm("取消后不再发起新请求，已完成的用例结果会保留。确定取消？")) return;
  try {
    await api(`/api/tasks/${state.taskId}/cancel`, { method: "POST", body: {} });
    toast("已请求取消", "ok");
    await refreshDetail(true);
  } catch (err) {
    toast(err.message, "error");
  }
}

async function retest(scope) {
  if (!state.taskId || !state.detail) return;
  let chapter = null;
  if (scope === "chapter") {
    const input = window.prompt("要重测第几章？请输入 1～4", "2");
    if (!input) return;
    chapter = Number(input);
    if (![1, 2, 3, 4].includes(chapter)) {
      toast("章节只能是 1～4", "error");
      return;
    }
  }
  const forward = String(state.detail.task.link || "").includes("forward");
  const answer = await askKey({
    title: scope === "chapter" ? `重测第 ${chapter} 章` : "重测整个任务",
    hint: "重测会创建新任务，历史记录与失败证据保留。",
    forward,
  });
  if (!answer) return;
  if (!answer.key.trim() && !(state.detail.task.options || {}).no_auth) {
    toast("请填写 API Key", "error");
    return;
  }
  try {
    const data = await api(`/api/tasks/${state.taskId}/retest`, {
      method: "POST",
      body: {
        scope,
        chapter,
        api_key: answer.key,
        forward_api_key: answer.forward,
      },
    });
    toast("重测任务已创建", "ok");
    await loadList();
    await openDetail(data.task.id);
  } catch (err) {
    toast(err.message, "error");
  }
}

async function runSingle(itemId) {
  if (!state.taskId) return;
  const forward = String((state.detail.task.link || "")).includes("forward");
  const answer = await askKey({
    title: `重测单项 ${itemId}`,
    hint: "只重跑这一项，不覆盖历史记录（旧判定会记入重测日志）。",
    forward,
  });
  if (!answer) return;
  try {
    const data = await api(`/api/tasks/${state.taskId}/items/${itemId}/run?model=${encodeURIComponent(state.selectedModel || "")}`, {
      method: "POST",
      body: { api_key: answer.key, forward_api_key: answer.forward },
    });
    toast(`${itemId}：${state.statusLabels[data.status] || data.status}`, data.status === "fail" ? "error" : "ok");
    await refreshDetail(true);
  } catch (err) {
    toast(err.message, "error");
  }
}

function openManual(entry) {
  state.manualItem = entry;
  $("manual-item").textContent = entry.item_id;
  $("manual-expected").textContent = `预期/通过标准：${entry.criteria || entry.expected || "—"}`;
  $("manual-status").value = entry.status === "pass" ? "pass" : "pending";
  $("manual-actual").value = entry.actual || "";
  $("manual-note").value = entry.note || "";
  $("manual-file").value = "";
  $("manual-operator").textContent = "当前登录用户";
  $("manual-dialog").showModal();
}

async function submitManual() {
  const dialog = $("manual-dialog");
  if (dialog.returnValue !== "ok" || !state.manualItem) return;
  const entry = state.manualItem;
  const status = $("manual-status").value;
  const actual = $("manual-actual").value.trim();
  const note = $("manual-note").value.trim();
  if (["fail", "not_applicable", "blocked"].includes(status) && !note) {
    toast("标记为不通过 / 不适用 / 阻塞时必须填写说明", "error");
    return;
  }
  try {
    const file = $("manual-file").files[0];
    if (file) {
      if (file.size > 2 * 1024 * 1024) throw new Error("证据文件不能超过 2 MB");
      const content = await fileToBase64(file);
      await api(`/api/tasks/${state.taskId}/evidence`, {
        method: "POST",
        body: { item_id: entry.item_id, filename: file.name, content_base64: content, note: "人工确认附件" },
      });
    }
    const data = await api(`/api/tasks/${state.taskId}/items/${entry.item_id}?model=${encodeURIComponent(state.selectedModel || "")}`, {
      method: "POST",
      body: { status, actual, note },
    });
    toast(`已保存，整体结论：${data.conclusion.verdict}`, "ok");
    await refreshDetail(true);
  } catch (err) {
    toast(err.message, "error");
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(new Error("读取文件失败"));
    reader.readAsDataURL(file);
  });
}

/* ------------------------------------------------------------------ 轮询 */
function tick() {
  if (document.hidden) return;
  const running = state.tasks.some((task) => task.status === "running" || task.status === "queued");
  if (running || !state.tasks.length) loadList();
  if (state.taskId) {
    const current = state.tasks.find((task) => task.id === state.taskId);
    const detailRunning = current && (current.status === "running" || current.status === "queued");
    if (detailRunning || !state.detail || document.activeElement === document.body) refreshDetail();
  }
}

boot();
