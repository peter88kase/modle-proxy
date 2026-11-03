/* 测试标准页：按章节分组展示第 1～4 章测试项，管理员可另存为新版本。 */
import { api, toast, $, el, getSession, setPageError } from "./app.js";

const state = {
  session: null,
  versionId: null,
  version: null,
  edits: new Map(), // item_id -> { enabled?, requirement?, params? }
  dirty: false,
};

const STATUS_TEXT = {
  auto: "自动",
  manual: "人工",
};

/** 页面只保留测试项清单：标准元信息节点已下线，写之前先确认节点存在。 */
function fillText(id, text) {
  const node = $(id);
  if (node) node.textContent = text;
}

function setDirty(value) {
  state.dirty = value;
  document.querySelectorAll("#std-save, #std-save-2").forEach((btn) => {
    btn.textContent = value ? "另存为新版本 *" : "另存为新版本";
  });
}

function markEdit(itemId, patch) {
  const current = state.edits.get(itemId) || {};
  state.edits.set(itemId, { ...current, ...patch });
  setDirty(true);
}

async function loadOverview() {
  const data = await api("/api/standards");
  const select = $("std-version");
  select.innerHTML = data.versions
    .map((v) => `<option value="${v.id}">v${v.id} · ${v.version} · ${v.item_count} 项</option>`)
    .join("");
  if (data.versions.length) {
    select.value = String(data.versions[0].id);
  }
  fillText("std-id", data.standard_id);
  fillText("std-source", data.source_document);
  fillText("std-count", `${data.item_count} 项`);
  return data;
}

function badgeFor(execution) {
  return el("span", `badge ${execution === "auto" ? "pass" : "skip"}`, STATUS_TEXT[execution] || execution);
}

function controlBlock(item, editable) {
  const wrap = el("div", "sctrl");

  const enableRow = el("div", "rowline");
  const enable = document.createElement("input");
  enable.type = "checkbox";
  enable.checked = item.enabled;
  enable.id = `en-${item.id}`;
  enable.dataset.testid = "t-standards-check-enabled";
  enable.dataset.itemId = item.id;
  enable.disabled = !editable;
  enable.addEventListener("change", () => {
    markEdit(item.id, { enabled: enable.checked });
    const node = document.getElementById(`item-${item.id}`);
    if (node) node.classList.toggle("is-disabled", !enable.checked);
  });
  const enableLabel = el("label", null, "启用");
  enableLabel.htmlFor = enable.id;
  enableRow.append(enable, enableLabel);
  wrap.appendChild(enableRow);

  wrap.appendChild(el("div", "ctrl-label", "必测级别"));
  const req = document.createElement("select");
  req.disabled = !editable;
  req.innerHTML = `
    <option value="mandatory">必测项</option>
    <option value="conditional">条件项</option>`;
  req.value = item.requirement;
  req.dataset.testid = "t-standards-select-requirement";
  req.dataset.itemId = item.id;
  req.setAttribute("aria-label", `${item.id} 必测级别`);
  req.addEventListener("change", () => markEdit(item.id, { requirement: req.value }));
  wrap.appendChild(req);

  for (const def of item.param_defs || []) {
    wrap.appendChild(el("div", "ctrl-label", def.label));
    const input = document.createElement("input");
    input.type = "text";
    input.inputMode = "numeric";
    input.value = (item.params && item.params[def.key]) || "";
    input.placeholder = "未配置";
    input.disabled = !editable;
    input.id = `p-${item.id}-${def.key}`;
    input.dataset.testid = "t-standards-input-param";
    input.dataset.itemId = item.id;
    input.dataset.paramKey = def.key;
    input.addEventListener("input", () => {
      const params = { ...(state.edits.get(item.id)?.params || item.params || {}) };
      params[def.key] = input.value.trim();
      markEdit(item.id, { params });
    });
    input.title = def.label;
    wrap.appendChild(input);
  }

  if (!editable) {
    wrap.querySelectorAll("input, select").forEach((node) => {
      node.disabled = true;
    });
  }
  return wrap;
}

function renderItem(item, editable) {
  const node = el("div", "std-item");
  node.id = `item-${item.id}`;
  node.dataset.testid = "t-standards-row";
  node.dataset.itemId = item.id;
  node.dataset.execution = item.execution;
  node.dataset.enabled = item.enabled ? "true" : "false";
  if (!item.enabled) node.classList.add("is-disabled");

  const left = el("div", "sid");
  left.appendChild(el("div", null, item.id));
  left.appendChild(badgeFor(item.execution));
  node.appendChild(left);

  const mid = el("div");
  mid.appendChild(el("div", "sname", item.name));
  const method = el("div", "srow");
  method.append(el("b", null, "方法："), document.createTextNode(item.method || "—"));
  mid.appendChild(method);
  const criteria = el("div", "srow");
  criteria.append(el("b", null, "通过标准："), document.createTextNode(item.criteria || "—"));
  mid.appendChild(criteria);
  node.appendChild(mid);
  node.appendChild(controlBlock(item, editable));
  return node;
}

function renderVersion(version, editable) {
  const host = $("std-chapters");
  host.replaceChildren();

  // 只列测试项：不显示章标题、小节标题与项数统计，顺序沿用标准原文的项顺序。
  const body = el("div", "std-body std-flat");
  for (const item of version.items) body.appendChild(renderItem(item, editable));
  if (version.items.length) host.appendChild(body);

  if (!version.items.length) {
    const empty = el("p", "table-empty", "该版本没有任何测试项。");
    empty.dataset.testid = "t-standards-empty";
    host.appendChild(empty);
  }
  setPageError("standards-error", "");
  fillText("std-meta", `${version.item_count} 项 · 共 ${version.items.length} 项已载入`);
  fillText("std-id", version.standard_id);
  fillText("std-vlabel", `v${version.id} · ${version.version}`);
  fillText("std-checksum", version.checksum);
  fillText("std-count", `${version.item_count} 项`);
  const autoTotal = version.items.filter((i) => i.execution === "auto").length;
  fillText("std-split", `自动 ${autoTotal} · 人工 ${version.items.length - autoTotal}`);
  fillText("std-note", version.note || "");
}

async function loadVersion(versionId) {
  const version = await api(`/api/standards/versions/${versionId}`);
  state.version = version;
  state.versionId = version.id;
  state.edits.clear();
  setDirty(false);
  renderVersion(version, Boolean(state.session && state.session.role === "admin"));
}

async function saveVersion() {
  if (!state.versionId) return;
  const items = [...state.edits.entries()].map(([itemId, patch]) => ({
    item_id: itemId,
    ...patch,
  }));
  if (!items.length) {
    toast("没有需要保存的修改", "error");
    return;
  }
  const noteInput = $("std-change-note");
  const note = noteInput ? noteInput.value.trim() : "";
  const buttons = document.querySelectorAll("#std-save, #std-save-2");
  buttons.forEach((btn) => {
    btn.disabled = true;
  });
  try {
    const result = await api("/api/standards/versions", {
      method: "POST",
      body: { parent_id: state.versionId, note, items },
    });
    toast(`已创建新版本 v${result.id}（${result.checksum}）`, "ok");
    if (noteInput) noteInput.value = "";
    const overview = await loadOverview();
    const select = $("std-version");
    select.value = String(result.id);
    await loadVersion(result.id);
    void overview;
  } catch (err) {
    setPageError("standards-error", err.message || "保存失败");
    toast(err.message || "保存失败", "error");
  } finally {
    buttons.forEach((btn) => {
      btn.disabled = false;
    });
  }
}

/** 包内标准定义比库里最新版本新时给出提示。
 *
 * 2026-10-30：新增 GATE-01~03 后，有人升级了代码却没重启服务 / 用的是旧包，
 * 页面还停在旧版本上，看起来像“新增项没生效”。这里把两个数字直接摊开说清楚。
 */
function syncHint(overview) {
  const hint = $("std-sync-hint");
  if (!hint) return;
  const latest = overview.versions[0];
  const shipped = Number(overview.item_count || 0);
  const stored = Number((latest && latest.item_count) || 0);
  if (!latest || !shipped || stored === shipped) {
    hint.classList.add("hidden");
    hint.textContent = "";
    return;
  }
  hint.textContent =
    `当前显示的是历史标准版本 v${latest.id}（${stored} 项），而服务端包内定义已是 ${shipped} 项。` +
    "请确认已升级到新包并重启服务；若最新版本是人工另存过的，点右上角「同步包内定义」生成新版本。";
  hint.classList.remove("hidden");
}

async function boot() {
  try {
    state.session = await getSession();
  } catch (err) {
    return;
  }
  let overview;
  try {
    overview = await loadOverview();
  } catch (err) {
    setPageError("standards-error", `测试标准加载失败：${err.message}`);
    toast(`测试标准加载失败：${err.message}`, "error");
    return;
  }
  if (!overview.versions.length) {
    setPageError("standards-error", "");
    const empty = el("p", "table-empty", "尚无标准版本。");
    empty.dataset.testid = "t-standards-empty";
    $("std-chapters").appendChild(empty);
    toast("尚无标准版本", "error");
    return;
  }
  syncHint(overview);
  try {
    await loadVersion(overview.versions[0].id);
  } catch (err) {
    setPageError("standards-error", `测试标准加载失败：${err.message}`);
    toast(`测试标准加载失败：${err.message}`, "error");
    return;
  }

  $("std-version").addEventListener("change", (event) => {
    if (state.dirty && !window.confirm("当前修改尚未保存，切换版本会丢失修改，是否继续？")) {
      event.target.value = String(state.versionId);
      return;
    }
    loadVersion(Number(event.target.value));
  });
  $("std-reload").addEventListener("click", () => loadVersion(state.versionId));
  const syncBtn = $("std-sync-def");
  if (syncBtn) {
    syncBtn.addEventListener("click", async () => {
      syncBtn.disabled = true;
      try {
        const result = await api("/api/standards/sync", { method: "POST", body: {} });
        if (result.created) {
          toast(`已按包内定义生成 v${result.id}（${result.item_count} 项）`, "ok");
        } else {
          toast(result.message || "已是最新定义，无需同步", "ok");
        }
        const overview = await loadOverview();
        syncHint(overview);
        if (overview.versions.length) {
          await loadVersion(overview.versions[0].id);
        }
      } catch (err) {
        setPageError("standards-error", `同步失败：${err.message}`);
        toast(`同步失败：${err.message}`, "error");
      } finally {
        syncBtn.disabled = false;
      }
    });
  }
  document.querySelectorAll("#std-save, #std-save-2").forEach((btn) => {
    btn.addEventListener("click", saveVersion);
  });
}

boot();
