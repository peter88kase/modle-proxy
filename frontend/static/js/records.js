import { api, getSession, toast, $, el, setPageError } from "./app.js";

const body = $("records-body");
const detailPanel = $("detail-panel");
const standardPanel = $("standard-panel");
let currentRunId = null;
let isAdmin = false;
let reportEntries = [];
let reportRunId = null;

const STATUS_BADGE = {
  pass: ["pass", "通过"],
  fail: ["fail", "不通过"],
  not_tested: ["not-tested", "未测试"],
  pending: ["pending", "待确认"],
  undefined: ["undefined", "标准未定义"],
  not_applicable: ["na", "不适用"],
  blocked: ["blocked", "阻塞"],
};

const MANUAL_OPTIONS = [
  ["", "保持未测试"],
  ["pass", "通过"],
  ["fail", "不通过"],
  ["pending", "待确认"],
  ["not_applicable", "不适用"],
];

function badgeClass(result) {
  return result === "PASS" ? "pass" : result === "FAIL" ? "fail" : "skip";
}

function prettyTime(value) {
  if (!value) return "—";
  return String(value).replace("T", " ").replace(/([+-]\d{2}:\d{2})$/, " $1");
}

function cell(text, className) {
  return el("td", className || null, text === null || text === undefined ? "—" : String(text));
}

function verdictClass(verdict) {
  if (verdict === "达标") return "pass";
  if (verdict === "不达标") return "fail";
  return "undecided";
}

async function loadRuns() {
  const limit = Number($("record-limit").value || 30);
  const loading = el("tr");
  const td = el("td", "table-empty", "加载中…");
  td.colSpan = 12;
  loading.appendChild(td);
  body.replaceChildren(loading);

  try {
    const data = await api(`/api/suite/runs?limit=${limit}`);
    const items = data.items || [];
    setPageError("records-error", "");
    $("record-count").textContent = `${items.length} 条`;
    if (!items.length) {
      const row = el("tr");
      const empty = el("td", "table-empty", "暂无记录。运行一次验收套件后会自动保存。");
      empty.dataset.testid = "t-records-empty";
      empty.colSpan = 12;
      row.appendChild(empty);
      body.replaceChildren(row);
      return;
    }
    body.replaceChildren();
    items.forEach((run) => {
      const row = el("tr", "clickable");
      row.dataset.testid = "t-records-row";
      row.dataset.runId = String(run.id);
      row.appendChild(cell(run.id, "mono num"));
      row.appendChild(cell(prettyTime(run.created_at), "mono small"));
      row.appendChild(cell(run.provider_name));
      row.appendChild(cell(run.model, "mono"));
      row.appendChild(cell(run.link === "direct" ? "直连" : run.link === "forward" ? "转发" : run.link));
      row.appendChild(cell(run.adapter, "mono"));
      row.appendChild(cell(run.passed, "mono num"));
      row.appendChild(cell(run.failed, "mono num"));
      row.appendChild(cell(run.skipped, "mono num"));
      row.appendChild(cell(run.standard_version ? `v${run.standard_version_id} · ${run.standard_version}` : "未绑定", "mono small"));
      const verdictTd = el("td");
      verdictTd.dataset.testid = "t-records-cell-row-verdict";
      verdictTd.dataset.verdict = run.conclusion || "";
      if (run.conclusion) {
        verdictTd.appendChild(el("span", `badge ${verdictClass(run.conclusion)}`, run.conclusion));
      } else {
        verdictTd.appendChild(el("span", "muted small", "—"));
      }
      row.appendChild(verdictTd);
      row.appendChild(cell(run.note || "—", "small"));
      row.addEventListener("click", () => openRun(run.id, row));
      body.appendChild(row);
    });
  } catch (err) {
    setPageError("records-error", `验收记录加载失败：${err.message}`);
    toast(err.message, "error");
  }
}

function renderConclusionBar(conclusion) {
  const node = $("d-verdict");
  node.textContent = conclusion.verdict;
  node.className = `verdict ${verdictClass(conclusion.verdict)}`;
  node.dataset.verdict = conclusion.verdict;
  $("d-verdict-reason").textContent = conclusion.reason;
  const counts = conclusion.counts || {};
  $("d-verdict-counts").replaceChildren();
  [
    ["通过", counts.pass || 0],
    ["不通过", counts.fail || 0],
    ["未测试", counts.not_tested || 0],
    ["待确认", counts.pending || 0],
    ["未定义", counts.undefined || 0],
  ].forEach(([label, value]) => {
    const span = el("span");
    span.append(document.createTextNode(`${label} `), el("b", null, String(value)));
    $("d-verdict-counts").appendChild(span);
  });
}

function itemRow(entry) {
  const tr = el("tr");
  tr.dataset.testid = "t-records-row-item";
  tr.dataset.itemId = entry.item_id;
  tr.dataset.status = entry.status;
  tr.dataset.execution = entry.execution === "auto" ? "auto" : "manual";
  tr.appendChild(cell(entry.item_id, "mono"));
  const nameTd = el("td");
  nameTd.appendChild(el("div", null, entry.name));
  nameTd.appendChild(el("div", "small muted", entry.section));
  tr.appendChild(nameTd);
  tr.appendChild(cell(entry.execution === "auto" ? "自动" : "人工", "small"));
  tr.appendChild(cell(entry.expected || entry.criteria || "—", "small"));
  tr.appendChild(cell(entry.actual || entry.reason || "—", "small"));

  const [cls, label] = STATUS_BADGE[entry.status] || ["skip", entry.status];
  const statusTd = el("td");
  statusTd.dataset.testid = "t-records-cell-status";
  statusTd.appendChild(el("span", `badge ${cls}`, label));
  tr.appendChild(statusTd);

  const actionTd = el("td", "actions");
  const select = document.createElement("select");
  select.dataset.testid = "t-records-select-status";
  select.dataset.itemId = entry.item_id;
  select.setAttribute("aria-label", `${entry.item_id} 判定`);
  select.innerHTML = MANUAL_OPTIONS.map(
    ([value, text]) => `<option value="${value}"${value === entry.status ? " selected" : ""}>${text}</option>`
  ).join("");
  const note = document.createElement("input");
  note.dataset.testid = "t-records-input-note";
  note.dataset.itemId = entry.item_id;
  note.type = "text";
  note.placeholder = "说明（不通过/不适用必填）";
  note.value = entry.note || "";
  note.setAttribute("aria-label", `${entry.item_id} 说明`);
  const save = el("button", "btn btn-sm", "保存");
  save.dataset.testid = "t-records-btn-confirm";
  save.dataset.itemId = entry.item_id;
  save.type = "button";
  save.addEventListener("click", async () => {
    const status = select.value || "not_tested";
    try {
      save.disabled = true;
      const result = await api(`/api/runs/${reportRunId}/items/${entry.item_id}`, {
        method: "POST",
        body: { status, note: note.value.trim() },
      });
      toast(`${entry.item_id} 已记录为「${STATUS_BADGE[status]?.[1] || status}」`, "ok");
      renderConclusionBar(result.conclusion);
      await refreshReport(reportRunId);
      loadRuns();
    } catch (err) {
      toast(err.message, "error");
    } finally {
      save.disabled = false;
    }
  });
  const box = el("div", "confirm-box");
  box.append(select, note, save);
  actionTd.appendChild(box);
  tr.appendChild(actionTd);
  return tr;
}

function renderEntries() {
  const filter = $("std-filter") ? $("std-filter").value : "all";
  const host = $("std-body");
  host.replaceChildren();
  const list = reportEntries.filter((entry) => {
    if (filter === "attention") return ["fail", "pending", "undefined", "not_tested"].includes(entry.status);
    if (filter === "auto") return entry.execution === "auto";
    return true;
  });
  if (!list.length) {
    const tr = el("tr");
    const td = el("td", "table-empty", "没有符合条件的测试项");
    td.dataset.testid = "t-records-empty-items";
    td.colSpan = 7;
    tr.appendChild(td);
    host.appendChild(tr);
    return;
  }
  list.forEach((entry) => host.appendChild(itemRow(entry)));
  $("std-panel-meta").textContent = `显示 ${list.length} / ${reportEntries.length} 项`;
}

async function refreshReport(runId) {
  try {
    const report = await api(`/api/runs/${runId}/report`);
    reportRunId = runId;
    reportEntries = report.entries || [];
    standardPanel.classList.remove("hidden");
    $("std-panel-version").textContent = `v${report.standard.id} · ${report.standard.version} · ${report.standard.checksum}`;
    renderConclusionBar(report.conclusion);
    $("d-standard").textContent = `v${report.standard.id} · ${report.standard.version}（${report.standard.checksum}）`;
    const pdf = $("detail-pdf");
    pdf.href = `/api/runs/${runId}/report.pdf`;
    pdf.removeAttribute("aria-disabled");
    $("d-report-hint").textContent = `报告编号 ${report.report_no}。导出前会重新校验标准版本；报告只包含本批次真实记录。`;
    renderEntries();
    return report;
  } catch (err) {
    standardPanel.classList.add("hidden");
    $("std-panel-meta").textContent = "—";
    const pdf = $("detail-pdf");
    pdf.setAttribute("href", "#");
    pdf.setAttribute("aria-disabled", "true");
    $("d-verdict").textContent = "不可判定";
    $("d-verdict").className = "verdict undecided";
    $("d-verdict-reason").textContent = "";
    $("d-verdict-counts").replaceChildren();
    $("d-standard").textContent = "未绑定";
    $("d-report-hint").textContent = err.message || "无法生成判定";
    throw err;
  }
}

async function openRun(runId, row) {
  currentRunId = runId;
  document.querySelectorAll("#records-body tr").forEach((tr) => tr.classList.remove("is-selected"));
  if (row) row.classList.add("is-selected");

  try {
    const data = await api(`/api/suite/runs/${runId}`);
    const run = data.run;
    const cases = data.cases || [];
    detailPanel.classList.remove("hidden");
    $("detail-id").textContent = `#${run.id}`;
    $("d-provider").textContent = `${run.provider_name}（${run.provider_id}）`;
    $("d-host").textContent = run.endpoint_host || "—";
    $("d-model").textContent = run.model;
    $("d-link").textContent = `${run.link} · ${run.adapter}`;
    $("d-time").textContent = prettyTime(run.created_at);
    $("d-note").textContent = run.note || "无";
    $("detail-md").href = `/api/suite/runs/${run.id}/export?format=md`;
    $("detail-csv").href = `/api/suite/runs/${run.id}/export?format=csv`;
    $("detail-delete").classList.toggle("hidden", !isAdmin);

    const detailBody = $("detail-body");
    detailBody.replaceChildren();
    if (!cases.length) {
      const tr = el("tr");
      const td = el("td", "table-empty", "该批次没有用例记录");
      td.dataset.testid = "t-records-empty-cases";
      td.colSpan = 6;
      tr.appendChild(td);
      detailBody.appendChild(tr);
    } else {
      cases.forEach((item) => {
        const tr = el("tr");
        tr.dataset.testid = "t-records-row-case";
        tr.dataset.caseId = item.case_id;
        tr.dataset.result = item.result;
        tr.appendChild(cell(item.case_id, "mono"));
        tr.appendChild(cell(item.title));
        const resultCell = el("td");
        resultCell.appendChild(el("span", `badge ${badgeClass(item.result)}`, item.result));
        tr.appendChild(resultCell);
        tr.appendChild(cell(item.http_status, "mono num"));
        tr.appendChild(cell(item.latency_ms === null ? "—" : `${item.latency_ms} ms`, "mono num"));
        tr.appendChild(cell(item.evidence || "—", "small"));
        detailBody.appendChild(tr);
      });
    }

    try {
      await refreshReport(run.id);
    } catch (err) {
      /* 未绑定标准的批次：结论区已展示原因，不再重复弹错 */
    }
    detailPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    toast(err.message, "error");
  }
}

$("reload-records").addEventListener("click", loadRuns);
$("record-limit").addEventListener("change", loadRuns);

$("detail-delete").addEventListener("click", async () => {
  if (!currentRunId) return;
  if (!window.confirm(`确认删除记录 #${currentRunId}？该操作不可恢复。`)) return;
  try {
    await api(`/api/suite/runs/${currentRunId}`, { method: "DELETE" });
    detailPanel.classList.add("hidden");
    standardPanel.classList.add("hidden");
    currentRunId = null;
    toast("记录已删除", "ok");
    loadRuns();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("detail-pdf").addEventListener("click", (event) => {
  if ($("detail-pdf").getAttribute("aria-disabled") === "true") {
    event.preventDefault();
    toast($("d-report-hint").textContent || "该批次无法导出报告", "error");
  }
});

(async () => {
  try {
    const session = await getSession();
    isAdmin = session.role === "admin";
  } catch (err) {
    return;
  }
  const filter = document.createElement("select");
  filter.id = "std-filter";
  filter.className = "mono";
  filter.innerHTML = `
    <option value="all">全部测试项</option>
    <option value="attention">仅需处理</option>
    <option value="auto">仅自动项</option>`;
  filter.addEventListener("change", renderEntries);
  const meta = $("std-panel-meta");
  if (meta && meta.parentElement) {
    meta.parentElement.insertBefore(filter, meta);
  }
  loadRuns();
})();
