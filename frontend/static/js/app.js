/* Shared runtime: session bootstrap, JSON API client, SSE client, toasts. */

let sessionPromise = null;

export class ApiError extends Error {
  constructor(message, code, status, fields) {
    super(message);
    this.name = "ApiError";
    this.code = code || "error";
    this.status = status || 0;
    this.fields = fields || [];
  }
}

export function toast(message, type = "info") {
  const host = document.getElementById("toast-host");
  if (!host) return;
  const node = document.createElement("div");
  node.className = "toast" + (type === "error" ? " error" : type === "ok" ? " ok" : "");
  node.textContent = message;
  host.appendChild(node);
  window.setTimeout(() => node.remove(), 4200);
}

function redirectToLogin() {
  if (window.location.pathname !== "/login") {
    window.location.replace("/login?notice=expired");
  }
}

export async function getSession(force = false) {
  if (!sessionPromise || force) {
    sessionPromise = fetch("/api/auth/session", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(async (resp) => {
        if (resp.status === 401) {
          redirectToLogin();
          throw new ApiError("会话已失效", "unauthenticated", 401);
        }
        if (!resp.ok) throw new ApiError("无法获取会话信息", "session_error", resp.status);
        return resp.json();
      })
      .catch((err) => {
        sessionPromise = null;
        throw err;
      });
  }
  return sessionPromise;
}

export async function api(path, options = {}) {
  const { method = "GET", body = null, signal = null, csrf = null } = options;
  const session = await getSession();
  const headers = { Accept: "application/json", "X-CSRF-Token": csrf || session.csrf_token };
  const init = { method, headers, credentials: "same-origin", signal };
  if (body !== null) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  const resp = await fetch(path, init);
  const text = await resp.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    data = null;
  }

  if (resp.status === 401) {
    redirectToLogin();
    throw new ApiError("会话已失效，请重新登录", "unauthenticated", 401);
  }
  if (!resp.ok) {
    const error = (data && data.error) || {};
    throw new ApiError(error.message || `请求失败（HTTP ${resp.status}）`, error.code, resp.status, error.fields);
  }
  return data;
}

export async function streamRequest(path, body, { onEvent, signal, csrf = null } = {}) {
  const session = await getSession();
  const resp = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      "X-CSRF-Token": csrf || session.csrf_token,
    },
    body: JSON.stringify(body),
    signal,
  });

  if (resp.status === 401) {
    redirectToLogin();
    throw new ApiError("会话已失效，请重新登录", "unauthenticated", 401);
  }
  if (!resp.ok) {
    let message = `请求失败（HTTP ${resp.status}）`;
    try {
      const data = await resp.json();
      if (data && data.error && data.error.message) message = data.error.message;
    } catch (err) {
      /* ignore non-JSON error bodies */
    }
    throw new ApiError(message, "http_error", resp.status);
  }
  if (!resp.body) throw new ApiError("浏览器不支持流式读取", "no_stream", 0);

  const reader = resp.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  const dispatch = (chunk) => {
    const lines = chunk.split("\n");
    let event = "message";
    const dataLines = [];
    lines.forEach((line) => {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
    });
    if (!dataLines.length) return;
    let payload = {};
    try {
      payload = JSON.parse(dataLines.join("\n"));
    } catch (err) {
      payload = { raw: dataLines.join("\n") };
    }
    if (onEvent) onEvent(event, payload);
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
    let index = buffer.indexOf("\n\n");
    while (index >= 0) {
      dispatch(buffer.slice(0, index));
      buffer = buffer.slice(index + 2);
      index = buffer.indexOf("\n\n");
    }
  }
  if (buffer.trim()) dispatch(buffer);
}

export async function logout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch (err) {
    /* the cookie is cleared server-side even if the call fails */
  }
  window.location.replace("/login?notice=logout");
}

export function bindLogout() {
  const button = document.getElementById("logout-btn");
  if (button) {
    button.addEventListener("click", async () => {
      button.disabled = true;
      await logout();
    });
  }
}

export function actorLabel(role) {
  return role === "admin" ? "管理员" : role === "operator" ? "操作员" : "只读";
}

export function formatTime(seconds) {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString("zh-CN", { hour12: false });
}

export function formatMs(value) {
  if (value === null || value === undefined) return "—";
  return `${value} ms`;
}

export function $(id) {
  return document.getElementById(id);
}

/* 页面级错误锚点：把加载失败写进 `t-<page>-error`（模板里的隐藏 alert），
 * 与 toast 的区别是「静态锚点」——脚本可以先等根节点、再判 error，从而区分
 * “加载失败”和“确实没有数据”。规范见 docs/12-testability-spec.md §6.2.1。 */
export function setPageError(id, message) {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = message || "";
  node.classList.toggle("hidden", !message);
}

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}
