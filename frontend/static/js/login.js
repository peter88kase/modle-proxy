const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");
const submit = document.getElementById("login-submit");

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.classList.add("hidden");

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) {
    showError("请输入用户名和密码。");
    return;
  }

  submit.disabled = true;
  submit.textContent = "验证中…";
  try {
    const resp = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ username, password }),
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok) {
      const code = data && data.error && data.error.code;
      if (code === "invalid_credentials") {
        showError("用户名或密码错误，请重试。");
      } else {
        showError((data && data.error && data.error.message) || "登录失败，请重试。");
      }
      return;
    }
    window.location.replace("/");
  } catch (err) {
    showError("无法连接服务器，请稍后重试。");
  } finally {
    submit.disabled = false;
    submit.textContent = "登录";
    document.getElementById("password").value = "";
  }
});
