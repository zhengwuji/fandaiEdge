// ECH-Workers - KV-less Admin Panel + Login
// ---------------------------------------
// 本版本完全不依赖 KV：
// - 管理密码从环境变量 ADMIN_PASSWORD 读取（或代码里默认值）
// - 会话使用 HMAC 签名的无状态 Cookie（无需存储 Session）
// - 配置数据全部保存在浏览器 localStorage / URL 中，Worker 不写入任何存储
//
// 使用方法：
// 1. 在 Cloudflare Worker 的环境变量中设置：
//      ADMIN_PASSWORD  登录密码（必填，建议随机复杂一点）
//      SESSION_SECRET  会话签名密钥（必填，建议随机 32+ 字符）
// 2. 访问 /login 登录，成功后即可进入面板。
// 3. 面板里的所有配置都只保存在浏览器本地/localStorage，你可以导出为 URL 备份。

const encoder = new TextEncoder();

// 生成 HMAC-SHA256 签名（base64url）
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const bytes = new Uint8Array(sigBuf);
  let binary = "";
  for (let b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return b64;
}

async function hmacVerify(secret, data, sig) {
  const expected = await hmacSign(secret, data);
  // 固定时间比较，避免侧信道（简单实现）
  if (expected.length !== sig.length) return false;
  let ok = 0;
  for (let i = 0; i < expected.length; i++) {
    ok |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return ok === 0;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  const parts = header.split(";");
  for (let p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    out[k] = v;
  }
  return out;
}

function redirect(location, extraHeaders = {}) {
  return new Response("", {
    status: 302,
    headers: {
      Location: location,
      ...extraHeaders,
    },
  });
}

// 渲染登录页
function renderLoginPage(message = "") {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>ECH-Workers 登录</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui;
background:#030712;color:#e5e7eb;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0}
.card{background:#020617;border:1px solid #1f2937;border-radius:16px;
padding:32px 28px;box-shadow:0 24px 60px rgba(15,23,42,.9);width:320px}
h1{margin:0 0 12px;font-size:20px;font-weight:600;}
label{display:block;font-size:13px;margin-bottom:6px;color:#9ca3af}
input[type=password]{width:100%;padding:10px 12px;border-radius:10px;
border:1px solid #374151;background:#020617;color:#e5e7eb;box-sizing:border-box;
outline:none;font-size:14px}
input[type=password]:focus{border-color:#38bdf8;}
button{margin-top:14px;width:100%;padding:10px 12px;border-radius:999px;
border:none;font-size:14px;font-weight:500;background:linear-gradient(90deg,#06b6d4,#3b82f6);
color:white;cursor:pointer}
button:hover{filter:brightness(1.08);}
.msg{min-height:20px;font-size:12px;color:#f97316;margin-bottom:8px}
.footer{margin-top:20px;font-size:11px;color:#6b7280;text-align:center}
</style>
</head>
<body>
  <div class="card">
    <h1>ECH-Workers 登录</h1>
    <form method="POST" action="/login">
      <div class="msg">${message ? message : ""}</div>
      <label for="pwd">管理密码</label>
      <input id="pwd" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">登录</button>
    </form>
    <div class="footer">
      无 KV 版本 · 配置仅保存在浏览器本地<br/>
    </div>
  </div>
</body>
</html>`;
}

// 管理面板 HTML（配置全部在前端 localStorage / URL 中）
function renderAdminApp() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>ECH-Workers 面板 (No-KV)</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
:root{
  color-scheme:dark;
  --bg:#020617;
  --card:#020617;
  --border:#1f2937;
  --accent:#38bdf8;
  --accent-soft:#0ea5e9;
  --text:#e5e7eb;
  --muted:#9ca3af;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",system-ui;
background:radial-gradient(circle at top,#1d283a 0,#020617 55%,#020617 100%);
color:var(--text);min-height:100vh;padding:24px;}
.card{background:rgba(15,23,42,.9);border:1px solid rgba(55,65,81,.85);
border-radius:24px;padding:22px 22px 18px;max-width:930px;margin:0 auto;
backdrop-filter:blur(22px);box-shadow:0 24px 80px rgba(15,23,42,.95);}
h1{font-size:22px;font-weight:600;display:flex;align-items:center;gap:8px;
margin-bottom:4px;}
.badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid #4b5563;
color:#9ca3af}
p.desc{font-size:13px;color:#9ca3af;margin-bottom:18px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;}
.field{display:flex;flex-direction:column;gap:4px;font-size:13px;}
label{color:#9ca3af;font-size:12px;}
input,select,textarea{
  background:#020617;border-radius:12px;border:1px solid #374151;
  padding:8px 10px;font-size:13px;color:#e5e7eb;outline:none;
}
input:focus,select:focus,textarea:focus{border-color:var(--accent);}
textarea{min-height:90px;resize:vertical;}
.row{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px;align-items:center;}
button.btn{border:none;border-radius:999px;padding:7px 14px;font-size:12px;
display:inline-flex;align-items:center;gap:6px;cursor:pointer;
background:linear-gradient(90deg,#0ea5e9,#3b82f6);color:white;}
button.btn.secondary{background:#020617;border:1px solid #374151;color:#e5e7eb;}
.small{font-size:11px;color:#6b7280;}
pre.out{margin-top:10px;background:#020617;border-radius:12px;border:1px dashed #334155;
padding:8px 10px;font-size:11px;white-space:pre-wrap;word-break:break-all;
max-height:160px;overflow:auto;}
.tag{display:inline-flex;align-items:center;gap:4px;font-size:11px;
padding:2px 8px;border-radius:999px;background:#020617;border:1px solid #334155;
color:#9ca3af;}
</style>
</head>
<body>
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div>
      <h1>ECH-Workers 面板 <span class="badge">No KV · Local Only</span></h1>
      <p class="desc">所有配置仅保存在浏览器 localStorage 中，可导出为 URL 进行备份或在其他设备导入。</p>
    </div>
    <div style="text-align:right;font-size:11px;color:#9ca3af;">
      <div><span class="tag">已登录</span></div>
      <div style="margin-top:6px;"><a href="/logout" style="color:#f97316;text-decoration:none;">退出登录</a></div>
    </div>
  </div>

  <div class="grid">
    <div class="field">
      <label>UUID（必填）</label>
      <input id="uuid" placeholder="例如：d50b4326-41b4-455b-899f-9452690286fe" />
    </div>
    <div class="field">
      <label>Worker 域名（必填）</label>
      <input id="workerHost" placeholder="例如：ech.example.com" />
    </div>
    <div class="field">
      <label>WS 路径（必填）</label>
      <input id="wsPath" placeholder="/echws" />
    </div>
    <div class="field">
      <label>后端 VPS 域名（必填）</label>
      <input id="backendHost" placeholder="例如：cc1.example.com" />
    </div>
    <div class="field">
      <label>后端端口（必填）</label>
      <input id="backendPort" placeholder="2082" />
    </div>
  </div>

  <div class="row">
    <button class="btn" id="saveBtn">保存到浏览器</button>
    <button class="btn secondary" id="exportBtn">导出配置为 URL</button>
    <button class="btn secondary" id="importBtn">从 URL 导入配置</button>
    <span class="small">配置保存在当前浏览器 localStorage：<code>ech_workers_config</code></span>
  </div>

  <div style="margin-top:18px;">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div class="small">生成的 VLESS 节点（可复制到 v2rayN / Clash / Sing-box）：</div>
      <button class="btn secondary" id="genBtn">生成节点</button>
    </div>
    <pre class="out" id="outBox">// 在上方填写配置后点击“生成节点”</pre>
  </div>
</div>

<script>
const STORAGE_KEY = "ech_workers_config";

function loadConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const cfg = JSON.parse(raw);
    for (const k of ["uuid","workerHost","wsPath","backendHost","backendPort"]) {
      if (cfg[k]) document.getElementById(k).value = cfg[k];
    }
  } catch (e) { console.error(e); }
}

function saveConfig() {
  const cfg = {
    uuid: document.getElementById("uuid").value.trim(),
    workerHost: document.getElementById("workerHost").value.trim(),
    wsPath: document.getElementById("wsPath").value.trim(),
    backendHost: document.getElementById("backendHost").value.trim(),
    backendPort: document.getElementById("backendPort").value.trim(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
  alert("已保存到当前浏览器。");
}

function encodeConfigToURL() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) { alert("请先填写并保存配置。"); return; }
  const b64 = btoa(unescape(encodeURIComponent(raw)));
  const url = location.origin + "/?cfg=" + b64;
  navigator.clipboard.writeText(url).then(()=>{
    alert("已复制配置 URL，可在其他设备打开此链接导入。");
  },()=>{ alert("复制失败，请手动复制:\\n" + url); });
}

function tryImportConfigFromURL() {
  const params = new URLSearchParams(location.search);
  const cfgParam = params.get("cfg");
  if (!cfgParam) return;
  try {
    const json = decodeURIComponent(escape(atob(cfgParam)));
    localStorage.setItem(STORAGE_KEY, json);
  } catch (e) { console.error("导入配置失败", e); }
}

function genNode() {
  const uuid = document.getElementById("uuid").value.trim();
  const host = document.getElementById("workerHost").value.trim();
  const path = document.getElementById("wsPath").value.trim() || "/echws";
  if (!uuid || !host) {
    alert("UUID 和 Worker 域名为必填项。");
    return;
  }
  const addr = host;
  const port = 443;
  const params = new URLSearchParams({
    encryption: "none",
    security: "tls",
    type: "ws",
    path: path,
    host: host,
    sni: host
  });
  const link = "vless://" + uuid + "@" + addr + ":" + port + "?" +
    params.toString() + "#ECH-Workers";
  document.getElementById("outBox").textContent = link;
}

document.getElementById("saveBtn").onclick = saveConfig;
document.getElementById("exportBtn").onclick = encodeConfigToURL;
document.getElementById("importBtn").onclick = ()=>{
  const u = prompt("请输入包含 cfg 参数的 URL：","");
  if (!u) return;
  try {
    const urlObj = new URL(u);
    const cfgParam = urlObj.searchParams.get("cfg");
    if (!cfgParam) throw new Error("缺少 cfg 参数");
    const json = decodeURIComponent(escape(atob(cfgParam)));
    localStorage.setItem(STORAGE_KEY, json);
    loadConfig();
    alert("已从 URL 导入配置并保存到浏览器。");
  } catch(e) {
    alert("解析失败：" + e.message);
  }
};
document.getElementById("genBtn").onclick = genNode;

tryImportConfigFromURL();
loadConfig();
</script>
</body>
</html>`;
}

// 解析 x-www-form-urlencoded
async function parseFormData(request) {
  const text = await request.text();
  const params = new URLSearchParams(text);
  const out = {};
  for (const [k, v] of params) out[k] = v;
  return out;
}

// 校验 Session Cookie
async function verifySession(env, request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const token = cookies["ech_session"];
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [expStr, sig] = parts;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return false;
  const secret = env.SESSION_SECRET || "CHANGE_ME_SESSION_SECRET";
  const ok = await hmacVerify(secret, expStr, sig);
  return ok;
}

// 生成 Session Cookie
async function createSessionCookie(env) {
  const ttlMs = 24 * 60 * 60 * 1000; // 24h
  const exp = Date.now() + ttlMs;
  const expStr = String(exp);
  const secret = env.SESSION_SECRET || "CHANGE_ME_SESSION_SECRET";
  const sig = await hmacSign(secret, expStr);
  const token = `${expStr}.${sig}`;
  const maxAge = Math.floor(ttlMs / 1000);
  const cookie = [
    `ech_session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ].join("; ");
  return cookie;
}

// 清空 Session Cookie
function clearSessionCookie() {
  const cookie = [
    "ech_session=deleted",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
  return cookie;
}

// 处理请求
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 登录逻辑
    if (pathname === "/login") {
      if (request.method === "GET") {
        const authed = await verifySession(env, request);
        if (authed) {
          return redirect("/");
        }
        return new Response(renderLoginPage(""), {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        });
      }

      if (request.method === "POST") {
        const form = await parseFormData(request);
        const password = form.password || "";
        const expected = env.ADMIN_PASSWORD || "CHANGE_ME_ADMIN_PASSWORD";
        if (!password || password !== expected) {
          return new Response(renderLoginPage("密码错误，请重试。"), {
            status: 200,
            headers: { "content-type": "text/html; charset=utf-8" },
          });
        }
        const cookie = await createSessionCookie(env);
        return new Response("", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": cookie,
          },
        });
      }

      return new Response("Method Not Allowed", { status: 405 });
    }

    // 退出登录
    if (pathname === "/logout") {
      const cookie = clearSessionCookie();
      return redirect("/login", { "Set-Cookie": cookie });
    }

    // 其它路径都需要鉴权
    const authed = await verifySession(env, request);
    if (!authed) {
      return redirect("/login");
    }

    // 管理面板单页应用
    if (pathname === "/" || pathname === "/index.html") {
      return new Response(renderAdminApp(), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    // 未知路径
    return new Response("Not found", { status: 404 });
  },
};
