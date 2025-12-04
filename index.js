// ===============================================================
// VLESS Edge Worker with Admin UI + Password Login + KV Storage
// ---------------------------------------------------------------
// - Admin UI (Tailwind) at "/"
// - Login page with password + "show password" + "remember me 1 day"
// - Password stored in KV (key: ADMIN_PASSWORD)
// - Session token stored in KV (key: ADMIN_SESSION) + cookie "vless_admin"
// - Config stored in KV (key: CONFIG_JSON)
// - Subscription endpoints: /sub, /singbox, /clash, /qrcode
// - WebSocket VLESS proxy with mode A (stable) and B (obfuscated)
// ---------------------------------------------------------------
// IMPORTANT:
// 1. Create a KV Namespace in Cloudflare (e.g. "VLESS_CONFIG").
// 2. Bind it to this Worker with binding name: CONFIG_KV
// ===============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // --- Auth-related routing ---
    if (pathname === "/login" && request.method === "GET") {
      const hasPw = !!(await env.CONFIG_KV.get("ADMIN_PASSWORD"));
      return new Response(renderLoginPage("", !hasPw), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    if (pathname === "/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    // --- Admin UI, protected ---
    if (pathname === "/" || pathname === "/index") {
      const authed = await isAuthenticated(request, env);
      const hasPw = !!(await env.CONFIG_KV.get("ADMIN_PASSWORD"));
      if (!authed) {
        return new Response(renderLoginPage("", !hasPw), {
          headers: { "content-type": "text/html; charset=utf-8" }
        });
      }
      return new Response(renderAdminUI(), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    // --- Protected JSON APIs (config) ---
    if (pathname === "/api/get-config") {
      if (!(await isAuthenticated(request, env))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const data = await env.CONFIG_KV.get("CONFIG_JSON");
      return new Response(data || "{}", {
        headers: { "content-type": "application/json" }
      });
    }

    if (pathname === "/api/set-config") {
      if (!(await isAuthenticated(request, env))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const body = await request.text();
      await env.CONFIG_KV.put("CONFIG_JSON", body);
      return new Response("OK");
    }

    if (pathname === "/api/reset-config") {
      if (!(await isAuthenticated(request, env))) {
        return new Response("Unauthorized", { status: 401 });
      }
      await env.CONFIG_KV.delete("CONFIG_JSON");
      return new Response("RESET_OK");
    }
    // --- Geo info API (线路探测 + 节点评分 + 优选建议) ---
    if (pathname === "/api/geo") {
      const info = {
        ip: request.headers.get("CF-Connecting-IP") || "",
        country: request.cf && request.cf.country || "",
        region: request.cf && request.cf.region || "",
        city: request.cf && request.cf.city || "",
        asn: request.cf && request.cf.asn || "",
        colo: request.cf && request.cf.colo || ""
      };

      const colo = (info.colo || "").toUpperCase();
      let score = "C";
      let comment = "线路一般，可以考虑更换 Cloudflare IP 或区域。";
      let ipSuggestions = [];

      if (["HKG","TPE","NRT","KIX","ICN","SIN"].includes(colo)) {
        score = "A";
        comment = "非常适合中国大陆访问（亚洲节点，就近接入）。建议保留当前 IP，但可在同段内优选更稳节点。";
        ipSuggestions = [
          "188.114.96.0/20 （常见优选，适合港/台/新）",
          "104.16.0.0/13",
          "172.64.0.0/13"
        ];
      } else if (["LAX","SJC","SEA","ORD","DFW","IAD","JFK"].includes(colo)) {
        score = "B";
        comment = "落在北美节点，延迟略高但可用。建议改用更易落香港/台湾的新 IP。";
        ipSuggestions = [
          "188.114.96.0/20 （尝试改绑到该段，再测试是否转向 HKG/TPE）",
          "141.101.64.0/18",
          "104.24.0.0/14"
        ];
      } else {
        score = "C";
        comment = "可能落在较远或冷门节点，建议优选 IP，观察 colo 是否切到 HKG/TPE/NRT/SIN。";
        ipSuggestions = [
          "188.114.96.0/20",
          "104.16.0.0/13",
          "172.64.0.0/13",
          "141.101.64.0/18"
        ];
      }

      return new Response(JSON.stringify({
        ...info,
        score,
        comment,
        ipSuggestions
      }, null, 2), {
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }

    // --- 速度测试页面（前端测速工具） ---
    if (pathname === "/speedtest") {
      return new Response(renderSpeedtestPage(), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    // --- 下载测试文件（约 1MB） ---
    if (pathname === "/speed.bin") {
      const size = 1024 * 1024; // 1MB
      const chunk = "0".repeat(1024);
      let data = "";
      for (let i = 0; i < size / 1024; i++) {
        data += chunk;
      }
      return new Response(data, {
        headers: {
          "content-type": "application/octet-stream",
          "cache-control": "no-store"
        }
      });
    }



        // --- Public API: subscriptions (not protected,方便客户端直接订阅) ---
    if (pathname === "/sub") {
      const cfg = await loadConfig(env);

      // 订阅 IP 模式：
      // ?ip=domain  → 只用域名（默认）
      // ?ip=dual    → 域名 + 多个 IP 备胎节点
      // ?ip=ip/best/colo → 仅 IP 节点（多个备胎 IP）
      const ipParam = url.searchParams.get("ip") || "domain";
      const colo = (request.cf && request.cf.colo || "").toUpperCase();
      const ipList = typeof pickIpListByColo === "function"
        ? pickIpListByColo(colo)
        : [];

      let ipOption = { mode: "domain", ips: [] };
      if (ipParam === "dual") {
        ipOption = { mode: "dual", ips: ipList };
      } else if (ipParam === "ip" || ipParam === "best" || ipParam === "colo") {
        ipOption = { mode: "ip", ips: ipList };
      } else {
        ipOption = { mode: "domain", ips: [] };
      }

      const str = generateV2raySub(cfg, ipOption);
      const b64 = typeof btoa === "function"
        ? btoa(str)
        : Buffer.from(str, "utf-8").toString("base64");
      return new Response(b64, {
        headers: { "content-type": "text/plain; charset=utf-8" }
      });
    }



    if (pathname === "/singbox") {
      const cfg = await loadConfig(env);
      const json = generateSingbox(cfg);
      return new Response(JSON.stringify(json, null, 2), {
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }

    if (pathname === "/clash") {
      const cfg = await loadConfig(env);
      const yaml = generateClash(cfg);
      return new Response(yaml, {
        headers: { "content-type": "text/yaml; charset=utf-8" }
      });
    }

    if (pathname === "/qrcode") {
      const cfg = await loadConfig(env);
      const png = await generateQRCode(cfg);
      return new Response(png, {
        headers: { "content-type": "image/png" }
      });
    }

    // --- WebSocket for VLESS proxy (no auth, for clients) ---
    const upgrade = request.headers.get("Upgrade") || "";
    if (upgrade.toLowerCase() === "websocket") {
      const cfg = await loadConfig(env);
      return handleWS(request, cfg);
    }

    return new Response("Not Found", { status: 404 });
  }
};

// ===============================================================
// Auth helpers: password & session
// ===============================================================

async function isAuthenticated(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const token = cookies["vless_admin"];
  if (!token) return false;
  const saved = await env.CONFIG_KV.get("ADMIN_SESSION");
  if (!saved) return false;
  return token === saved;
}

function parseCookies(header) {
  const out = {};
  header.split(";").forEach(part => {
    const [k, v] = part.split("=").map(s => s && s.trim());
    if (k && v) out[k] = v;
  });
  return out;
}

async function handleLogin(request, env) {
  const formData = await request.formData();
  const password = (formData.get("password") || "").toString();
  const remember = formData.get("remember") === "on";

  if (!password) {
    const hasPw = !!(await env.CONFIG_KV.get("ADMIN_PASSWORD"));
    return new Response(renderLoginPage("密码不能为空", !hasPw), {
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  }

  const existing = await env.CONFIG_KV.get("ADMIN_PASSWORD");

  // 初次设置密码
  if (!existing) {
    await env.CONFIG_KV.put("ADMIN_PASSWORD", password);
  } else {
    if (existing !== password) {
      return new Response(renderLoginPage("密码错误，请重试。", false), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }
  }

  // 生成 session token 存入 KV
  const token = crypto.randomUUID();
  await env.CONFIG_KV.put("ADMIN_SESSION", token);

  // 设置 Cookie，记住 1 天（如勾选）
  let cookie = `vless_admin=${token}; Path=/; HttpOnly; SameSite=Lax; Secure`;
  if (remember) {
    cookie += "; Max-Age=86400";
  }

  const headers = new Headers();
  headers.set("Set-Cookie", cookie);
  headers.set("Location", "/");

  return new Response(null, {
    status: 302,
    headers
  });
}

// ===============================================================
// Login Page (风格 C, 卡片 + 显示密码 + 记住我 1 天)
// ===============================================================

function renderLoginPage(message, needInit) {
  const safeMsg = message ? String(message) : "";
  return `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8" />
  <title>VLESS 后台登录</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"><\/script>
</head>
<body class="min-h-screen bg-slate-100 flex items-center justify-center">
  <div class="w-full max-w-md">
    <div class="bg-white shadow-xl rounded-2xl p-8 border border-slate-200">
      <h1 class="text-2xl font-bold mb-4 flex items-center">
        <span class="mr-2">🔐</span> VLESS 管理后台登录
      </h1>
      <p class="text-sm text-slate-500 mb-4">
        ${needInit
          ? "检测到你还没有设置后台密码，请先设置一个新的管理员密码。以后登录都将使用该密码。"
          : "请输入后台密码进入管理面板。"}
      </p>

      ${safeMsg ? `<div class="mb-4 text-red-600 text-sm font-semibold">${safeMsg}</div>` : ""}

      <form method="POST" action="/login" class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-1">后台密码</label>
          <div class="flex items-center border border-slate-300 rounded-lg overflow-hidden bg-slate-50">
            <input id="password" name="password" type="password"
                   class="flex-1 px-3 py-2 bg-transparent outline-none"
                   placeholder="请输入后台密码" />
            <button type="button" id="togglePwd"
                    class="px-3 text-xs text-slate-600 hover:text-slate-900">
              显示
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between text-sm">
          <label class="inline-flex items-center">
            <input type="checkbox" name="remember" class="mr-2" />
            记住我 1 天
          </label>
        </div>

        <button type="submit"
                class="w-full py-2 rounded-lg bg-blue-600 text-white font-semibold hover:bg-blue-700">
          登录 / 保存密码
        </button>
      </form>

      <div class="mt-6 text-xs text-slate-500 space-y-1">
        <p class="font-semibold">使用说明：</p>
        <p>1. 在 Cloudflare Dashboard → Workers 和 KV → 创建一个 KV Namespace（例如：VLESS_CONFIG）。</p>
        <p>2. 在当前 Worker 的 Settings → Variables → KV Namespace Bindings 中绑定该 KV，绑定名设为：<code>CONFIG_KV</code>。</p>
        <p>3. 首次打开本页面时，将提示你设置后台密码。设置完成后，今后访问本后台需要输入该密码。</p>
        <p>4. 登录成功后，将进入节点管理面板，在那里可以配置 UUID、后端域名、端口、WS 路径、多节点等。</p>
      </div>
    </div>
  </div>

  <script>
    const pwdInput = document.getElementById("password");
    const toggleBtn = document.getElementById("togglePwd");
    if (toggleBtn && pwdInput) {
      toggleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        if (pwdInput.type === "password") {
          pwdInput.type = "text";
          toggleBtn.textContent = "隐藏";
        } else {
          pwdInput.type = "password";
          toggleBtn.textContent = "显示";
        }
      });
    }
  <\/script>
</body>
</html>`;
}

// ===============================================================
// Admin UI 页面（已登录后才可访问）
// ===============================================================

function renderAdminUI() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8" />
  <title>VLESS Edge 节点管理面板</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"><\/script>
  <style>
    body { background: #f8fafc; }
    .card { background:white;border-radius:16px;padding:20px;box-shadow:0 4px 10px rgba(0,0,0,0.06); }
    .input { width:100%;padding:10px;border-radius:8px;background:#f1f5f9;margin-bottom:10px; }
    .label { font-weight:600;margin-bottom:4px;display:block;color:#334155; }
    .btn { padding:8px 16px;border-radius:8px;font-weight:600;color:white;background:#2563eb; }
    .btn2 { padding:8px 16px;border-radius:8px;font-weight:600;background:#e2e8f0; }
    .btn-danger { padding:8px 16px;border-radius:8px;font-weight:600;background:#dc2626;color:white; }
  </style>
</head>
<body class="p-6">
  <h1 class="text-3xl font-bold mb-2">🚀 VLESS Edge 节点管理系统</h1>
  <p class="text-gray-600 mb-6">通过本面板，你可以可视化配置 Cloudflare Worker 反代的 VLESS 节点，并一键生成 v2rayN / SingBox / Clash 订阅。</p>

  <!-- 线路检测 / Geo 信息 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-3">当前线路状态 / 入口节点</h2>
    <p id="geoLocation" class="text-sm text-slate-700 mb-1">正在检测你的地理位置...</p>
    <p id="geoColo" class="text-sm text-slate-700 mb-1">正在检测 Cloudflare 入口机房...</p>
    <p id="geoScore" class="text-sm font-semibold mb-1">评分：-</p>
    <p id="geoComment" class="text-xs text-slate-500 mb-2"></p>
    <p class="text-xs text-slate-500">建议优选 IP 段（需要你手动去测速筛选最优）：</p>
    <p id="geoIps" class="text-xs text-slate-600 break-words"></p>
  </div>

  <!-- 基础参数配置 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">基础参数配置</h2>
    <label class="label">UUID（必填）</label>
    <input id="uuid" class="input" placeholder="请输入 VLESS UUID">
    <label class="label">Worker 域名（必填）</label>
    <input id="workerHost" class="input" placeholder="例如：ech.firegod.eu.org">
    <label class="label">WS 路径（必填）</label>
    <input id="wsPath" class="input" value="/echws">
    <label class="label">后端 VPS 域名（必填）</label>
    <input id="backendHost" class="input" placeholder="例如：cc1.firegod.eu.org">
    <label class="label">后端端口（必填）</label>
    <input id="backendPort" class="input" value="2082">
    <p class="text-xs text-slate-500">后端端口为 Xray WS 入站端口（无需 TLS）。本 Worker 将通过 ws:// 后端转发客户端流量。</p>
  </div>

  <!-- WebSocket 模式 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">WebSocket 代理模式</h2>
    <label class="flex items-center mb-2">
      <input type="radio" name="wsMode" value="A" class="mr-2" checked>
      <span>方式 A（稳定型，推荐）</span>
    </label>
    <p class="text-xs text-slate-500 mb-3 ml-6">
      只转发 WebSocket 数据，不主动修改请求头，兼容性最高。
    </p>
    <label class="flex items-center mb-2">
      <input type="radio" name="wsMode" value="B" class="mr-2">
      <span>方式 B（高级混淆，可修改 Host / UA / SNI）</span>
    </label>
    <p class="text-xs text-slate-500 ml-6">
      若启用方式 B，建议在下方填写 Fake Host / SNI / User-Agent，用于伪装成 CDN / 正常网站。
    </p>
  </div>

  <!-- 混淆设置 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">混淆设置（可选）</h2>
    <label class="label">Fake Host</label>
    <input id="fakeHost" class="input" placeholder="例如：cdn.jsdelivr.net">
    <label class="label">SNI</label>
    <input id="sni" class="input" placeholder="例如：www.cloudflare.com">
    <label class="label">User-Agent</label>
    <input id="ua" class="input" placeholder="例如：Mozilla/5.0 Chrome/120">
    <p class="text-xs text-slate-500">当 WS 模式选择为 B 时，这些字段将用于伪装请求头。</p>
  </div>

  <!-- 多节点 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4 flex justify-between">
      多节点列表（可选）
      <button id="addNode" class="btn2">➕ 添加节点</button>
    </h2>
    <div id="nodes"></div>
    <p class="text-xs text-slate-500 mt-2">你可以在这里添加多个前端节点域名，例如：ech1.firegod.eu.org、ech2.firegod.eu.org。</p>
  </div>

  <!-- 保存 & 重置 -->
  <div class="card mb-6">
    <button id="save" class="btn">💾 保存配置到 KV</button>
    <button id="resetCfg" class="btn-danger ml-3">🗑️ 清空节点配置</button>
    <span id="msg" class="ml-3 font-semibold"></span>
  </div>


  <!-- 线路测速工具 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">Cloudflare Worker 线路测速</h2>
    <p class="text-sm text-slate-600 mb-3">
      使用内置测速工具，可以一键测试当前 Worker 域名的真实延迟和下载速度，并对比不同 CF 优选 IP / 不同子域名的表现。
    </p>
    <div class="space-x-2">
      <a href="/speedtest" target="_blank" class="btn2">打开测速页面（新窗口）</a>
      <a href="/api/geo" target="_blank" class="btn2">查看当前线路 JSON 信息</a>
    </div>
    <p class="text-xs text-slate-500 mt-2">
      建议先在这里跑一遍测速，确认入口机房（colo）是否为 HKG/TPE/SIN 等亚洲节点，再配合订阅里的“优选IP节点”进行真实体验对比。
    </p>
  </div>
  <!-- 订阅区 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">订阅 & 导入</h2>
    <div class="space-y-2 text-sm">
      <p>v2rayN 订阅（Base64）：</p>
      <p><code id="subUrl"></code></p>
      <p class="text-xs text-slate-500">复制上述链接到 v2rayN → 订阅 → 添加订阅，即可自动导入节点。</p>
    </div>
    <div class="mt-3 space-x-2">
      <a href="/sub" target="_blank" class="btn2">打开 v2rayN 订阅内容</a>
      <a href="/singbox" target="_blank" class="btn2">查看 SingBox JSON</a>
      <a href="/clash" target="_blank" class="btn2">查看 Clash Meta YAML</a>
      <a href="/qrcode" target="_blank" class="btn2">查看节点二维码</a>
    </div>
  </div>

  <script>
    async function loadConfig() {
      var cfg = {};
      try {
        cfg = await fetch("/api/get-config").then(function(r){return r.json()});
      } catch(e) { cfg = {}; }

      document.getElementById("uuid").value = cfg.uuid || "";
      document.getElementById("workerHost").value = cfg.workerHost || "";
      document.getElementById("wsPath").value = cfg.wsPath || "/echws";
      document.getElementById("backendHost").value = cfg.backendHost || "";
      document.getElementById("backendPort").value = cfg.backendPort || "2082";
      document.getElementById("fakeHost").value = cfg.fakeHost || "";
      document.getElementById("sni").value = cfg.sni || "";
      document.getElementById("ua").value = cfg.ua || "";

      if (cfg.mode === "B") {
        var b = document.querySelector("input[name='wsMode'][value='B']");
        if (b) b.checked = true;
      } else {
        var a = document.querySelector("input[name='wsMode'][value='A']");
        if (a) a.checked = true;
      }

      if (cfg.nodes && Array.isArray(cfg.nodes)) {
        cfg.nodes.forEach(function(n){ addNodeUI(n); });
      }

      try {
        var loc = window.location;
        var base = loc.origin;
        document.getElementById("subUrl").textContent = base + "/sub";
      } catch(e) {}

      // 额外：加载 Geo 信息
      try {
        var geoRes = await fetch("/api/geo");
        var geo = await geoRes.json();
        var locText = "你的大致位置：" + (geo.country || "-") + " / " + (geo.region || "-") + " / " + (geo.city || "-")
          + " （ASN " + (geo.asn || "-") + "）";
        document.getElementById("geoLocation").textContent = locText;
        document.getElementById("geoColo").textContent = "当前 Worker 落地机房（colo）：" + (geo.colo || "-");
        document.getElementById("geoScore").textContent = "线路评分：" + (geo.score || "-");
        document.getElementById("geoComment").textContent = geo.comment || "";
        if (geo.ipSuggestions && geo.ipSuggestions.length) {
          document.getElementById("geoIps").textContent = geo.ipSuggestions.join(", ");
        }
      } catch(e) {
        document.getElementById("geoLocation").textContent = "无法获取 Geo 信息（可能是浏览器或网络限制）。";
      }
    }

    function addNodeUI(d) {
      d = d || {};
      var div = document.createElement("div");
      div.className = "p-3 border rounded-lg mb-3";
      var html = ""
        + '<label class="label">节点域名</label>'
        + '<input class="input node-host" placeholder="例如：ech2.firegod.eu.org" value="' + (d.host || "") + '">'
        + '<label class="label">备注（可选）</label>'
        + '<input class="input node-name" placeholder="例如：新加坡节点" value="' + (d.name || "") + '">'
        + '<button class="btn2 remove mt-2">删除节点</button>';
      div.innerHTML = html;
      div.querySelector(".remove").onclick = function(){ div.remove(); };
      document.getElementById("nodes").appendChild(div);
    }

    document.getElementById("addNode").onclick = function(){ addNodeUI(); };

    document.getElementById("save").onclick = async function () {
      var modeInput = document.querySelector("input[name='wsMode']:checked");
      var mode = modeInput ? modeInput.value : "A";

      var uuidEl = document.getElementById("uuid");
      var workerHostEl = document.getElementById("workerHost");
      var backendHostEl = document.getElementById("backendHost");
      var backendPortEl = document.getElementById("backendPort");
      var wsPathEl = document.getElementById("wsPath");
      var fakeHostEl = document.getElementById("fakeHost");
      var sniEl = document.getElementById("sni");
      var uaEl = document.getElementById("ua");

      if (!uuidEl.value) return showMsg("❌ UUID 不能为空", true);
      if (!workerHostEl.value) return showMsg("❌ Worker 域名不能为空", true);
      if (!backendHostEl.value) return showMsg("❌ 后端域名不能为空", true);
      if (!backendPortEl.value) return showMsg("❌ 后端端口不能为空", true);

      var nodesDivs = document.querySelectorAll("#nodes > div");
      var nodesData = [];
      nodesDivs.forEach(function(d){
        nodesData.push({
          host: d.querySelector(".node-host").value,
          name: d.querySelector(".node-name").value
        });
      });

      var cfg = {
        uuid: uuidEl.value,
        workerHost: workerHostEl.value,
        wsPath: wsPathEl.value,
        backendHost: backendHostEl.value,
        backendPort: backendPortEl.value,
        fakeHost: fakeHostEl.value,
        sni: sniEl.value,
        ua: uaEl.value,
        mode: mode,
        nodes: nodesData
      };

      await fetch("/api/set-config", {
        method: "POST",
        body: JSON.stringify(cfg)
      });

      showMsg("✅ 已保存配置");
    };

    document.getElementById("resetCfg").onclick = async function () {
      if (!confirm("确定要清空节点配置？此操作不可恢复。")) return;
      await fetch("/api/reset-config");
      location.reload();
    };

    function showMsg(text, isError) {
      var m = document.getElementById("msg");
      m.textContent = text;
      m.style.color = isError ? "red" : "green";
      setTimeout(function(){ m.textContent = ""; }, 3000);
    }

    loadConfig();
  <\/script>
</body>
</html>`;
}


// ===============================================================
// Config Loader
// ===============================================================
async function loadConfig(env) {
  const raw = await env.CONFIG_KV.get("CONFIG_JSON");
  if (!raw) {
    return {
      uuid: "",
      workerHost: "",
      wsPath: "/echws",
      backendHost: "",
      backendPort: "2082",
      fakeHost: "",
      sni: "",
      ua: "",
      mode: "A",
      nodes: []
    };
  }
  return JSON.parse(raw);
}

// ===============================================================
// VLESS URL builder
// ===============================================================
function buildVlessUrl(cfg, hostOverride = null, name = "Node") {
  const host = hostOverride || cfg.workerHost;
  const params = new URLSearchParams({
    encryption: "none",
    security: "tls",
    type: "ws",
    path: cfg.wsPath,
    host: cfg.fakeHost || cfg.workerHost,
    sni: cfg.sni || cfg.workerHost
  });
  return `vless://${cfg.uuid}@${host}:443?${params.toString()}#${encodeURIComponent(name)}`;
}

// ===============================================================
// v2rayN Subscription text
// ===============================================================
function generateV2raySub(cfg, ipOption) {
  const list = [];
  ipOption = ipOption || { mode: "domain", ips: [] };
  const mode = ipOption.mode || "domain";
  const ips = Array.isArray(ipOption.ips) ? ipOption.ips : (ipOption.ip ? [ipOption.ip] : []);

  const ipOnly = (mode === "ip");

  // 1）域名节点（非 ip-only 模式才添加）
  if (!ipOnly) {
    list.push(buildVlessUrl(cfg, null, "主节点"));
    if (cfg.nodes && Array.isArray(cfg.nodes)) {
      cfg.nodes.forEach(function(n) {
        if (!n.host) return;
        list.push(buildVlessUrl(cfg, n.host, n.name || n.host));
      });
    }
  }

  // 2）IP 备胎节点
  if ((mode === "dual" || mode === "ip") && ips.length) {
    ips.forEach(function(ip, idx) {
      if (!ip) return;
      const name = "优选IP节点" + (ips.length > 1 ? (idx + 1) : "");
      list.push(buildVlessUrl(cfg, ip, name));
    });
  }

  return list.join("\n");
}



// 根据 Cloudflare colo 返回一个推荐 IP 列表（示例，可按需调整为你实测的 IP）
function pickIpListByColo(colo) {
  colo = (colo || "").toUpperCase();
  // A 类：亚洲常见优选（HKG / TPE / SIN / ICN）
  if (colo === "HKG" || colo === "TPE" || colo === "SIN" || colo === "ICN") {
    return [
      "188.114.97.3",
      "188.114.96.3",
      "104.16.1.3"
    ];
  }
  // 日本 / 关西等
  if (colo === "NRT" || colo === "KIX") {
    return [
      "104.16.1.3",
      "104.17.1.3",
      "188.114.96.3"
    ];
  }
  // 北美常见入口
  if (colo === "LAX" || colo === "SJC" || colo === "SEA" || colo === "ORD" || colo === "DFW" || colo === "IAD" || colo === "JFK") {
    return [
      "188.114.96.3",
      "188.114.97.3",
      "141.101.64.3"
    ];
  }
  // 其他未知地区，返回一个相对通用的组合
  return [
    "188.114.96.3",
    "188.114.97.3",
    "104.16.1.3"
  ];
}

// 单 IP 版本：保留给可能需要的地方使用（取列表第一个）
function pickIpByColo(colo) {
  const list = pickIpListByColo(colo);
  return list && list.length ? list[0] : "188.114.96.3";
}


function renderSpeedtestPage() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8" />
  <title>Cloudflare Worker 速度测试工具</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"><\/script>
</head>
<body class="min-h-screen bg-slate-100 p-4">
  <div class="max-w-4xl mx-auto space-y-6">
    <div class="bg-white rounded-2xl shadow p-6">
      <h1 class="text-2xl font-bold mb-2">⚡ Cloudflare Worker 线路测速</h1>
      <p class="text-sm text-slate-600 mb-4">
        本页面用于测试当前 Worker 域名的实际访问延迟与下载速度，并提供一个简单的“自定义 URL 批量测速”工具，方便你对比不同 CF 优选 IP 或不同域名的表现。
      </p>
      <a href="/" class="text-blue-600 text-sm underline">← 返回管理面板</a>
    </div>

    <!-- 单节点测速 -->
    <div class="bg-white rounded-2xl shadow p-6">
      <h2 class="text-xl font-semibold mb-4">一、当前 Worker 域名测速</h2>
      <p class="text-sm text-slate-600 mb-2">
        将对当前域名执行多次延迟测试（ping），并下载 1MB 测试文件，粗略估算下载速度。
      </p>
      <button id="btnPing" class="px-4 py-2 rounded-lg bg-blue-600 text-white font-semibold mb-3">
        开始单节点测速
      </button>
      <pre id="pingResult" class="bg-slate-950 text-slate-100 text-xs rounded-lg p-3 overflow-x-auto h-40"></pre>
    </div>

    <!-- 批量测速 -->
    <div class="bg-white rounded-2xl shadow p-6">
      <h2 class="text-xl font-semibold mb-4">二、自定义 URL 批量测速（配合优选 IP 使用）</h2>
      <p class="text-sm text-slate-600 mb-2">
        在下方输入要测试的 URL（每行一个）。可用于：
      </p>
      <ul class="list-disc ml-6 text-sm text-slate-600 mb-3">
        <li>给多个不同子域名分别绑定不同 CF IP，然后依次测速。</li>
        <li>或在本机 hosts 中，将同一域名指向不同 CF IP，填入对应 URL 进行对比。</li>
      </ul>
      <textarea id="urlList" class="w-full h-32 border rounded-lg p-2 text-sm mb-3" placeholder="例如：&#10;https://ech1.yourdomain.com/speed.bin&#10;https://ech2.yourdomain.com/speed.bin"></textarea>
      <button id="btnBatch" class="px-4 py-2 rounded-lg bg-emerald-600 text-white font-semibold mb-3">
        开始批量测速
      </button>
      <pre id="batchResult" class="bg-slate-950 text-slate-100 text-xs rounded-lg p-3 overflow-x-auto h-52"></pre>
    </div>
  </div>

  <script>
    async function runSingleTest() {
      var out = [];
      var logEl = document.getElementById("pingResult");
      logEl.textContent = "开始测试...\\n";

      // 延迟测试：多次请求 /api/geo
      var count = 5;
      var times = [];
      for (var i = 0; i < count; i++) {
        var t0 = performance.now();
        try {
          await fetch("/api/geo?ts=" + Math.random(), { cache: "no-store" });
          var t1 = performance.now();
          var ms = Math.round(t1 - t0);
          times.push(ms);
          out.push("第 " + (i+1) + " 次延迟：" + ms + " ms");
        } catch(e) {
          out.push("第 " + (i+1) + " 次延迟测试失败：" + e);
        }
        logEl.textContent = out.join("\\n");
      }

      if (times.length) {
        var sum = times.reduce(function(a,b){return a+b;},0);
        var avg = Math.round(sum / times.length);
        var min = Math.min.apply(null, times);
        var max = Math.max.apply(null, times);
        out.push("");
        out.push("延迟统计：");
        out.push("  次数：" + times.length);
        out.push("  平均：" + avg + " ms");
        out.push("  最小：" + min + " ms");
        out.push("  最大：" + max + " ms");
      }

      logEl.textContent = out.join("\\n");

      // 下载测速：/speed.bin (约 1MB)
      out.push("");
      out.push("开始下载测速 /speed.bin (约 1MB)...");
      logEl.textContent = out.join("\\n");

      try {
        var t0d = performance.now();
        var resp = await fetch("/speed.bin?ts=" + Math.random(), { cache: "no-store" });
        var buf = await resp.arrayBuffer();
        var t1d = performance.now();
        var msd = t1d - t0d;
        var sizeBytes = buf.byteLength;
        var speedMbps = (sizeBytes * 8 / 1024 / 1024) / (msd / 1000);
        out.push("下载用时：" + Math.round(msd) + " ms");
        out.push("下载大小：" + sizeBytes + " 字节");
        out.push("估算下行速度：" + speedMbps.toFixed(2) + " Mbps");
      } catch(e) {
        out.push("下载测速失败：" + e);
      }

      logEl.textContent = out.join("\\n");
    }

    async function runBatchTest() {
      var txt = document.getElementById("urlList").value || "";
      var lines = txt.split(/\\r?\\n/).map(function(l){return l.trim();}).filter(function(l){return l;});
      var out = [];
      var logEl = document.getElementById("batchResult");
      if (!lines.length) {
        logEl.textContent = "请先在上方文本框中填入要测试的 URL，每行一个。";
        return;
      }
      out.push("共 " + lines.length + " 个 URL，将依次进行测试（只做一次下载测速）...");
      logEl.textContent = out.join("\\n");

      for (var i = 0; i < lines.length; i++) {
        var url = lines[i];
        out.push("");
        out.push("[" + (i+1) + "/" + lines.length + "] 测试：" + url);
        logEl.textContent = out.join("\\n");
        try {
          var t0 = performance.now();
          var resp = await fetch(url, { cache: "no-store" });
          var buf = await resp.arrayBuffer();
          var t1 = performance.now();
          var ms = t1 - t0;
          var sizeBytes = buf.byteLength;
          var speedMbps = (sizeBytes * 8 / 1024 / 1024) / (ms / 1000);
          out.push("  用时：" + Math.round(ms) + " ms");
          out.push("  大小：" + sizeBytes + " 字节");
          out.push("  估算速度：" + speedMbps.toFixed(2) + " Mbps");
        } catch(e) {
          out.push("  测试失败：" + e);
        }
        logEl.textContent = out.join("\\n");
      }

      out.push("");
      out.push("批量测速完成。可对比各 URL 的时延与 Mbps 评估哪条 CF 线路更优。");
      logEl.textContent = out.join("\\n");
    }

    document.getElementById("btnPing").onclick = function(){ runSingleTest(); };
    document.getElementById("btnBatch").onclick = function(){ runBatchTest(); };
  <\/script>
</body>
</html>`;
}

// ===============================================================
// SingBox JSON
// ===============================================================
function generateSingbox(cfg) {
  const outbounds = [];

  outbounds.push({
    type: "vless",
    tag: "主节点",
    server: cfg.workerHost,
    server_port: 443,
    uuid: cfg.uuid,
    tls: {
      enabled: true,
      server_name: cfg.sni || cfg.workerHost
    },
    transport: {
      type: "ws",
      path: cfg.wsPath,
      headers: {
        Host: cfg.fakeHost || cfg.workerHost
      }
    }
  });

  if (cfg.nodes && Array.isArray(cfg.nodes)) {
    cfg.nodes.forEach(n => {
      if (!n.host) return;
      outbounds.push({
        type: "vless",
        tag: n.name || n.host,
        server: n.host,
        server_port: 443,
        uuid: cfg.uuid,
        tls: {
          enabled: true,
          server_name: cfg.sni || n.host
        },
        transport: {
          type: "ws",
          path: cfg.wsPath,
          headers: {
            Host: cfg.fakeHost || n.host
          }
        }
      });
    });
  }

  return { outbounds };
}

// ===============================================================
// Clash Meta YAML
// ===============================================================
function generateClash(cfg) {
  const proxies = [];

  function addNode(name, host) {
    proxies.push({
      name,
      type: "vless",
      server: host,
      port: 443,
      uuid: cfg.uuid,
      tls: true,
      servername: cfg.sni || host,
      network: "ws",
      ws_opts: {
        path: cfg.wsPath,
        headers: {
          Host: cfg.fakeHost || host
        }
      }
    });
  }

  addNode("主节点", cfg.workerHost);
  if (cfg.nodes && Array.isArray(cfg.nodes)) {
    cfg.nodes.forEach(n => {
      if (!n.host) return;
      addNode(n.name || n.host, n.host);
    });
  }

  let yaml = "proxies:\n";
  proxies.forEach(p => {
    yaml += `  - name: "${p.name}"
    type: vless
    server: ${p.server}
    port: 443
    uuid: ${p.uuid}
    tls: true
    servername: ${p.servername}
    network: ws
    ws-opts:
      path: ${p.ws_opts.path}
      headers:
        Host: ${p.ws_opts.headers.Host}
`;
  });

  return yaml;
}

// ===============================================================
// QR Code (Google Chart API)
// ===============================================================
async function generateQRCode(cfg) {
  const vlessUrl = buildVlessUrl(cfg, null, "主节点");
  const api =
    "https://chart.googleapis.com/chart?cht=qr&chs=400x400&chl=" +
    encodeURIComponent(vlessUrl);

  const resp = await fetch(api);
  return resp.arrayBuffer();
}

// ===============================================================
// WebSocket Proxy (Mode A & B)
// ===============================================================
async function handleWS(request, cfg) {
  if (cfg.mode === "B") {
    return handleWS_B(request, cfg);
  }
  return handleWS_A(request, cfg);
}

// --- Mode A: Stable ---
async function handleWS_A(request, cfg) {
  const backendUrl = `http://${cfg.backendHost}:${cfg.backendPort}${cfg.wsPath}`;
  const headers = new Headers(request.headers);
  headers.set("Host", cfg.backendHost);

  const backendReq = new Request(backendUrl, {
    method: request.method,
    headers,
    body: request.body
  });

  let resp;
  try {
    resp = await fetch(backendReq);
  } catch (e) {
    return new Response("Backend connection failed (mode A)", { status: 502 });
  }

  if (resp.status !== 101) {
    return new Response("WebSocket upgrade failed (mode A)", { status: 502 });
  }
  return resp;
}

// --- Mode B: Obfuscated ---
async function handleWS_B(request, cfg) {
  const backendUrl = `http://${cfg.backendHost}:${cfg.backendPort}${cfg.wsPath}`;
  const headers = new Headers(request.headers);

  if (cfg.fakeHost) {
    headers.set("Host", cfg.fakeHost);
  }
  if (cfg.ua) {
    headers.set("User-Agent", cfg.ua);
  }
  if (cfg.sni) {
    headers.set("CF-Connecting-SNI", cfg.sni);
  }

  headers.set("X-Forwarded-For", "1.1.1.1");
  headers.set("X-Real-IP", "1.1.1.1");

  const backendReq = new Request(backendUrl, {
    method: request.method,
    headers,
    body: request.body
  });

  let resp;
  try {
    resp = await fetch(backendReq);
  } catch (e) {
    return new Response("Backend connection failed (mode B)", { status: 503 });
  }

  if (resp.status !== 101) {
    return new Response("WebSocket upgrade failed (mode B)", { status: 502 });
  }
  return resp;
}
