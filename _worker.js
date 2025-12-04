// ============================================================
// VLESS Edge Worker + 管理面板 + KV 存储
// 适用于 Cloudflare Workers / Pages Functions
// 通过 CONFIG_KV 保存配置：UUID / Worker 域名 / WS 路径 / VPS 等
// ============================================================

/**
 * 默认配置（首次运行 / KV 为空时使用）
 * 保存后会写入 KV，下次读取 KV
 */
const DEFAULT_CONFIG = {
  uuid: "d50b4326-41b4-455b-899f-9452690286fe", // 默认 UUID，可在面板修改
  workerHost: "ec.firegod.eu.org",              // Worker 域名
  wsPath: "/echws",                             // WS 路径
  backendHost: "cc1.firegod.eu.org",            // 后端 VPS 域名
  backendPort: 2082,                            // 后端 WS 端口（无 TLS）
  panelPassword: "admin123",                    // 面板登录密码（首次默认，可改）
  enableMultiUser: false,                       // 是否多 UUID 模式（简化版先关）
};

/**
 * 从 KV 加载配置
 */
async function loadConfig(env) {
  if (!env.CONFIG_KV) {
    throw new Error("CONFIG_KV 未绑定，请在 Worker 设置里绑定 KV 命名空间，绑定名必须为 CONFIG_KV");
  }
  const raw = await env.CONFIG_KV.get("EDGE_CONFIG");
  if (!raw) {
    // KV 为空时写入默认配置
    await env.CONFIG_KV.put("EDGE_CONFIG", JSON.stringify(DEFAULT_CONFIG));
    return { ...DEFAULT_CONFIG };
  }
  try {
    const data = JSON.parse(raw);
    return { ...DEFAULT_CONFIG, ...data };
  } catch (e) {
    console.error("KV 配置 JSON 解析失败，使用默认配置", e);
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * 保存配置到 KV
 */
async function saveConfig(env, config) {
  if (!env.CONFIG_KV) {
    throw new Error("CONFIG_KV 未绑定");
  }
  await env.CONFIG_KV.put("EDGE_CONFIG", JSON.stringify(config));
}

/**
 * 简单 HTML 模板
 */
function htmlTemplate(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<title>${title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f5f5f7;margin:0;padding:0;color:#111}
  .navbar{background:#111827;color:#fff;padding:12px 20px;font-size:18px;font-weight:600;display:flex;align-items:center}
  .navbar span{margin-left:8px}
  .container{max-width:960px;margin:24px auto;padding:0 12px 40px}
  .card{background:#fff;border-radius:12px;box-shadow:0 10px 30px rgba(15,23,42,.08);padding:20px 22px;margin-bottom:18px;border:1px solid #e5e7eb}
  .card h2{font-size:18px;margin:0 0 14px;font-weight:600;color:#111827;display:flex;align-items:center}
  .card h2 span{font-size:14px;font-weight:500;color:#6b7280;margin-left:8px}
  .field{margin-bottom:12px}
  .field label{display:block;font-size:13px;color:#374151;margin-bottom:4px}
  .field input, .field select, .field textarea{width:100%;padding:8px 10px;border-radius:8px;border:1px solid #d1d5db;font-size:13px;box-sizing:border-box}
  .field input:focus, .field textarea:focus, .field select:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 1px rgba(37,99,235,.35)}
  .help{font-size:12px;color:#6b7280;margin-top:2px}
  .btn{display:inline-flex;align-items:center;justify-content:center;padding:7px 14px;border-radius:999px;border:none;cursor:pointer;font-size:13px;font-weight:500}
  .btn-primary{background:#2563eb;color:#fff}
  .btn-primary:hover{background:#1d4ed8}
  .btn-secondary{background:#f3f4f6;color:#111827}
  .btn-secondary:hover{background:#e5e7eb}
  .btn-danger{background:#ef4444;color:#fff}
  .btn-danger:hover{background:#dc2626}
  .row{display:flex;flex-wrap:wrap;margin:-4px}
  .col-6{width:50%;padding:4px;box-sizing:border-box}
  .badge{display:inline-flex;align-items:center;border-radius:999px;background:#ecfeff;color:#0e7490;font-size:11px;padding:2px 8px;margin-right:4px}
  .badge-red{background:#fee2e2;color:#b91c1c}
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,"Liberation Mono","Courier New",monospace}
  .muted{color:#6b7280;font-size:13px}
  .mt8{margin-top:8px}
  .mt12{margin-top:12px}
  .mt16{margin-top:16px}
  .tag{display:inline-block;margin-right:4px;border-radius:999px;background:#eef2ff;color:#4338ca;font-size:11px;padding:2px 8px}
  .table{width:100%;border-collapse:collapse;font-size:13px}
  .table th,.table td{padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:left}
  .table th{background:#f9fafb;color:#374151;font-weight:500}
  .pill{display:inline-flex;align-items:center;border-radius:999px;background:#111827;color:#e5e7eb;padding:3px 8px;font-size:11px;margin-right:4px}
  a{color:#2563eb;text-decoration:none}
  a:hover{text-decoration:underline}
  .top-notice{font-size:13px;color:#4b5563;margin-bottom:12px}
  .code{background:#111827;color:#e5e7eb;border-radius:8px;padding:10px 12px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,"Liberation Mono","Courier New",monospace;font-size:12px;overflow-x:auto}
  @media (max-width:768px){
    .col-6{width:100%}
    .navbar{font-size:16px}
  }
  .badge-green{background:#dcfce7;color:#15803d}
  .badge-yellow{background:#fef9c3;color:#854d0e}
</style>
</head>
<body>
<div class="navbar">
  <span>🚀</span><span>VLESS Edge 节点管理系统</span>
</div>
<div class="container">
${bodyHtml}
</div>
</body>
</html>`;
}

/**
 * 登录页
 */
function renderLoginPage(message = "") {
  const body = `
  <div class="card">
    <h2>登录面板 <span>请输入面板密码</span></h2>
    ${message ? `<div class="badge-red" style="margin-bottom:10px;">${message}</div>` : ""}
    <form method="post" action="/login">
      <div class="field">
        <label>面板密码</label>
        <input type="password" name="password" placeholder="请输入配置的面板密码" required />
      </div>
      <button class="btn btn-primary mt8" type="submit">登录</button>
    </form>
    <p class="mt16 muted">
      首次使用默认密码为 <span class="mono badge">admin123</span>，登录后请尽快在下方修改为复杂密码。
    </p>
  </div>`;
  return new Response(htmlTemplate("登录面板", body), {
    status: 200,
    headers: { "content-type": "text/html;charset=utf-8" },
  });
}

/**
 * 主配置页
 */
function renderConfigPage(config) {
  const {
    uuid,
    workerHost,
    wsPath,
    backendHost,
    backendPort,
    panelPassword,
  } = config;

  const subUrl = `https://${workerHost}/sub`;
  const clashUrl = `https://${workerHost}/clash`;
  const singboxUrl = `https://${workerHost}/singbox`;

  const body = `
  <div class="card">
    <h2>当前线路状态 / 入口节点 <span>通过 Cloudflare ECH-Workers 回源后端 VPS</span></h2>
    <p class="top-notice">
      通过本面板，你可以可视化配置 Cloudflare Worker 反代的 VLESS 节点，并一键生成 v2rayN / SingBox / Clash 订阅。
    </p>
    <p class="muted">
      建议：开启 TLS，选择自动 IP 或优选 IP，为避免被动暴露真实 IP，建议使用香港/台湾等中转节点承载。
    </p>
  </div>

  <form method="post" action="/save">
    <div class="card">
      <h2>基础参数配置</h2>
      <div class="field">
        <label>UUID（必填）</label>
        <input type="text" name="uuid" value="${uuid}" required />
        <div class="help">建议使用 Xray / 3x-ui 中已配置的 UUID，保持前后端一致。</div>
      </div>

      <div class="field">
        <label>Worker 域名（必填）</label>
        <input type="text" name="workerHost" value="${workerHost}" required />
        <div class="help">例如：<span class="mono">ech.firegod.eu.org</span>。必须是已经 CNAME 到本 Worker 的域名，且为橙云。</div>
      </div>

      <div class="field">
        <label>WS 路径（必填）</label>
        <input type="text" name="wsPath" value="${wsPath}" required />
        <div class="help">例如：<span class="mono">/echws</span>。需要与后端 WS 入站路径一致。</div>
      </div>

      <div class="field">
        <label>后端 VPS 域名（必填）</label>
        <input type="text" name="backendHost" value="${backendHost}" required />
        <div class="help">例如：<span class="mono">cc1.firegod.eu.org</span>。建议使用带证书的域名（仅用于 SNI），后端仍然是纯 WS，无 TLS。</div>
      </div>

      <div class="field">
        <label>后端端口（必填）</label>
        <input type="number" name="backendPort" value="${backendPort}" required />
        <div class="help">后端端口为 Xray WS 入站端口（无需 TLS）。本 Worker 将通过 <span class="mono">ws://</span> 后端转发客户端流量。</div>
      </div>

      <hr class="mt16" />

      <div class="field mt16">
        <label>面板密码</label>
        <input type="password" name="panelPassword" value="${panelPassword}" />
        <div class="help">用于登录本配置面板。请设置为复杂密码并妥善保存。</div>
      </div>

      <button class="btn btn-primary mt16" type="submit">保存配置</button>
    </div>
  </form>

  <div class="card">
    <h2>订阅与导出 <span>一键下发到客户端</span></h2>
    <p class="muted">完成基础配置并生效后，可以通过以下链接在客户端中导入配置：</p>
    <div class="field">
      <label>v2rayN 订阅</label>
      <div class="code mono">${subUrl}</div>
    </div>
    <div class="field">
      <label>Clash Meta 配置</label>
      <div class="code mono">${clashUrl}</div>
    </div>
    <div class="field">
      <label>Sing-box 配置</label>
      <div class="code mono">${singboxUrl}</div>
    </div>
  </div>

  <div class="card">
    <h2>使用说明 & 注意事项</h2>
    <ul class="muted">
      <li>确保 Worker 域名在 Cloudflare DNS 面板中为 <span class="pill">Proxied（橙云）</span>。</li>
      <li>后端 Xray / 3x-ui 中的入站协议为 VLESS + WS，关闭 TLS，由 Cloudflare 负责 TLS。</li>
      <li>建议在 Worker 前端启用 ECH / HTTP3 / 0-RTT 等特性，以提升性能。</li>
      <li>如需多节点 / 多 UUID，可在后续版本中启用多用户配置功能。</li>
    </ul>
  </div>`;
  return new Response(htmlTemplate("VLESS Edge 节点管理系统", body), {
    status: 200,
    headers: { "content-type": "text/html;charset=utf-8" },
  });
}

/**
 * 生成单个 vless 节点链接
 */
function buildVlessUrl(config) {
  const { uuid, workerHost, wsPath } = config;
  const host = workerHost;
  const path = wsPath.startsWith("/") ? wsPath : `/${wsPath}`;
  return `vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&path=${encodeURIComponent(
    path
  )}&sni=${host}&host=${host}#VLESS_Edge`;
}

/**
 * 生成 v2rayN 订阅（base64）
 */
function buildSub(config) {
  const url = buildVlessUrl(config);
  const b64 = btoa(unescape(encodeURIComponent(url)));
  return b64;
}

/**
 * 生成 Clash Meta 配置（简单单节点版本）
 */
function buildClash(config) {
  const { uuid, workerHost, wsPath } = config;
  const host = workerHost;
  const path = wsPath.startsWith("/") ? wsPath : `/${wsPath}`;
  const yaml = `
proxies:
  - name: "vless-edge"
    type: vless
    server: ${host}
    port: 443
    uuid: ${uuid}
    tls: true
    servername: ${host}
    network: ws
    ws-opts:
      path: "${path}"
      headers:
        Host: ${host}
`;
  return yaml.trim();
}

/**
 * 生成 Sing-box 配置（简化）
 */
function buildSingbox(config) {
  const { uuid, workerHost, wsPath } = config;
  const host = workerHost;
  const path = wsPath.startsWith("/") ? wsPath : `/${wsPath}`;
  const obj = {
    outbounds: [
      {
        type: "vless",
        tag: "vless-edge",
        server: host,
        server_port: 443,
        uuid,
        flow: "xtls-rprx-vision",
        tls: {
          enabled: true,
          server_name: host,
          insecure: false,
        },
        transport: {
          type: "ws",
          path,
          headers: {
            Host: host,
          },
        },
      },
    ],
  };
  return JSON.stringify(obj, null, 2);
}

/**
 * 工具：解析表单
 */
async function parseFormData(request) {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const text = await request.text();
    const params = new URLSearchParams(text);
    const obj = {};
    for (const [key, value] of params.entries()) {
      obj[key] = value;
    }
    return obj;
  }
  return {};
}

/**
 * Worker 主逻辑
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 静态资源
    if (pathname === "/favicon.ico") {
      return new Response("", { status: 204 });
    }

    // 登录态使用简单 Cookie 标记
    const cookie = request.headers.get("Cookie") || "";
    const loggedIn = cookie.includes("EDGE_ADMIN_AUTH=1");

    // 加载配置（大部分路由都需要）
    let config;
    try {
      config = await loadConfig(env);
    } catch (e) {
      console.error(e);
      return new Response(
        "CONFIG_KV 未正确绑定，请在 Worker 设置中绑定 KV 命名空间，绑定名为 CONFIG_KV。",
        { status: 500 }
      );
    }

    // 登录 / 登出
    if (pathname === "/login") {
      if (request.method === "GET") {
        return renderLoginPage();
      } else if (request.method === "POST") {
        const form = await parseFormData(request);
        const pwd = form.password || "";
        if (pwd && pwd === config.panelPassword) {
          // 设置 cookie
          const resp = new Response(
            `<script>location.href='/'</script>`,
            { status: 200, headers: { "content-type": "text/html;charset=utf-8" } }
          );
          resp.headers.set(
            "Set-Cookie",
            "EDGE_ADMIN_AUTH=1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
          );
          return resp;
        } else {
          return renderLoginPage("密码错误，请重试。");
        }
      }
    }

    if (pathname === "/logout") {
      const resp = new Response(
        `<script>location.href='/login'</script>`,
        { status: 200, headers: { "content-type": "text/html;charset=utf-8" } }
      );
      resp.headers.set(
        "Set-Cookie",
        "EDGE_ADMIN_AUTH=0; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
      );
      return resp;
    }

    // 未登录 → 跳转登录
    const adminPaths = ["/", "/save"];
    if (adminPaths.includes(pathname) && !loggedIn) {
      return Response.redirect("/login", 302);
    }

    // 保存配置
    if (pathname === "/save" && request.method === "POST") {
      const form = await parseFormData(request);
      const newConfig = {
        ...config,
        uuid: (form.uuid || config.uuid).trim(),
        workerHost: (form.workerHost || config.workerHost).trim(),
        wsPath: (form.wsPath || config.wsPath).trim(),
        backendHost: (form.backendHost || config.backendHost).trim(),
        backendPort: parseInt(form.backendPort || config.backendPort, 10) || 2082,
        panelPassword: form.panelPassword || config.panelPassword,
      };
      await saveConfig(env, newConfig);
      return new Response(
        `<script>alert('保存成功');location.href='/'</script>`,
        { status: 200, headers: { "content-type": "text/html;charset=utf-8" } }
      );
    }

    // 管理首页
    if (pathname === "/") {
      return renderConfigPage(config);
    }

    // 订阅导出
    if (pathname === "/sub") {
      const b64 = buildSub(config);
      return new Response(b64, {
        status: 200,
        headers: { "content-type": "text/plain;charset=utf-8" },
      });
    }

    if (pathname === "/clash") {
      const yaml = buildClash(config);
      return new Response(yaml, {
        status: 200,
        headers: { "content-type": "text/plain;charset=utf-8" },
      });
    }

    if (pathname === "/singbox") {
      const json = buildSingbox(config);
      return new Response(json, {
        status: 200,
        headers: { "content-type": "application/json;charset=utf-8" },
      });
    }

    // WebSocket / VLESS 代理入口
    if (pathname === config.wsPath || pathname === (DEFAULT_CONFIG.wsPath)) {
      if (request.headers.get("Upgrade") === "websocket") {
        return handleVlessOverWS(request, config);
      }
      return new Response("Not a websocket request", { status: 400 });
    }

    return new Response("Not Found", { status: 404 });
  },
};

/**
 * 处理 VLESS over WebSocket
 * 简化版：不做多用户 / 统计，只做转发
 */
async function handleVlessOverWS(request, config) {
  const { backendHost, backendPort } = config;

  const [clientWs, clientWsServer] = Object.values(new WebSocketPair());
  const url = `ws://${backendHost}:${backendPort}${config.wsPath}`;

  const backendWsPromise = fetch(url, {
    headers: {
      Upgrade: "websocket",
      Connection: "Upgrade",
    },
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWsServer,
  });
}
