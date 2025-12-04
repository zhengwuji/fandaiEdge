// ===============================================================
// VLESS Edge Worker with Admin UI + Password Login (No KV)
// ---------------------------------------------------------------
// - Admin UI (Tailwind) at "/"
// - Login page with password + "show password" + "remember me 1 day"
// - Password from ADMIN_PASSWORD environment variable
// - Session token stored in Cookie (encrypted with SESSION_SECRET)
// - Config stored in Cookie / URL parameters (no KV)
// - Subscription endpoints: /sub, /singbox, /clash, /qrcode
// - WebSocket VLESS proxy with mode A (stable) and B (obfuscated)
// ---------------------------------------------------------------
// IMPORTANT: This version does NOT require KV storage.
// Environment Variables Required:
// 1. ADMIN_PASSWORD - Admin login password (set in Cloudflare Dashboard)
// 2. SESSION_SECRET - Secret key for signing/encrypting cookies (set in Cloudflare Dashboard)
// All config data is stored in Cookies or URL parameters.
// ===============================================================

// Base64 encoding helper (compatible with Cloudflare Workers)
function base64Encode(str) {
  try {
    // Cloudflare Workers support btoa, but need to handle UTF-8 properly
    if (typeof btoa === "function") {
      // Convert UTF-8 string to binary string for btoa
      const utf8Bytes = new TextEncoder().encode(str);
      let binary = '';
      for (let i = 0; i < utf8Bytes.length; i++) {
        binary += String.fromCharCode(utf8Bytes[i]);
      }
      return btoa(binary);
    }
    // Fallback: manual base64 encoding
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const utf8Bytes = new TextEncoder().encode(str);
    let result = '';
    let i = 0;
    while (i < utf8Bytes.length) {
      const a = utf8Bytes[i++];
      const b = i < utf8Bytes.length ? utf8Bytes[i++] : 0;
      const c = i < utf8Bytes.length ? utf8Bytes[i++] : 0;
      const bitmap = (a << 16) | (b << 8) | c;
      result += chars.charAt((bitmap >> 18) & 63);
      result += chars.charAt((bitmap >> 12) & 63);
      result += i - 2 < utf8Bytes.length ? chars.charAt((bitmap >> 6) & 63) : '=';
      result += i - 1 < utf8Bytes.length ? chars.charAt(bitmap & 63) : '=';
    }
    return result;
  } catch (e) {
    // Ultimate fallback: return empty string
    console.error("Base64 encoding error:", e);
    return '';
  }
}

// Simple hash function for password verification (using Web Crypto API)
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple encryption/decryption using Web Crypto API (AES-CBC for compatibility)
async function encrypt(text, key) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    // Use first 32 bytes of key hash as actual key
    const keyHash = await crypto.subtle.digest('SHA-256', encoder.encode(key));
    const keyBytes = new Uint8Array(keyHash).slice(0, 16); // AES-128-CBC uses 16-byte key
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: iv },
      cryptoKey,
      data
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  } catch (e) {
    // Fallback: simple base64 encoding (not secure, but works)
    return btoa(unescape(encodeURIComponent(text))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}

async function decrypt(encrypted, key) {
  try {
    const encoder = new TextEncoder();
    const data = Uint8Array.from(atob(encrypted.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const iv = data.slice(0, 16);
    const encryptedData = data.slice(16);
    
    // Use first 32 bytes of key hash as actual key
    const keyHash = await crypto.subtle.digest('SHA-256', encoder.encode(key));
    const keyBytes = new Uint8Array(keyHash).slice(0, 16); // AES-128-CBC uses 16-byte key
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: iv },
      cryptoKey,
      encryptedData
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    // Fallback: simple base64 decoding
    try {
      return decodeURIComponent(escape(atob(encrypted.replace(/-/g, '+').replace(/_/g, '/'))));
    } catch (e2) {
      return null;
    }
  }
}

// Get session secret from Worker's environment or use a default
function getSessionSecret(env) {
  // Use SESSION_SECRET environment variable for signing/encrypting cookies
  // In production, set SESSION_SECRET in Cloudflare Dashboard → Workers → Settings → Variables
  return env.SESSION_SECRET || 'vless-session-secret-2024-default-change-me';
}

// Get admin password from Worker's environment
function getAdminPassword(env) {
  // Use ADMIN_PASSWORD environment variable
  // Set it in Cloudflare Dashboard → Workers → Settings → Variables
  return env.ADMIN_PASSWORD || null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const sessionSecret = getSessionSecret(env);
    const adminPassword = getAdminPassword(env);

    // --- Auth-related routing ---
    if (pathname === "/login" && request.method === "GET") {
      const hasPw = !!adminPassword;
      return new Response(renderLoginPage("", !hasPw, adminPassword), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    if (pathname === "/login" && request.method === "POST") {
      return handleLogin(request, env, sessionSecret, adminPassword);
    }

    // --- Admin UI, protected ---
    if (pathname === "/" || pathname === "/index") {
      const authed = await isAuthenticated(request, sessionSecret);
      const hasPw = !!adminPassword;
      if (!authed) {
        return new Response(renderLoginPage("", !hasPw, adminPassword), {
          headers: { "content-type": "text/html; charset=utf-8" }
        });
      }
      return new Response(renderAdminUI(), {
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    // --- Protected JSON APIs (config) ---
    if (pathname === "/api/get-config") {
      if (!(await isAuthenticated(request, sessionSecret))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const cookies = parseCookies(request.headers.get("Cookie") || "");
      const configCookie = cookies["vless_config"];
      let data = "{}";
      if (configCookie) {
        try {
          const decrypted = await decrypt(configCookie, sessionSecret);
          if (decrypted) data = decrypted;
        } catch (e) {}
      }
      // Also check URL parameter
      const cfgParam = url.searchParams.get("cfg");
      if (cfgParam) {
        try {
          const decoded = decodeURIComponent(cfgParam);
          data = decoded;
        } catch (e) {}
      }
      return new Response(data, {
        headers: { "content-type": "application/json" }
      });
    }

    if (pathname === "/api/set-config") {
      if (!(await isAuthenticated(request, sessionSecret))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const body = await request.text();
      const encrypted = await encrypt(body, sessionSecret);
      const headers = new Headers();
      headers.set("Set-Cookie", `vless_config=${encrypted}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=31536000`);
      headers.set("content-type", "text/plain");
      return new Response("OK", { headers });
    }

    if (pathname === "/api/reset-config") {
      if (!(await isAuthenticated(request, sessionSecret))) {
        return new Response("Unauthorized", { status: 401 });
      }
      const headers = new Headers();
      headers.set("Set-Cookie", `vless_config=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`);
      return new Response("RESET_OK", { headers });
    }

    // --- Health Check API (健康检查) ---
    if (pathname === "/health" || pathname === "/api/health") {
      const cfg = await loadConfig(request, url, sessionSecret);
      const health = {
        status: "ok",
        timestamp: new Date().toISOString(),
        worker: {
          name: "VLESS Edge Worker",
          version: "1.0.0",
          uptime: "running"
        },
        config: {
          hasUuid: !!cfg?.uuid,
          hasWorkerHost: !!cfg?.workerHost,
          hasBackendHost: !!cfg?.backendHost,
          hasBackendPort: !!cfg?.backendPort,
          wsPath: cfg?.wsPath || "/echws",
          mode: cfg?.mode || "A",
          configured: !!(cfg?.uuid && cfg?.workerHost && cfg?.backendHost && cfg?.backendPort)
        },
        network: {
          ip: request.headers.get("CF-Connecting-IP") || "",
          country: request.cf && request.cf.country || "",
          region: request.cf && request.cf.region || "",
          city: request.cf && request.cf.city || "",
          colo: request.cf && request.cf.colo || "",
          asn: request.cf && request.cf.asn || ""
        },
        endpoints: {
          subscription: "/sub",
          admin: "/",
          geo: "/api/geo",
          singbox: "/singbox",
          clash: "/clash",
          qrcode: "/qrcode",
          websocket: "/echws"
        }
      };

      // 评估整体健康状态
      if (!health.config.configured) {
        health.status = "warning";
        health.message = "配置不完整，请访问管理面板完成配置";
      } else {
        health.status = "ok";
        health.message = "Worker 运行正常，配置完整";
      }

      // 检查是否请求 JSON 格式（通过 Accept 头或 ?format=json 参数）
      const acceptHeader = request.headers.get("Accept") || "";
      const formatParam = url.searchParams.get("format");
      const wantsJson = formatParam === "json" || acceptHeader.includes("application/json");

      if (wantsJson) {
        return new Response(JSON.stringify(health, null, 2), {
          headers: { 
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-cache, no-store, must-revalidate"
          }
        });
      }

      // 返回 HTML UI
      return new Response(renderHealthPage(health), {
        headers: { 
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-cache, no-store, must-revalidate"
        }
      });
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
      try {
      const cfg = await loadConfig(request, url, sessionSecret);

        // 验证配置是否完整
        if (!cfg || !cfg.uuid || !cfg.workerHost || !cfg.backendHost || !cfg.backendPort) {
          // 配置不完整，记录详细日志
          const missingFields = [];
          if (!cfg?.uuid) missingFields.push("UUID");
          if (!cfg?.workerHost) missingFields.push("Worker域名");
          if (!cfg?.backendHost) missingFields.push("后端域名");
          if (!cfg?.backendPort) missingFields.push("后端端口");
          
          console.error("Config incomplete. Missing fields:", missingFields.join(", "));
          console.error("Config state:", {
            hasUuid: !!cfg?.uuid,
            hasWorkerHost: !!cfg?.workerHost,
            hasBackendHost: !!cfg?.backendHost,
            hasBackendPort: !!cfg?.backendPort,
            cookieHeader: request.headers.get("Cookie") ? "present" : "missing"
          });
          
          // 返回空字符串（v2rayN 会显示为空订阅）
          return new Response("", {
            headers: { 
              "content-type": "text/plain; charset=utf-8",
              "cache-control": "no-cache, no-store, must-revalidate"
            }
          });
        }

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
        
        // 如果生成的订阅为空，记录日志并返回空字符串
        if (!str || str.trim().length === 0) {
          console.error("Generated subscription is empty. Config:", {
            uuid: cfg.uuid ? "***" : "missing",
            workerHost: cfg.workerHost || "missing",
            backendHost: cfg.backendHost || "missing",
            backendPort: cfg.backendPort || "missing",
            wsPath: cfg.wsPath || "missing",
            mode: ipOption.mode,
            ipCount: ipList.length
          });
          return new Response("", {
            headers: { 
              "content-type": "text/plain; charset=utf-8",
              "cache-control": "no-cache, no-store, must-revalidate"
            }
          });
        }
        
        // 使用安全的 base64 编码函数
        const b64 = base64Encode(str);
        
        // 确保 Base64 编码结果不为空
        if (!b64 || b64.length === 0) {
          console.error("Base64 encoding failed, original string length:", str.length);
          return new Response("", {
            headers: { 
              "content-type": "text/plain; charset=utf-8",
              "cache-control": "no-cache, no-store, must-revalidate"
            }
          });
        }
        
      return new Response(b64, {
          headers: { 
            "content-type": "text/plain; charset=utf-8",
            "cache-control": "no-cache, no-store, must-revalidate"
          }
        });
      } catch (error) {
        // 捕获所有错误，避免 500 错误
        console.error("Subscription generation error:", error);
        return new Response("", {
          headers: { 
            "content-type": "text/plain; charset=utf-8",
            "cache-control": "no-cache, no-store, must-revalidate"
          }
      });
      }
    }

    if (pathname === "/singbox") {
      const cfg = await loadConfig(request, url, sessionSecret);
      const json = generateSingbox(cfg);
      return new Response(JSON.stringify(json, null, 2), {
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }

    if (pathname === "/clash") {
      const cfg = await loadConfig(request, url, sessionSecret);
      const yaml = generateClash(cfg);
      return new Response(yaml, {
        headers: { "content-type": "text/yaml; charset=utf-8" }
      });
    }

    if (pathname === "/qrcode") {
      const cfg = await loadConfig(request, url, sessionSecret);
      const png = await generateQRCode(cfg);
      return new Response(png, {
        headers: { "content-type": "image/png" }
      });
    }

    // --- WebSocket for VLESS proxy (no auth, for clients) ---
    const upgrade = request.headers.get("Upgrade") || "";
    if (upgrade.toLowerCase() === "websocket") {
      // 首先尝试从 URL 查询参数读取配置
      let cfg = await loadConfig(request, url, sessionSecret);
      
      // 如果配置不完整，尝试从路径中提取配置
      // 路径格式可能是：/echws/{base64_config} 或 /echws/{base64_config}/...
      if (!cfg || !cfg.backendHost || !cfg.backendPort) {
        const pathParts = url.pathname.split('/').filter(p => p);
        // 查找 /echws 后面的配置部分
        const echwsIndex = pathParts.indexOf('echws');
        if (echwsIndex >= 0 && pathParts.length > echwsIndex + 1) {
          const configB64 = pathParts[echwsIndex + 1];
          try {
            // 还原 Base64 编码（处理 URL 安全的 Base64）
            const normalizedB64 = configB64.replace(/-/g, '+').replace(/_/g, '/');
            // 添加填充
            const paddedB64 = normalizedB64 + '='.repeat((4 - normalizedB64.length % 4) % 4);
            // Base64 解码
            const binaryString = atob(paddedB64);
            const configJson = binaryString;
            const wsConfig = JSON.parse(configJson);
            // 合并配置
            cfg = {
              ...cfg,
              backendHost: wsConfig.h || wsConfig.backendHost || cfg?.backendHost,
              backendPort: wsConfig.p || wsConfig.backendPort || cfg?.backendPort,
              wsPath: cfg?.wsPath || "/echws",
              mode: wsConfig.m || wsConfig.mode || cfg?.mode || "A"
            };
            console.log("Config loaded from WebSocket path:", {
              backendHost: cfg.backendHost,
              backendPort: cfg.backendPort
            });
          } catch (e) {
            console.error("Failed to parse config from WebSocket path:", e, "path:", url.pathname);
          }
        }
        
        // 如果还是不行，尝试从查询参数读取
        if ((!cfg || !cfg.backendHost || !cfg.backendPort) && url.search) {
          const cfgMatch = url.search.match(/[?&]cfg=([^&]+)/);
          if (cfgMatch) {
            try {
              const decoded = decodeURIComponent(cfgMatch[1]);
              const wsConfig = JSON.parse(decoded);
              cfg = {
                ...cfg,
                backendHost: wsConfig.backendHost || wsConfig.h || cfg?.backendHost,
                backendPort: wsConfig.backendPort || wsConfig.p || cfg?.backendPort,
                wsPath: wsConfig.wsPath || cfg?.wsPath || "/echws",
                mode: wsConfig.mode || wsConfig.m || cfg?.mode || "A"
              };
              console.log("Config loaded from WebSocket query parameter");
            } catch (e) {
              console.error("Failed to parse config from query parameter:", e);
            }
          }
        }
      }
      
      // 验证配置是否完整
      if (!cfg || !cfg.backendHost || !cfg.backendPort) {
        console.error("WebSocket: Config incomplete", {
          hasUuid: !!cfg?.uuid,
          hasWorkerHost: !!cfg?.workerHost,
          hasBackendHost: !!cfg?.backendHost,
          hasBackendPort: !!cfg?.backendPort,
          urlPath: url.pathname,
          urlSearch: url.search,
          fullPath: url.pathname + url.search
        });
        return new Response("Configuration incomplete", { status: 502 });
      }
      
      return handleWS(request, cfg);
    }

    return new Response("Not Found", { status: 404 });
  }
};

// ===============================================================
// Auth helpers: password & session (Cookie-based, no KV)
// ===============================================================

async function isAuthenticated(request, secretKey) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const sessionToken = cookies["vless_admin"];
  if (!sessionToken) return false;
  
  // Verify session token signature
  try {
    const decrypted = await decrypt(sessionToken, secretKey);
    if (!decrypted) return false;
    const session = JSON.parse(decrypted);
    const now = Date.now();
    // Check if session is expired (1 day = 86400000 ms)
    if (session.expires && now > session.expires) return false;
    return true;
  } catch (e) {
    return false;
  }
}

function parseCookies(header) {
  const out = {};
  header.split(";").forEach(part => {
    const [k, v] = part.split("=").map(s => s && s.trim());
    if (k && v) out[k] = v;
  });
  return out;
}

async function handleLogin(request, env, sessionSecret, adminPassword) {
  const formData = await request.formData();
  const password = (formData.get("password") || "").toString();
  const remember = formData.get("remember") === "on";

  if (!password) {
    const hasPw = !!adminPassword;
    return new Response(renderLoginPage("密码不能为空", !hasPw, adminPassword), {
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  }

  // Check if ADMIN_PASSWORD is set
  if (!adminPassword) {
    return new Response(renderLoginPage("错误：未配置 ADMIN_PASSWORD 环境变量。请在 Cloudflare Dashboard 中设置。", true, null), {
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  }

  // Verify password against environment variable
  if (password !== adminPassword) {
    return new Response(renderLoginPage("密码错误，请重试。", false, adminPassword), {
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  }

  // Create session token
  const session = {
    token: crypto.randomUUID(),
    expires: remember ? Date.now() + 86400000 : Date.now() + 3600000 // 1 day or 1 hour
  };
  const sessionEncrypted = await encrypt(JSON.stringify(session), sessionSecret);

  // Set Cookie
  const headers = new Headers();
  headers.set("Set-Cookie", `vless_admin=${sessionEncrypted}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${remember ? 86400 : 3600}`);
  headers.set("Location", "/");

  return new Response(null, {
    status: 302,
    headers
  });
}

// ===============================================================
// Login Page (风格 C, 卡片 + 显示密码 + 记住我 1 天)
// ===============================================================

function renderLoginPage(message, needInit, adminPassword) {
  const safeMsg = message ? String(message) : "";
  const hasPassword = !!adminPassword;
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
        ${!hasPassword
          ? "⚠️ 未检测到 ADMIN_PASSWORD 环境变量。请在 Cloudflare Dashboard → Workers → Settings → Variables 中设置 ADMIN_PASSWORD。"
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
          登录
        </button>
      </form>

      <div class="mt-6 text-xs text-slate-500 space-y-1">
        <p class="font-semibold">使用说明：</p>
        <p>1. 本版本完全不依赖 KV 存储，所有数据保存在 Cookie 中。</p>
        <p>2. 管理员密码通过 <code>ADMIN_PASSWORD</code> 环境变量配置（在 Cloudflare Dashboard 中设置）。</p>
        <p>3. 会话签名密钥通过 <code>SESSION_SECRET</code> 环境变量配置（用于加密 Cookie）。</p>
        <p>4. 登录成功后，将进入节点管理面板，在那里可以配置 UUID、后端域名、端口、WS 路径、多节点等。</p>
        <p>5. 配置数据保存在 Cookie 中，也可以通过 URL 参数 <code>?cfg=</code> 传递配置。</p>
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
  <div class="flex items-center justify-between mb-2">
    <div>
  <h1 class="text-3xl font-bold mb-2">🚀 VLESS Edge 节点管理系统</h1>
      <p class="text-gray-600">通过本面板，你可以可视化配置 Cloudflare Worker 反代的 VLESS 节点，并一键生成 v2rayN / SingBox / Clash 订阅。</p>
    </div>
    <a href="/health" target="_blank" class="px-4 py-2 rounded-lg font-semibold text-white whitespace-nowrap ml-4" style="background: #10b981; text-decoration: none; height: fit-content;">🔍 健康检查</a>
  </div>

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
    <input id="workerHost" class="input" placeholder="例如：ech.xxxxxxx.com">
    <label class="label">WS 路径（必填）</label>
    <input id="wsPath" class="input" value="/echws">
    <label class="label">后端 VPS 域名（必填）</label>
    <input id="backendHost" class="input" placeholder="例如：cc1.xxxxxxx.com">
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
    <p class="text-xs text-slate-500 mt-2">你可以在这里添加多个前端节点域名，例如：ech1.xxxxxxx.com、ech2.xxxxxxx.com。</p>
  </div>

  <!-- 保存 & 重置 -->
  <div class="card mb-6">
    <button id="save" class="btn">💾 保存配置到 Cookie</button>
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
      建议先在这里跑一遍测速，确认入口机房（colo）是否为 HKG/TPE/SIN 等亚洲节点，再配合订阅里的"优选IP节点"进行真实体验对比。
    </p>
  </div>
  <!-- 订阅区 -->
  <div class="card mb-6">
    <h2 class="text-xl font-semibold mb-4">订阅 & 导入</h2>
    <div class="space-y-3">
      <div>
        <p class="text-sm font-semibold mb-2">v2rayN 订阅链接（推荐）：</p>
        <div class="flex items-center gap-2">
          <input type="text" id="subUrlWithConfig" class="input flex-1" readonly placeholder="配置完成后点击下方按钮生成订阅链接">
          <button id="generateSubUrl" class="btn">生成订阅链接</button>
        </div>
        <p class="text-xs text-slate-500 mt-1">⚠️ 重要：由于 v2rayN 不会携带浏览器 Cookie，请使用此链接（包含配置参数）添加到 v2rayN。</p>
      </div>
      <div>
        <p class="text-sm font-semibold mb-2">基础订阅链接（需要 Cookie）：</p>
        <p><code id="subUrl" class="text-xs break-all"></code></p>
        <p class="text-xs text-slate-500">此链接仅在浏览器中有效（需要 Cookie），v2rayN 无法使用。</p>
      </div>
    </div>
    <div class="mt-3 space-x-2">
      <a href="/health" target="_blank" class="btn2" style="background: #10b981; color: white;">🔍 健康检查</a>
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
        // 如果配置完整，自动生成订阅链接
        if (cfg.uuid && cfg.workerHost && cfg.backendHost && cfg.backendPort) {
          generateSubscriptionUrl();
        }
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
        + '<input class="input node-host" placeholder="例如：ech2.xxxxxxx.com" value="' + (d.host || "") + '">'
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

      showMsg("✅ 已保存配置到 Cookie");
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

    // 生成订阅链接函数
    function generateSubscriptionUrl() {
      var uuidEl = document.getElementById("uuid");
      var workerHostEl = document.getElementById("workerHost");
      var backendHostEl = document.getElementById("backendHost");
      var backendPortEl = document.getElementById("backendPort");
      var wsPathEl = document.getElementById("wsPath");
      var fakeHostEl = document.getElementById("fakeHost");
      var sniEl = document.getElementById("sni");
      var uaEl = document.getElementById("ua");
      var modeInput = document.querySelector("input[name='wsMode']:checked");
      var mode = modeInput ? modeInput.value : "A";

      // 验证必填字段
      if (!uuidEl.value || !workerHostEl.value || !backendHostEl.value || !backendPortEl.value) {
        document.getElementById("subUrlWithConfig").value = "请先填写必填字段（UUID、Worker域名、后端域名、后端端口）";
        return;
      }

      // 收集节点列表
      var nodesDivs = document.querySelectorAll("#nodes > div");
      var nodesData = [];
      nodesDivs.forEach(function(d){
        var host = d.querySelector(".node-host")?.value;
        if (host) {
          nodesData.push({
            host: host,
            name: d.querySelector(".node-name")?.value || host
          });
        }
      });

      // 构建配置对象
      var cfg = {
        uuid: uuidEl.value.trim(),
        workerHost: workerHostEl.value.trim(),
        wsPath: wsPathEl.value.trim() || "/echws",
        backendHost: backendHostEl.value.trim(),
        backendPort: backendPortEl.value.trim(),
        fakeHost: fakeHostEl.value.trim(),
        sni: sniEl.value.trim(),
        ua: uaEl.value.trim(),
        mode: mode,
        nodes: nodesData
      };

      // 将配置编码为 JSON 并 URL 编码
      try {
        var cfgJson = JSON.stringify(cfg);
        var cfgEncoded = encodeURIComponent(cfgJson);
        var base = window.location.origin;
        var subUrl = base + "/sub?cfg=" + cfgEncoded;
        document.getElementById("subUrlWithConfig").value = subUrl;
      } catch(e) {
        document.getElementById("subUrlWithConfig").value = "生成订阅链接失败：" + e.message;
      }
    }

    // 绑定生成订阅链接按钮
    var generateBtn = document.getElementById("generateSubUrl");
    if (generateBtn) {
      generateBtn.onclick = function() {
        generateSubscriptionUrl();
      };
    }

    loadConfig();
  <\/script>
</body>
</html>`;
}

// ===============================================================
// Config Loader (Cookie / URL parameter based, no KV)
// ===============================================================
async function loadConfig(request, url, sessionSecret) {
  // First try to get from Cookie
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  let raw = null;
  
  if (cookies["vless_config"]) {
    try {
      raw = await decrypt(cookies["vless_config"], sessionSecret);
      if (raw) {
        console.log("Config loaded from cookie, length:", raw.length);
      }
    } catch (e) {
      console.error("Failed to decrypt config cookie:", e);
    }
  } else {
    console.log("No vless_config cookie found. Available cookies:", Object.keys(cookies));
  }
  
  // If not in cookie, try URL parameter
  if (!raw) {
    const cfgParam = url.searchParams.get("cfg");
    if (cfgParam) {
      try {
        raw = decodeURIComponent(cfgParam);
        console.log("Config loaded from URL parameter, length:", raw.length);
      } catch (e) {
        console.error("Failed to decode config from URL parameter:", e);
      }
    }
  }
  
  if (!raw) {
    console.log("No config found, returning default empty config");
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
  
  try {
    const config = JSON.parse(raw);
    console.log("Config parsed successfully:", {
      hasUuid: !!config.uuid,
      hasWorkerHost: !!config.workerHost,
      hasBackendHost: !!config.backendHost,
      hasBackendPort: !!config.backendPort
    });
    return config;
  } catch (e) {
    console.error("Failed to parse config JSON:", e);
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
}

// ===============================================================
// VLESS URL builder
// ===============================================================
function buildVlessUrl(cfg, hostOverride = null, name = "Node") {
  try {
    // 验证必要参数
    if (!cfg || typeof cfg !== "object") {
      return null;
    }
    
    if (!cfg.uuid || typeof cfg.uuid !== "string" || cfg.uuid.trim().length === 0) {
      return null;
    }
    
    if (!cfg.workerHost || typeof cfg.workerHost !== "string" || cfg.workerHost.trim().length === 0) {
      return null;
    }
    
  const host = hostOverride || cfg.workerHost;
    if (!host || typeof host !== "string" || host.trim().length === 0) {
      return null;
    }
    
    // 确保 UUID 和路径不为空
    const uuid = cfg.uuid.trim();
    const wsPath = (cfg.wsPath || "/echws").trim();
    const workerHost = cfg.workerHost.trim();
    
    if (!uuid || uuid.length === 0) {
      return null;
    }
    
    // 将配置信息编码为 Base64，嵌入到路径中
    // 格式：/echws/{base64_encoded_config}
    // 这样即使 v2rayN 忽略查询参数，我们也能从路径中提取配置
    const configForWs = {
      h: cfg.backendHost,  // 使用短键名减少长度
      p: cfg.backendPort,
      m: cfg.mode || "A"
    };
    const configJson = JSON.stringify(configForWs);
    // 使用 Base64 编码，然后替换特殊字符使其 URL 安全
    const configB64 = base64Encode(configJson).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    
    // 构建 WebSocket 路径，将配置编码到路径中
    // 格式：/echws/{config} 或 /echws/{config}?cfg=... (双重保险)
    const wsPathWithConfig = `${wsPath}/${configB64}`;
    
    // 同时也在查询参数中添加配置（双重保险）
    const configEncoded = encodeURIComponent(configJson);
    
    // 构建参数
    const params = new URLSearchParams();
    params.set("encryption", "none");
    params.set("security", "tls");
    params.set("type", "ws");
    params.set("path", wsPathWithConfig);
    params.set("host", cfg.fakeHost || workerHost);
    params.set("sni", cfg.sni || workerHost);
    
    // 构建 VLESS URL
    const url = `vless://${uuid}@${host.trim()}:443?${params.toString()}#${encodeURIComponent(name || "Node")}`;
    
    // 验证 URL 格式
    if (!url.startsWith("vless://")) {
      return null;
    }
    
    return url;
  } catch (e) {
    console.error("buildVlessUrl error:", e);
    return null;
  }
}

// ===============================================================
// v2rayN Subscription text
// ===============================================================
function generateV2raySub(cfg, ipOption) {
  const list = [];
  
  // 验证配置对象
  if (!cfg || typeof cfg !== "object") {
    return "";
  }
  
  ipOption = ipOption || { mode: "domain", ips: [] };
  const mode = ipOption.mode || "domain";
  const ips = Array.isArray(ipOption.ips) ? ipOption.ips : (ipOption.ip ? [ipOption.ip] : []);

  const ipOnly = (mode === "ip");

  // 1）域名节点（非 ip-only 模式才添加）
  if (!ipOnly) {
    const mainUrl = buildVlessUrl(cfg, null, "主节点");
    if (mainUrl && mainUrl.trim().length > 0) {
      list.push(mainUrl);
    }
    if (cfg.nodes && Array.isArray(cfg.nodes)) {
      cfg.nodes.forEach(function(n) {
        if (!n || !n.host) return;
        const nodeUrl = buildVlessUrl(cfg, n.host, n.name || n.host);
        if (nodeUrl && nodeUrl.trim().length > 0) {
          list.push(nodeUrl);
        }
      });
    }
  }

  // 2）IP 备胎节点
  if ((mode === "dual" || mode === "ip") && ips.length) {
    ips.forEach(function(ip, idx) {
      if (!ip || typeof ip !== "string" || ip.trim().length === 0) return;
      const name = "优选IP节点" + (ips.length > 1 ? (idx + 1) : "");
      const ipUrl = buildVlessUrl(cfg, ip.trim(), name);
      if (ipUrl && ipUrl.trim().length > 0) {
        list.push(ipUrl);
      }
    });
  }

  // 过滤掉空字符串和无效 URL
  const validList = list.filter(url => url && url.trim().length > 0 && url.startsWith("vless://"));
  return validList.join("\n");
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

function renderHealthPage(health) {
  const statusColor = health.status === "ok" ? "green" : health.status === "warning" ? "yellow" : "red";
  const statusIcon = health.status === "ok" ? "✅" : health.status === "warning" ? "⚠️" : "❌";
  const statusBg = health.status === "ok" ? "bg-green-50 border-green-200" : health.status === "warning" ? "bg-yellow-50 border-yellow-200" : "bg-red-50 border-red-200";
  
  return `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8" />
  <title>Worker 健康检查</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"><\/script>
  <style>
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: 600;
      font-size: 14px;
    }
    .status-ok { background: #10b981; color: white; }
    .status-warning { background: #f59e0b; color: white; }
    .status-error { background: #ef4444; color: white; }
    .info-card {
      background: white;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      margin-bottom: 16px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid #e5e7eb;
    }
    .info-row:last-child {
      border-bottom: none;
    }
    .info-label {
      font-weight: 600;
      color: #6b7280;
    }
    .info-value {
      color: #111827;
      font-family: monospace;
    }
    .check-icon { color: #10b981; }
    .cross-icon { color: #ef4444; }
  </style>
</head>
<body class="min-h-screen bg-slate-100 p-4">
  <div class="max-w-4xl mx-auto space-y-6">
    <!-- 标题和状态 -->
    <div class="info-card ${statusBg}">
      <div class="flex items-center justify-between mb-4">
        <h1 class="text-2xl font-bold">🔍 Worker 健康检查</h1>
        <span class="status-badge status-${health.status}">
          ${statusIcon} ${health.status === "ok" ? "运行正常" : health.status === "warning" ? "配置警告" : "运行异常"}
        </span>
      </div>
      <p class="text-lg font-semibold mb-2">${health.message}</p>
      <p class="text-sm text-gray-600">检查时间：${new Date(health.timestamp).toLocaleString('zh-CN')}</p>
    </div>

    <!-- Worker 信息 -->
    <div class="info-card">
      <h2 class="text-xl font-semibold mb-4">📦 Worker 信息</h2>
      <div class="info-row">
        <span class="info-label">名称</span>
        <span class="info-value">${health.worker.name}</span>
      </div>
      <div class="info-row">
        <span class="info-label">版本</span>
        <span class="info-value">${health.worker.version}</span>
      </div>
      <div class="info-row">
        <span class="info-label">运行状态</span>
        <span class="info-value">${health.worker.uptime}</span>
      </div>
    </div>

    <!-- 配置状态 -->
    <div class="info-card">
      <h2 class="text-xl font-semibold mb-4">⚙️ 配置状态</h2>
      <div class="info-row">
        <span class="info-label">UUID</span>
        <span class="info-value">${health.config.hasUuid ? '<span class="check-icon">✓ 已配置</span>' : '<span class="cross-icon">✗ 未配置</span>'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Worker 域名</span>
        <span class="info-value">${health.config.hasWorkerHost ? '<span class="check-icon">✓ 已配置</span>' : '<span class="cross-icon">✗ 未配置</span>'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">后端域名</span>
        <span class="info-value">${health.config.hasBackendHost ? '<span class="check-icon">✓ 已配置</span>' : '<span class="cross-icon">✗ 未配置</span>'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">后端端口</span>
        <span class="info-value">${health.config.hasBackendPort ? '<span class="check-icon">✓ 已配置</span>' : '<span class="cross-icon">✗ 未配置</span>'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">WebSocket 路径</span>
        <span class="info-value">${health.config.wsPath}</span>
      </div>
      <div class="info-row">
        <span class="info-label">代理模式</span>
        <span class="info-value">${health.config.mode === "A" ? "方式 A（稳定型）" : "方式 B（高级混淆）"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">配置完整性</span>
        <span class="info-value">${health.config.configured ? '<span class="check-icon">✓ 完整</span>' : '<span class="cross-icon">✗ 不完整</span>'}</span>
      </div>
    </div>

    <!-- 网络信息 -->
    <div class="info-card">
      <h2 class="text-xl font-semibold mb-4">🌐 网络信息</h2>
      <div class="info-row">
        <span class="info-label">访问 IP</span>
        <span class="info-value">${health.network.ip || "-"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">国家/地区</span>
        <span class="info-value">${health.network.country || "-"} / ${health.network.region || "-"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">城市</span>
        <span class="info-value">${health.network.city || "-"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Cloudflare 入口机房</span>
        <span class="info-value font-bold">${health.network.colo || "-"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">ASN</span>
        <span class="info-value">${health.network.asn || "-"}</span>
      </div>
    </div>

    <!-- 可用端点 -->
    <div class="info-card">
      <h2 class="text-xl font-semibold mb-4">🔗 可用端点</h2>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <a href="${health.endpoints.subscription}" class="p-3 bg-blue-50 rounded-lg hover:bg-blue-100 transition">
          <div class="font-semibold text-blue-900">订阅链接</div>
          <div class="text-sm text-blue-600">${health.endpoints.subscription}</div>
        </a>
        <a href="${health.endpoints.admin}" class="p-3 bg-green-50 rounded-lg hover:bg-green-100 transition">
          <div class="font-semibold text-green-900">管理面板</div>
          <div class="text-sm text-green-600">${health.endpoints.admin}</div>
        </a>
        <a href="${health.endpoints.geo}" class="p-3 bg-purple-50 rounded-lg hover:bg-purple-100 transition">
          <div class="font-semibold text-purple-900">Geo 信息</div>
          <div class="text-sm text-purple-600">${health.endpoints.geo}</div>
        </a>
        <a href="${health.endpoints.singbox}" class="p-3 bg-orange-50 rounded-lg hover:bg-orange-100 transition">
          <div class="font-semibold text-orange-900">SingBox</div>
          <div class="text-sm text-orange-600">${health.endpoints.singbox}</div>
        </a>
        <a href="${health.endpoints.clash}" class="p-3 bg-pink-50 rounded-lg hover:bg-pink-100 transition">
          <div class="font-semibold text-pink-900">Clash</div>
          <div class="text-sm text-pink-600">${health.endpoints.clash}</div>
        </a>
        <a href="${health.endpoints.qrcode}" class="p-3 bg-indigo-50 rounded-lg hover:bg-indigo-100 transition">
          <div class="font-semibold text-indigo-900">二维码</div>
          <div class="text-sm text-indigo-600">${health.endpoints.qrcode}</div>
        </a>
      </div>
    </div>

    <!-- 操作按钮 -->
    <div class="info-card">
      <div class="flex gap-3 flex-wrap">
        <a href="/" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
          前往管理面板
        </a>
        <a href="/api/geo" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition">
          查看线路信息
        </a>
        <a href="/health?format=json" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition">
          查看 JSON 格式
        </a>
        <button onclick="location.reload()" class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition">
          刷新页面
        </button>
      </div>
    </div>

    <!-- JSON 数据（可折叠） -->
    <div class="info-card">
      <details>
        <summary class="cursor-pointer font-semibold text-gray-700 hover:text-gray-900">
          📄 查看原始 JSON 数据
        </summary>
        <pre class="mt-4 p-4 bg-gray-900 text-green-400 rounded-lg overflow-x-auto text-xs"><code>${JSON.stringify(health, null, 2)}</code></pre>
      </details>
    </div>
  </div>
</body>
</html>`;
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
        本页面用于测试当前 Worker 域名的实际访问延迟与下载速度，并提供一个简单的"自定义 URL 批量测速"工具，方便你对比不同 CF 优选 IP 或不同域名的表现。
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
  const wsPath = cfg.wsPath || "/echws";
  const backendUrl = `http://${cfg.backendHost}:${cfg.backendPort}${wsPath}`;
  
  // 创建新的 headers，保留必要的 WebSocket 升级头
  const headers = new Headers();
  
  // 保留 WebSocket 升级相关的 headers
  const upgradeHeader = request.headers.get("Upgrade");
  const connectionHeader = request.headers.get("Connection");
  const secWebSocketKey = request.headers.get("Sec-WebSocket-Key");
  const secWebSocketVersion = request.headers.get("Sec-WebSocket-Version");
  const secWebSocketProtocol = request.headers.get("Sec-WebSocket-Protocol");
  const secWebSocketExtensions = request.headers.get("Sec-WebSocket-Extensions");
  
  if (upgradeHeader) headers.set("Upgrade", upgradeHeader);
  if (connectionHeader) headers.set("Connection", connectionHeader);
  if (secWebSocketKey) headers.set("Sec-WebSocket-Key", secWebSocketKey);
  if (secWebSocketVersion) headers.set("Sec-WebSocket-Version", secWebSocketVersion);
  if (secWebSocketProtocol) headers.set("Sec-WebSocket-Protocol", secWebSocketProtocol);
  if (secWebSocketExtensions) headers.set("Sec-WebSocket-Extensions", secWebSocketExtensions);
  
  // 设置后端 Host
  headers.set("Host", cfg.backendHost);
  
  // 保留 Origin（如果需要）
  const origin = request.headers.get("Origin");
  if (origin) headers.set("Origin", origin);

  const backendReq = new Request(backendUrl, {
    method: request.method,
    headers,
    body: request.body
  });

  let resp;
  try {
    resp = await fetch(backendReq);
    console.log("WebSocket Mode A: Backend response status:", resp.status);
  } catch (e) {
    console.error("WebSocket Mode A: Backend connection failed:", e.message);
    return new Response("Backend connection failed: " + e.message, { status: 502 });
  }

  if (resp.status !== 101) {
    const errorText = await resp.text().catch(() => "Unknown error");
    console.error("WebSocket Mode A: Upgrade failed, status:", resp.status, "response:", errorText.substring(0, 200));
    return new Response(`WebSocket upgrade failed: ${resp.status} - ${errorText.substring(0, 100)}`, { status: 502 });
  }
  return resp;
}

// --- Mode B: Obfuscated ---
async function handleWS_B(request, cfg) {
  // 从 URL 中提取原始路径
  const urlPath = new URL(request.url).pathname;
  // 提取实际的 WebSocket 路径（去除配置部分）
  // 路径格式可能是：/echws/{config} 或 /echws
  let wsPath = cfg.wsPath || "/echws";
  if (urlPath.startsWith("/echws")) {
    // 如果路径是 /echws/{config}，提取基础路径
    const pathParts = urlPath.split('/').filter(p => p);
    if (pathParts[0] === 'echws') {
      wsPath = "/echws";  // 使用基础路径
    }
  }
  
  const backendUrl = `http://${cfg.backendHost}:${cfg.backendPort}${wsPath}`;
  
  // 创建新的 headers
  const headers = new Headers();
  
  // 保留 WebSocket 升级相关的 headers
  const upgradeHeader = request.headers.get("Upgrade");
  const connectionHeader = request.headers.get("Connection");
  const secWebSocketKey = request.headers.get("Sec-WebSocket-Key");
  const secWebSocketVersion = request.headers.get("Sec-WebSocket-Version");
  const secWebSocketProtocol = request.headers.get("Sec-WebSocket-Protocol");
  const secWebSocketExtensions = request.headers.get("Sec-WebSocket-Extensions");
  
  if (upgradeHeader) headers.set("Upgrade", upgradeHeader);
  if (connectionHeader) headers.set("Connection", connectionHeader);
  if (secWebSocketKey) headers.set("Sec-WebSocket-Key", secWebSocketKey);
  if (secWebSocketVersion) headers.set("Sec-WebSocket-Version", secWebSocketVersion);
  if (secWebSocketProtocol) headers.set("Sec-WebSocket-Protocol", secWebSocketProtocol);
  if (secWebSocketExtensions) headers.set("Sec-WebSocket-Extensions", secWebSocketExtensions);

  // 混淆设置
  if (cfg.fakeHost) {
    headers.set("Host", cfg.fakeHost);
  } else {
    headers.set("Host", cfg.backendHost);
  }
  if (cfg.ua) {
    headers.set("User-Agent", cfg.ua);
  }
  if (cfg.sni) {
    headers.set("CF-Connecting-SNI", cfg.sni);
  }

  headers.set("X-Forwarded-For", "1.1.1.1");
  headers.set("X-Real-IP", "1.1.1.1");
  
  // 保留 Origin（如果需要）
  const origin = request.headers.get("Origin");
  if (origin) headers.set("Origin", origin);

  const backendReq = new Request(backendUrl, {
    method: request.method,
    headers,
    body: request.body
  });

  let resp;
  try {
    resp = await fetch(backendReq);
    console.log("WebSocket Mode B: Backend response status:", resp.status);
  } catch (e) {
    console.error("WebSocket Mode B: Backend connection failed:", e.message);
    return new Response("Backend connection failed: " + e.message, { status: 503 });
  }

  if (resp.status !== 101) {
    const errorText = await resp.text().catch(() => "Unknown error");
    console.error("WebSocket Mode B: Upgrade failed, status:", resp.status, "response:", errorText.substring(0, 200));
    return new Response(`WebSocket upgrade failed: ${resp.status} - ${errorText.substring(0, 100)}`, { status: 502 });
  }
  return resp;
}
