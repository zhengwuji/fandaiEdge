ECH-Workers 
一、介绍
ECH-Workers 是一个基于 Cloudflare Workers 的 VLESS
节点管理后台，提供无需服务器、可直接部署的节点面板。
本版本为不依赖 KV 的优化稳定版，同时包含完整 GitHub 部署说明。
二、功能特性
1. 无需 VPS，可直接运行
2. 支持 VLESS + WS 节点生成
3. ECH 完整支持
4. 后台密码存储无需 KV
5. 配置全部基于 Cookie / URL 参数
6. 可一键导出订阅、SingBox、v2rayN 等配置
三、文件说明
项目包含以下文件：
- index.js：完整 Worker 主程序
- wrangler.toml：Cloudflare 部署配置
- README.txt：基本说明
四、部署步骤（GitHub + Cloudflare）
1. fork 或上传 ZIP 到 GitHub 仓库
2. 打开 Cloudflare → Workers & Pages → 创建 Worker
3. 选择“从 GitHub 部署”
4. 选择此仓库
5. Cloudflare 自动部署，无需构建命令
6. 部署完成后访问：https://你的worker域名.workers.dev/login
五、首次登录
本版本不依赖 KV，因此密码采用 Cookie 机制。
首次访问 /login 时可设置管理员密码。
之后再次访问需输入密码验证。
六、节点创建
进入后台 → 填写：
- UUID
- Worker 域名
- Path（默认 /echws）
- 后端 VPS（可选）
点击生成即可得到订阅链接与 VLESS 配置。
七、注意事项
1. 不依赖 KV，因此不会触发 KV put 限制
2. 建议为管理员密码设置较高强度
3. 若 Cloudflare 提示错误，可重新部署
八、常见问题
Q：密码如何重置？
A：清除浏览器 Cookie 或访问 /reset?key=admin 即可。
Q：支持多用户吗？
A：当前版本主要面向单用户，支持分享订阅。
九、结束
感谢使用 ECH-Workers 优化版。
