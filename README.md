# Real IP Checker 插件说明

## 📌 插件简介
**WP Real IP Checker** 是一款适用于 WordPress 的插件，用于在反向代理或 CDN（如 **Cloudflare**、**Nginx**、**Akamai** 等）环境下获取访问者的**真实客户端 IP**。  
支持可信代理 CIDR 白名单，可选安全模式，并支持自动获取 Cloudflare 官方网段（手动同步 + 定时任务刷新）。

---

## ✨ 功能特点
- **精准 IP 获取**  
  支持 Cloudflare 专用头 `CF-Connecting-IP`、`True-Client-IP`，Nginx 常用头 `X-Forwarded-For`、`X-Real-IP` 等。
- **安全模式**  
  仅当请求来源于可信代理 CIDR 列表时才信任代理头部，防止 IP 伪造。
- **Cloudflare 自动网段同步**  
  一键手动同步 + 首次开启自动预热 + WP-Cron 定时每日更新。
- **后台页脚显示当前 IP**（仅管理员可见）
- **前台短代码** `[real_ip]` 显示当前访问者的 IP。
- **调试模式（WP_DEBUG）** 可输出当前解析路径及缓存信息。

---

## 🛠 安装方法
1. 下载插件文件，将整个文件夹上传到：
   ```
   /wp-content/plugins/real-ip-checker/
   ```
2. 进入 WordPress 后台 → 插件 → 启用 **Real IP Checker**。
3. 后台左侧菜单 → **设置** → **Real IP Checker** 进行配置。

---

## ⚙️ 配置说明
### 1. 只信任可信代理的头部（安全模式）
- **建议开启（生产环境）**：仅在来源 IP 属于可信代理 CIDR 时，才解析代理头部。
- 关闭后将无条件解析头部（风险高，测试环境可用）。

### 2. 自动包含 Cloudflare 官方网段
- 开启后插件会从 Cloudflare 官网抓取并缓存 IPv4 / IPv6 网段。
- 支持：
  - **手动同步按钮** → 立即更新缓存
  - **首次开启预热** → 保存设置时自动抓取
  - **WP-Cron 自动刷新** → 每日更新一次

### 3. 自定义可信代理（CIDR / IP）
- 每行填写一个 IPv4 / IPv6 地址或 CIDR 段。
- 可与 Cloudflare 网段叠加使用。

### 4. 后台页脚显示当前 IP
- 仅管理员可见，用于快速确认解析结果。

---

## 🔍 IP 解析逻辑
1. **安全模式开启且来源不在可信代理列表** → 直接使用 `REMOTE_ADDR`  
2. **来源在 Cloudflare 官方网段** → 只解析：
   - `CF-Connecting-IP`（优先）
   - `True-Client-IP`（备选）
3. **来源在其他可信代理网段** → 按顺序解析：
   - `X-Forwarded-For`（取最左公共 IP）
   - `X-Real-IP`、`Client-IP` 等
4. 以上均未命中 → 回退 `REMOTE_ADDR`

---

## 🧩 短代码
- `[real_ip]`  
  在页面或文章中输出当前访问者 IP。

---

## 🧪 调试模式
- 在 `wp-config.php` 中开启：
  ```php
  define('WP_DEBUG', true);
  ```
- 后台页脚会显示：
  - 访问来源 IP (`REMOTE_ADDR`)
  - 是否来自可信代理
  - 解析出的真实 IP
  - 缓存的 Cloudflare 网段数量

---

## 🗓 定时任务
- 插件激活时自动注册 WP-Cron 事件 `ric_cron_refresh_cf`。
- 每日随机延迟 5~30 分钟后执行一次 Cloudflare 网段更新。
- 插件停用/卸载会自动清理定时任务与缓存。

---

## 📜 许可证
本插件遵循 **AGPLv3** 开源协议。
