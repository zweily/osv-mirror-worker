# osv-mirror-worker

[English](README.md)

`osv-mirror-worker` 是一个小型 Cloudflare Worker，用来镜像 [Clawsec](https://github.com/zweily/clawsec) 所使用的 OSV API 端点。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zweily/osv-mirror-worker)

支持的路径：

- `POST /v1/querybatch`
- `GET /v1/vulns/{id}`
- `GET /vulnerability/{id}`

该服务刻意避免成为开放代理。超出上述范围的请求会返回 `404`。

`/vulnerability/{id}` 会在你的镜像域名上渲染可读性更高的漏洞详情页，而 `/v1/vulns/{id}` 仍然返回原始 OSV JSON 数据。

## 使用场景

如果你的终端环境无法直接访问 `https://api.osv.dev`，但可以访问 Cloudflare Worker 域名，那么可以部署这个 Worker，并让 [Clawsec](https://github.com/zweily/clawsec) 指向它。

示例：

```bash
clawsec scan --osv-base-url https://your-worker.workers.dev --no-open
```

```bash
clawsec report --database ./clawsec.sqlite3 --osv-base-url https://your-worker.workers.dev --no-open
```

[Clawsec](https://github.com/zweily/clawsec) 既接受 Worker 的 origin，也接受显式带 `/v1` 的基地址。

当你在 `clawsec scan` 或 `clawsec report` 中使用 `--osv-base-url` 时，报告中的 OSV 链接会指向镜像上的 `/vulnerability/{id}` 页面，而不是原始 JSON 端点。

## 安装与运行

安装依赖：

```bash
npm install
```

如有需要，先登录 Wrangler：

```bash
npx wrangler login
```

本地运行：

```bash
npm run dev
```

类型检查：

```bash
npm run check
```

运行自动化测试：

```bash
npm test
```

部署：

```bash
npm run deploy
```

## 配置

`wrangler.toml` 中默认的上游配置如下：

```toml
[vars]
OSV_ORIGIN = "https://api.osv.dev"
```

如果后续需要接入其他兼容 OSV 的上游服务，可以修改该变量后重新部署。

## 安全与运维建议

- Worker 只会转发真正需要的上游请求头，不会再把客户端的 `Authorization`、`Cookie` 等环境性请求头直接代理到上游。
- 成功的 `GET /v1/vulns/{id}` 和 `GET /vulnerability/{id}` 响应会进行短时缓存，以降低上游压力并减少延迟。
- 开放 CORS 是有意为之，这样浏览器侧工具也可以直接调用该镜像服务。
- 对公网部署，建议在 Cloudflare 侧配置限流规则，尤其是对 `POST /v1/querybatch` 设置比缓存型 `GET` 路由更严格的阈值。
- 建议使用 Cloudflare WAF 或 Custom Rules，在请求进入 Worker 之前拦截异常路径、异常方法或可疑访问模式。
- 如果你希望边缘缓存策略比 Worker 自带的响应头控制更严格，可以额外配置 Cloudflare Cache Rules。
- 如果服务只应对受控团队或特定环境开放，建议使用 Cloudflare Access，而不是完全公开暴露。
- 如果公开部署后出现爬虫或机器人滥用，可以评估 Cloudflare Bot Management 或 Super Bot Fight Mode。
- 本地敏感文件如 `.dev.vars` 和 `.env*` 已被加入 gitignore。

## 许可证

本项目采用 MIT License，详见 `LICENSE`。