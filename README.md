# u1s1 CPA 插件

一个 CLIProxyAPI（CPA）插件，把 [u1s1](https://u1s1.io) 网关（`https://api.u1s1.io/v1`）接成原生 provider。

## 目录

- [为什么用插件而不是反向代理](#为什么用插件而不是反向代理)
- [功能](#功能)
- [额度面板](#额度面板)
- [构建](#构建)
- [安装](#安装)
- [登录](#登录)
- [模型前缀](#模型前缀)
- [思考强度](#思考强度)
- [测试](#测试)

## 为什么用插件而不是反向代理

u1s1 不接受普通 Bearer token。每个请求需要**四层**凭证同时成立：

1. `authorization: DPoP <deviceToken>` — `u1s1d-` 前缀的设备凭证。
2. `dpop: <JWT>` — 每请求一个 ES256 证明，签名覆盖 `{jti, htm, htu, iat, ath}`，
   用设备的 P-256 私钥签名。签名必须是 IEEE P1363 裸 `r||s` 格式
   （WebCrypto 的输出格式）；Go 默认的 DER 编码会被网关拒绝。
3. `x-u1s1-attestation` — 客户端完整性令牌，由 `GET /v1/models` 下发（有效期 7 天）。
4. 客户端指纹：`user-agent: pi (...)`、`x-u1s1-client/version/platform`，
   以及官方 CLI 内嵌 OpenAI SDK 的全套 `x-stainless-*` 请求头。

只带合法 DPoP 证明会返回 `403 client_integrity_review`，且响应中带有明确的封号警告。
四层缺一不可。

## 功能

| 能力 | 方法 | 说明 |
| --- | --- | --- |
| `auth_provider` | `auth.login.start`、`auth.login.poll`、`auth.parse`、`auth.refresh` | 浏览器设备登录；宿主负责把凭证持久化到 `auth-dir`。 |
| `model_provider` | `model.for_auth` | 实时目录来自 `GET /v1/models`，缓存 5 分钟。 |
| `executor` | `executor.execute`、`executor.execute_stream`、`executor.count_tokens` | chat-completions 进出，流式经 `host.stream.emit`，本地估算 token 数。 |
| `management_api` | `management.register`、`management.handle` | 额度面板加 JSON 路由（见下）。 |

所有出站 HTTP 都走 `host.http.do` / `host.http.do_stream`，因此宿主的
`proxy-url`、传输策略和请求日志全部生效。

## 额度面板

管理控制台里会出现一个 `u1s1` 菜单项，指向：

```
/v0/resource/plugins/u1s1/panel
```

页面展示与 `u1s1 usage` 相同的数据：每日免费额度、永久余额、当月累计开销，
以及每个额度包的范围和到期时间。

JSON 路由（需要管理密钥）：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/v0/management/plugins/u1s1/usage` | 所有 u1s1 凭证的额度；加 `?refresh=1` 跳过 30 秒缓存。 |
| POST | `/v0/management/plugins/u1s1/refresh` | 强制重新读取 `/v1/me`。 |

资源页面本身不做管理鉴权（宿主契约），所以 HTML 里**不带**任何额度或凭证数据。
它从 `?key=`、`sessionStorage` 或控制台同源 `localStorage` 取管理密钥，再调用带鉴权的路由。
凭证 JSON 只在插件进程内通过 `host.auth.list` / `host.auth.get` 读取，永远不会到达浏览器。

## 构建

```bash
CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -ldflags "-s -w" -o u1s1.so .
```

注意：构建机的 glibc 不能比 CPA 容器的新（本构建目标为 glibc ≤ 2.34；
官方镜像为 Debian 12 / glibc 2.36）。

## 安装

```bash
cp u1s1.so <cpa>/plugins/linux/amd64/u1s1.so
```

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    u1s1:
      enabled: true
      priority: 1
```

可选的插件自有配置：

| 键 | 默认值 | 用途 |
| --- | --- | --- |
| `base-url` | `https://api.u1s1.io/v1` | 网关基础 URL（鉴权路由挂在 origin 根路径下）。 |
| `client` | `terminal` | `x-u1s1-client` 的值。 |
| `client-version` | `1.3.2` | `x-u1s1-version` 的值；需与真实 CLI 发布版本保持一致。 |
| `user-agent` | `pi (linux ...; x64)` | 必须保持 `pi (...)` 指纹。 |

## 登录

```bash
curl -H "Authorization: Bearer $MGMT_KEY" \
  "http://127.0.0.1:8317/v0/management/u1s1-auth-url"
# -> {"status":"ok","url":"https://u1s1.io/login?device=...","state":"u1s1-..."}
```

打开 URL，在浏览器里批准设备，然后轮询：

```bash
curl -H "Authorization: Bearer $MGMT_KEY" \
  "http://127.0.0.1:8317/v0/management/get-auth-status?state=<state>"
```

成功后宿主会写入 `auth-dir/u1s1-<email>.json`，内含设备令牌、P-256 密钥对和缓存的
attestation 令牌。也可以把官方 CLI 的 `~/.u1s1/config.json` 直接放进 `auth-dir` ——
`auth.parse` 会认领任何携带 `u1s1d-` 令牌加 P-256 密钥对的文件。

凭证还声明了 `refresh_interval_seconds: 43200`，这正是宿主会调用 `auth.refresh` 的原因：
对第三方 provider 而言，仅凭 `NextRefreshAfter` 永远不会触发刷新。
插件未建模的字段（`priority`、`note`、`proxy_url`、`weight`、`excluded_models` 等）
在刷新后原样保留。

## 模型前缀

u1s1 的模型 id（`deepseek-v4-flash`、`glm-5.3-flash` 等）会与其他 provider 冲突。
设置前缀让两边都能访问：

```bash
curl -X PATCH -H "Authorization: Bearer $MGMT_KEY" -H "Content-Type: application/json" \
  -d '{"name":"u1s1-<email>.json","prefix":"u1s1"}' \
  http://127.0.0.1:8317/v0/management/auth-files/fields
```

之后模型会注册为 `u1s1/deepseek-v4-flash` 等。插件会从 `auth.parse` 回显 `Prefix`，
因为宿主只对原生解析的凭证文件自动填充前缀。

默认情况下 CPA 会**同时**注册裸 id 和带前缀的 id。若只想保留带前缀的形式，设置宿主级开关：

```yaml
force-model-prefix: true
```

它只影响声明了前缀的凭证，其他 provider 不受影响。

## 思考强度

声明了 `thinking.levels` 的模型支持 CPA 的思考强度后缀：

```
u1s1/deepseek-v4-flash(high)
u1s1/glm-5.3-flash(max)
u1s1/qwen3.8-flash(off)
```

宿主只剥离鉴权前缀，所以插件自行把后缀从模型 id 上拆开，按该模型的
`request_format`（`deepseek`、`qwen` 或 `openai`）把强度翻译成对应的上游字段，
并套用网关自己的 `level_map`。模型不支持的强度回退到其 `default_level`；
对 `can_disable: false` 的模型，`(off)` 会落到最低强度而不是被拒绝。
不带后缀的请求原样透传。

## 测试

```bash
go test ./...                                    # 离线单元测试
go test -race ./...                              # 并发路径
U1S1_LIVE_TEST=1 go test -run TestLiveGateway -v # 真实网关联测，会消耗额度
```

联测读取 `~/.u1s1/config.json`，覆盖模型列表、`/me` 以及两条 chat 路径。

## 开发文档

设计细节、逆向过程与实现要点见 [DEVELOPMENT.md](DEVELOPMENT.md)。
