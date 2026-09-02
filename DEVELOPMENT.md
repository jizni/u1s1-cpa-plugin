# u1s1 CPA 插件 — 开发文档

CLIProxyAPI (CPA) 插件，把 u1s1 网关（`https://api.u1s1.io/v1`）接成原生 provider。

- 开发日期：2026-09-01 ~ 2026-09-02
- 目标宿主：CPA v7.2.145（Docker，`eceasy/cli-proxy-api:latest`）
- 状态：已部署运行，`registered: true` / `effective_enabled: true`

---

## 1. 为什么需要插件而不是反向代理

u1s1 不接受普通 Bearer token。每个请求需要**四层**凭证同时成立，缺任何一层网关返回
`403 client_integrity_review`（响应里还带"继续使用非 u1s1 客户端将封禁账号"的警告）：

| # | 层 | 内容 | 来源 |
|---|---|---|---|
| 1 | 设备令牌 | `authorization: DPoP u1s1d-…` | 设备登录时下发 |
| 2 | 每请求签名 | `dpop:` JWT，ES256 签 `{jti, htm, htu, iat, ath}`；`ath` = base64url(sha256(deviceToken))；`htu` 去掉 query 和 fragment | 本地 P-256 私钥 |
| 3 | 完整性令牌 | `x-u1s1-attestation`，TTL 7 天 | `GET /v1/models` 响应的 `client_attestation` 字段 |
| 4 | 客户端指纹 | `user-agent: pi (...)`、`x-u1s1-client/version/platform`、全套 `x-stainless-*`（官方 CLI 内嵌的 OpenAI SDK 指纹） | 固定值 |

### 关键实现坑

**签名格式**必须是 IEEE P1363 的裸 `r||s`（64 字节，WebCrypto `subtle.sign` 的输出格式）。
Go 的 `ecdsa.SignASN1` 输出 DER，会被网关直接拒绝。见 `dpop.go:signP1363()`。

**指纹头是强制的**，不是装饰。只带合法 DPoP 证明的请求同样被 403 拦下。

### 逆向方法

用两个 preload 钩子抓官方 CLI 的真实流量：

- `dump-fetch.mjs` — 包装 `globalThis.fetch`，抓 CLI 自身的请求
- `dump-dc.mjs` — 订阅 `node:diagnostics_channel` 的 `undici:request:*`，抓 pi agent 捆绑版 undici 的流量（这部分不走 global fetch）

配合 `probe-*.mjs` 系列脚本逐层验证：只带 DPoP → 403；补 attestation → 仍 403；补齐指纹头 → 200。

---

## 2. 架构

### 声明的能力

| Capability | 方法 | 行为 |
|---|---|---|
| `auth_provider` | `auth.login.start` / `auth.login.poll` / `auth.parse` / `auth.refresh` | 浏览器设备登录；凭证由宿主落盘 `auth-dir` |
| `model_provider` | `model.for_auth` | `GET /v1/models` 动态发现，5 分钟缓存；带价格/免费包说明（见 §5） |
| `executor` | `executor.execute` / `executor.execute_stream` / `executor.count_tokens` | chat-completions 进出；流式经 `host.stream.emit`；token 数本地估算 |
| `management_api` | `management.register` / `management.handle` | 额度面板 + JSON 路由 |

`executor_model_scope: oauth`，输入输出格式均为 `chat-completions`。

### 出网路径

所有上游请求走 `host.http.do` / `host.http.do_stream` 宿主桥接，因此继承 CPA 的
`proxy-url`、传输策略和请求日志。宿主桥接不可用时（单元测试）回落到插件自己的
`http.Client`。`host.stream.emit` 没有回落可言（异步流的 stream id 本身就来自宿主），
因此桥接缺失时它报错而不是静默丢 chunk。

### 错误隔离

插件运行在宿主进程内，过 cgo C ABI 进入。宿主的 `defer recover()` 只能抦它自己那一侧
的调用帧，插件侧的 panic 穿不回去，会直接终止整个 CPA 进程。因此每个可能抛出 panic 的
入口都自带屏障：`guardDispatchPanic()` 护住方法分发（转成 `plugin_panic` 信封，宿主可据此
熔断插件），`reportStreamPanic()` 护住 `pumpStream` 的 goroutine（那里连 cgo 帧都没有，
转成流错误）。

`cliproxyPluginShutdown` 是故意的空实现，原因见 §8。

### 文件职责

入口层（cgo 边界 + 分发）：

| 文件 | 行数 | 职责 |
|---|---|---|
| `abi.go` | 174 | cgo C ABI 骨架：C preamble、四个导出入口、触碰 C 符号的 `writeResponse` / `hostCall` |
| `dispatch.go` | 105 | 方法分发 `handleMethod`、`dispatchMethod`、panic 屏障 |
| `bridge.go` | 61 | 插件↔宿主信封协议（`{ok,result,error}`）、`hostBridgeUnwrap` |

配置与共享状态：

| 文件 | 行数 | 职责 |
|---|---|---|
| `config.go` | 147 | 插件配置（base-url/client/client-version/user-agent）、注册声明 |
| `state.go` | 76 | 全部包级可变状态集中处（每块标注读写者，为拆包留口子） |

凭证与安全原语：

| 文件 | 行数 | 职责 |
|---|---|---|
| `credentials.go` | 149 | 凭证结构 `storedAuth`（含 Extra 保留往返）、解析校验 |
| `dpop.go` | 217 | JWK 解析与配对校验、P-256 密钥生成、P1363 签名、DPoP 头构造 |
| `headers.go` | 46 | 客户端指纹头、签名头（指纹 + DPoP + attestation） |
| `attestation.go` | 153 | client_attestation 令牌缓存（提前刷新、失败退避、并发合并） |

网关端点（wire 层，按端点一文件）：

| 文件 | 行数 | 职责 |
|---|---|---|
| `gateway_models.go` | 114 | `/v1/models` 端点与响应 wire 类型 |
| `profiles.go` | 81 | 每模型 thinking 契约缓存（由 `/models` 喂养，executor 读取） |
| `announcement.go` | 83 | 网关公告缓存（TTL 刷新、URL 校验） |
| `gateway_me.go` | 64 | `/v1/me` 端点与额度 wire 类型 |
| `gateway_device.go` | 98 | `/auth/device/start` / `poll` 端点 |
| `gateway_errors.go` | 57 | 上游错误解析与错误尾巴（HTTP 状态 · code · 请求编号） |

能力实现：

| 文件 | 行数 | 职责 |
|---|---|---|
| `auth.go` | 389 | 登录会话、poll 状态机、`auth.parse`、refresh、AuthData 与 metadata 构造 |
| `models.go` | 204 | 模型表映射为 ModelInfo（含价格/免费包说明）、attestation 回写 |
| `thinking.go` | 164 | 模型后缀拆解、等级映射、按 request_format 写上游推理字段 |
| `executor.go` | 442 | 请求体归一化、非流式/流式执行、SSE 扫描与 framing、token 估算 |
| `upstream.go` | 431 | 宿主 HTTP 桥接（buffered + streaming）、stream emit/close、日志脱敏 |
| `management.go` | 391 | 管理路由、额度快照缓存（双锁）、用量包标签 |
| `host_auth.go` | 87 | `host.auth.list` / `host.auth.get` 封装 |

面板与工具：

| 文件 | 行数 | 职责 |
|---|---|---|
| `panel.go` | 25 | 面板 HTML 嵌入与 base path 注入 |
| `panel.html` | 368 | 额度面板（内嵌，不加载任何第三方脚本） |
| `util.go` | 25 | UUID / 随机 hex |

---

## 3. 构建与部署

### 构建

构建命令见 README「构建」。本文件只补充工具链细节：

工具链：Go 1.27.0。产物 8.2MB，最高 glibc 符号需求 `GLIBC_2.34`。

**glibc 兼容性**：必须在不高于容器 glibc 的环境构建。官方镜像是 Debian 12（glibc 2.36），
本次构建机是 Debian 13（glibc 2.41）但实际符号需求只到 2.34，因此可用。换构建机时需
重新用 `objdump -T u1s1.so | grep GLIBC_ | sort -uV | tail -1` 确认。

### 安装与插件配置

安装步骤（`cp`、`chmod`、`config.yaml`）与插件配置项表、同名环境变量见 README「安装」「配置」，
本文件不再重复。

### 版本管理

插件的注册版本号（`registration.Metadata.Version`，管理控制台可见）来自
`main.pluginVersion`，构建时经 `-ldflags "-X main.pluginVersion=$(VERSION)"` 注入
（定义见 `config.go`）。未注入时（`go build .` 或 CI 测试构建）默认 `dev`。

- `make build` 默认取 `git describe --tags --always --dirty`，release tag 检出时无需额外参数。
- 发布流水线（`.github/workflows/release.yml`）由 `v*` tag 触发，去掉 `v` 前缀注入版本号，
  并在发布前强制校验 glibc 符号需求 ≤ 2.36（容器是 Debian 12 / glibc 2.36）。
- 发布产物：`u1s1.so` + `u1s1.so.sha256`，挂在 GitHub Release 资产上；用 `vX.Y.Z` tag 发版。

### 插件替换需重启容器

CPA 的插件宿主（`pluginhost`）只在**插件文件路径变化**时才重建插件：
`ApplyConfig` 用 `cleanPluginPath(loaded.path) != cleanPluginPath(file.Path)` 判断，
覆盖同一个 `u1s1.so` 文件 + `touch config.yaml` 不会触发重载，宿主仍持有旧库的 inode。

因此**替换插件（哪怕只是改配置）后必须重启容器**才能让新版本生效：

```bash
cp dist/u1s1.so <cpa>/plugins/linux/amd64/u1s1.so && docker restart cli-proxy-api
```

重启后核对日志确认新版本已加载：模型重新注册（`Registered new model u1s1/...`）、
宿主调用 `auth.refresh`（`refreshed u1s1, ...`）。管理面板的 `/v0/resource/plugins/u1s1/panel`
返回 200 说明管理路由已注册。

---

## 4. 授权与凭证持久化

### 设备登录

命令行流程（发起设备登录、浏览器批准、轮询）见 README「登录」。流程细节：

`auth.login.start` 生成 P-256 密钥对 → `POST {origin}/auth/device/start`
（带 `public_jwk`、设备名、客户端版本）→ 返回 `verify_url` + `poll_secret`；宿主按自己
的节奏反复调 `auth.login.poll`，插件每次做一次 `POST {origin}/auth/device/poll`；
`status: "ok"` 时构造 AuthData，宿主写盘。

设备批准后的顺序是**先 `/models` 拿 attestation，再带着它调 `/me`**：`/models` 是唯一
不需要 attestation 的路由，其余请求缺这一层就可能吃 403 client_integrity_review。

网关返回的 `interval` 钳到 `[2,30]` 秒且**保留更慢的值**——限流场景下网关要求 60s，钳成
30s 而不是重置为 2s。轮询遇到永久性 4xx（poll_secret 失效、设备被封；429 除外）直接结束
会话并报错，不再一路 pending 到会话过期。

### 凭证文件

落在 `auth-dir/u1s1-<email>.json`，字段与官方 CLI 的 `~/.u1s1/config.json` 同名，
因此把现有 CLI 登录态直接复制进 `auth-dir` 也能被 `auth.parse` 认领：

```json
{
  "type": "u1s1",
  "baseUrl": "https://api.u1s1.io/v1",
  "apiKey": "u1s1-…",
  "deviceToken": "u1s1d-…",
  "deviceId": 0,
  "devicePrivateJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "d": "…" },
  "devicePublicJwk":  { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "email": "user@example.com",
  "prefix": "u1s1",
  "attestation": "…",
  "attestationExpiresAt": 0,
  "createdAt": "2026-09-01T00:00:00Z"
}
```

`auth.parse` 的认领条件：JSON 里同时存在 `u1s1d-` 前缀的 `deviceToken` 和完整的
P-256 密钥对。不满足就返回 `Handled: false`，不抢别的 provider 的文件。公私钥不配对的
文件在解析期就被拒（`parsePrivateJWK` 校验 `d·G == (x,y)`），避免上线后拿到难以排查的 401。

文件名归属：`auth.parse` 回显发现时的文件名；`auth.refresh` 和 `model.for_auth` 的
`AuthUpdate` 则把 `FileName` **留空**交给宿主回填。否则 `authDataFor()` 会按 email 重算出
`u1s1-<email>.json`，把手工改名或直接拷进来的 `config.json` 改名/复制成第二份凭证
（后果是模型重复注册、面板出现两行同一账号）。

### 写盘契约：metadata 必须是凭证的全集

`AuthData.Metadata` 不是"展示用字段"，而是**写盘的权威来源**。宿主在落盘前会：

1. 读出同名的**旧文件**，把其中所有键补进 `Metadata`
   （`management.saveTokenRecord` → `MergeExistingAuthMetadata`）；
2. 再让 `Metadata` 覆盖 `StorageJSON`（`mergedStorageJSON`）。

所以插件**没写进 metadata 的凭证字段会被旧文件的值填回来**。宿主自带的保护
（`IsAuthTokenPayloadKey`）只认 `access_token` 那一族名字，u1s1 一个都不沾。后果很具体：
重新批准设备后，刚下发的 `deviceToken` / `devicePrivateJwk` / `attestation` 会被**已吊销的
旧值覆盖**，新凭证静默丢弃。

因此 `credentialMetadata()` 把整份凭证 dump 进 metadata，`attestation` /
`attestationExpiresAt` 即使为空也显式写入（空 attestation 必须重新拉取，而不是继承一个
为旧设备注册签发的令牌）。

反过来，`prefix` 和 `email` 依赖的正是同一条规则的另一面：`omitempty` 让它们在为空时
**不出现**，而"不出现"才是宿主允许回填的信号。写成显式空串会把宿主已知的值清掉。

### 结构体往返不能吃掉未建模的字段

`auth.refresh` 和 `model.for_auth` 都是"解码凭证 → 改 attestation → 重新编码"。
`storedAuth` 只建模 11 个字段，凭证文件里其余的键——`priority`、`note`、`proxy_url`、
`weight`、`excluded_models`、`disabled`、`request_retry`、`headers`——会在 marshal 时消失，
每 12 小时掉一次。

`storedAuth` 因此带 `Extra map[string]json.RawMessage` 并自定义
`MarshalJSON`/`UnmarshalJSON`：未建模的键原样保留，已建模字段始终优先。已建模键的集合由
结构体 tag 反射得出，加字段时不会漏改。

### attestation 生命周期

TTL 7 天，提前 24 小时刷新，失败后 30 秒冷却避免打爆网关。令牌同时缓存在内存
（按 authID，AuthID 为空时按设备令牌，`attestationCacheKey()` 统一定义）和凭证文件
（`attestation` / `attestationExpiresAt`），后者让重启后的第一次聊天请求不需要额外的
`/models` 往返。

刷新分两段加锁：判定用 `entry.mu`（只覆盖内存读写），真正的 `/models` 往返在 `entry.mu`
之外、由 `entry.fetching` 串行化。这样同一凭证的并发聊天请求会合并成一次刷新，同时读到
旧令牌的请求不必排在一次网络往返后面。

网关没下发 `expires_in` 时，写盘和内存缓存都按 `attestationUnknownTTL`（48 小时）记一个
**有界**过期时间（`attestationFreshUntil()`），既不会永不刷新，也不会每个请求都去拉
`/models`。反过来，凭证文件里只有 `attestation` 而没有 `attestationExpiresAt` 的旧数据
（或手工拷进来的 CLI config）视为过期，首次使用即换新，不赌剩余寿命。

### 让宿主真的调用 auth.refresh

光设 `AuthData.NextRefreshAfter` **不会**触发任何刷新——它只是给"已经被别的规则要求刷新"
的凭证加一道时间闸门。宿主 `shouldRefresh()` 的判定链走到最后是
`ProviderRefreshLead(provider)`，而 `refreshLeadFactories` 只注册了
codex/claude/antigravity/kimi/xai，第三方 provider 返回 `nil` → `shouldRefresh` 为 false，
`nextRefreshCheckAt` 也返回 `scheduled=false`，凭证根本不进自动刷新堆。

唯一对插件开放的入口是 metadata/attributes 里的 `refresh_interval_seconds`，因此
`credentialMetadata()` 写入 `43200`（12 小时），并镜像到 attributes 让首次落盘前的内存记录
也生效。这个值必须小于 `attestationUnknownTTL - attestationRefreshMargin`（48h − 24h），
否则缺 `expires_in` 时刷新会追不上过期。

---

## 5. 模型目录

### 模型前缀

u1s1 的模型 id（`deepseek-v4-flash`、`glm-5.3-flash` 等）与其他 provider 撞名。设前缀的命令与
`force-model-prefix` 宿主级开关见 README「模型前缀」。插件侧的两个要点：

- `auth.parse` 必须回显 `Prefix`，否则管理台设的前缀会在下次刷新时消失——宿主只对**原生解析**
  的凭证文件自动回填该字段（根源见 §8「prefix 静默丢失」）。
- 宿主的 `rewriteModelForAuth` 会在发往上游前剥掉**前缀**，但**不剥 thinking 后缀**——那一步
  归插件自己，见下面的「thinking 后缀」。

CPA 默认对设了前缀的凭证注册**两份**（裸 id + 带前缀 id），6 个模型变 12 条；
`force-model-prefix: true` 只保留带前缀的形式，且只影响声明了 prefix 的凭证，其他 provider 不受影响。

---

### 模型说明：免费包覆盖与价格

`/v1/models` 的每条记录带三个计费相关字段，插件把它们拼成 `ModelInfo.Description`
（宿主原样转给客户端的 `/v1/models`）：

| 字段 | 含义 |
|---|---|
| `free_package_eligible` | 免费用量包是否覆盖该模型。老网关没有这个字段 |
| `price` | 当前单价（USD / 百万 token），`cache_read` 可为 null |
| `price_bands` | 峰/闲价模型的两档价格 + `current` 指出此刻生效的那一档 |

拼出来的形状与官方 CLI 模型选择器里那一行一致：

```
免费用量包可抵扣 · $0.22/$0.66 每百万 token（峰/闲价 · 当前闲时价）
不走免费包 · 费用约为默认模型 3 倍 · $0.66/$1.98 每百万 token
```

倍数的基准是 `deepseek-v4-flash`（网关 `/v1/me` 里的 `daily_free_model`，也是 CLI 的默认
模型），按 `(input + output) / 2` 的混合价比较，与 CLI 的 `deriveModelNote` 同一算法。
不足 2 倍时只说"不走免费包"——四舍五入出来的"1 倍"是噪音。

这一行不是装饰：u1s1 上"用哪个模型"直接决定这次请求免费还是扣余额，而 CPA 的模型列表
除了 id 之外没有任何地方能表达它。`free_package_eligible` 缺失（老网关）时**不产生**覆盖
结论——猜"覆盖"会让用户白烧余额，猜"不覆盖"会让人不敢用免费模型。

价格用 `strconv.FormatFloat(v, 'f', -1, 64)` 打印，保持 `0.075` 而不是 `0.08`：
`glm-5.3-flash` 的输入价正是三位小数。

`reasoning` 标记也不再是 thinking 的前置条件——CLI 的 `apiModelToDef` 里
`reasoning: m.reasoning || thinking !== undefined`，即网关下发了 `thinking.levels`
就按推理模型处理。插件跟随这一契约（`gatewayModel.hasThinking()`），否则一个只给了
levels 但 `reasoning: false` 的模型会丢掉全部思考等级。

---

### thinking 后缀

`model.for_auth` 声明了 `Thinking.Levels`（来自 `/v1/models` 的 `thinking.levels`），
所以客户端可以请求 `u1s1/deepseek-v4-flash(high)`。宿主只剥前缀，**后缀会原样留在
`req.Model` 里**（所有原生 executor 都自己调 `thinking.ParseSuffix`）。直接转发
`deepseek-v4-flash(high)` 会被网关以 400 unknown model 拒掉。

`thinking.go` 因此做两件事：拆后缀，并按该模型的 `request_format` 写上游字段——三种
形状与官方 pi 客户端（`openai-completions` 适配层）一致：

| request_format | 上游字段 |
|---|---|
| `deepseek` | `thinking: {type: enabled\|disabled}` + `reasoning_effort` |
| `qwen` | `enable_thinking: bool` + `reasoning_effort` |
| `openai`（及其他） | 仅 `reasoning_effort` |

等级名还要经 `level_map` 换成网关自己的词汇（如 `off → none`）。几个边界：

- 该模型未声明的等级（如只有 off/low/high/max 的模型收到 `(medium)`）→ 回退到
  `default_level`，而不是把网关不认的值送上去。
- `can_disable: false` 的模型收到 `(off)` → 给它最低等级，而不是一个会被拒的 disable。
- 数字后缀 `(8192)`：u1s1 没有 budget 字段，正数仅意为"开启思考"，`(0)` 为关闭。
- 没有缓存到 profile 的模型：只剥后缀，**不**凭空添加推理字段（给未知模型猜字段正是 400
  的来源）。

profile 由 `fetchModels()` 缓存，而不是只在 `model.for_auth` 里：聊天请求带着后缀但没有
模型表，而 `/models` 是每条凭证路径都会经过的那一个路由。

---

## 6. 管理面板

CPA 管理台侧边栏出现 `u1s1` 菜单，指向：

```
/v0/resource/plugins/u1s1/panel
```

面板内容：今日免费额度（带进度条）、永久余额、本月已用、包内剩余 Token、额度重置时间，
以及全部用量包的表格（中文名、剩余/额度进度条、今日已用、适用范围、到期时间）。数字格式
与 `u1s1 usage` 的 万/亿 表达一致。

**单位口径跟 CLI 对齐**：金额卡片以 Token 为主、美元为副（按 `/v1/me` 下发的
`tokens_per_usd` 折算）。用量包本身就是用 Token 计量的，只给美元让人无法对照包里还剩
多少。老网关没有 `tokens_per_usd`，此时只有美元数字有意义，面板自动退回纯美元显示。

**运维公告**：`/v1/models` 的 `announcement` 字段（网关后台下发，维护窗口/政策变更都走
它）缓存在插件进程内，随 `usage` / `refresh` 响应下发，页首渲染。官方 CLI 也在会话内
轮询它（`announcements-poll.js`，5 分钟一次），理由一样：否则一次计划内维护对用户而言
就只是一串裸错误。公告在采集额度时顺便刷新（`refreshAnnouncementIfStale`，超过 5 分钟才
拉一次 `/models`，只用第一条凭证）——聊天流量本来也会带回公告，但不能指望一个只跑
固定模型的宿主恰好在维护窗口重拉过模型表。刷新失败不影响面板（旧公告强于加载失败）。
公告文本转义后插入，url 先在 Go 侧校验为 http(s)（`isHTTPURL`）才会变成链接，避开
`javascript:` 之类的 href。

**免费包待领取**：`/v1/me` 的 `free_claim` 为 `"first"`（首月包）或 `"renew"`（年度包）
时，账号行上出现指向官网 dashboard 的角标。只能跳转不能代领：领取接口在 `u1s1.io`
（非网关）且要浏览器会话 Cookie 加两道人机验证，同 §9 的签到结论。

JSON 路由（需管理密钥）：`GET /v0/management/plugins/u1s1/usage` 与
`POST /v0/management/plugins/u1s1/refresh`（用途、参数见 README「额度面板」）。

错误语义：`/v1/me` 逐凭证读失败时，对应账号在 `accounts` 里带 `error` 字段（面板显示"读取失败"）；
而 `host.auth.list` 枚举本身失败时，若有旧快照则继续返回旧快照（不污染缓存、不刷新时间戳），
没有任何可用快照时返回 502 + `{"error": ...}`，避免把"暂时读不到"伪装成"没有凭证"。

锁的划分：`usageCacheMu` 只护快照本身，`usageCollectMu` 只负责把并发采集合并成一次。
两者分开是因为采集是 N 个 `/me` 往返：若把缓存锁持有到采集结束，一个慢账号就能把所有
缓存命中和 `snapshotTime()` 一起阻住。

### 安全边界

按宿主契约，资源页 GET **不做管理鉴权**，因此：

- 页面 HTML 里不含任何额度或凭证数据，只有骨架和脚本
- 数据由页面自己带管理密钥去调认证路由
- 密钥来源顺序：URL `?key=`（读取后从 history 里抹掉）→ `sessionStorage` → 内嵌在管理台时
  读同源 `localStorage`（与 workbuddy 一致的做法）
- 凭证 JSON 经 `host.auth.list` / `host.auth.get` 在进程内读取，不出插件
- 所有日志与错误信息经 `redactSecrets()` 脱敏（`u1s1d-` / `u1s1-` 前缀的令牌替换为
  `[redacted]`）

### 主题

无自带主题设置。首屏绘制前读取父窗口的 `data-theme`，用 `MutationObserver` 跟随后续变化；
独立打开时回落系统 `prefers-color-scheme`。CSS 变量沿用 CPA 管理台的 token（paper / white / dark）。

---

## 7. 测试

测试命令（离线单测、`-race`、`U1S1_LIVE_TEST=1` 联测）见 README「测试」，此处不再重复。
当前离线测试：67 个测试函数、6 个子测试用例（`go test ./...` 全绿）。覆盖的关键点：

- DPoP 证明的完整结构，且签名能用公钥验签通过；私钥标量不出现在 header 的 JWK 里
- 公私钥不配对的 JWK 在解析期被拒
- 指纹头完整性（缺一个就意味着线上 403）
- `auth.parse` 只认领 u1s1 文件、不误伤其他 provider
- 凭证身份不嵌入完整设备令牌
- 请求体归一化（强制 model、stream 开关、`stream_options` 增删）
- SSE 扫描丢弃 `[DONE]` 和非法 JSON
- 跨格式入口的 `data: ` framing 判定
- **流式中途上游断开必须报错**（已 emit 过 chunk 也要报），而客户端断开必须静默
- 空流、上游 4xx 的错误路径
- attestation：未知过期时间不被无限信任、缺 `expires_in` 不会每请求重拉、刷新与读取共用缓存键
- 设备登录 `interval` 钳制保留更慢的值；永久性 4xx 结束会话而非一路 pending
- 登录时 `/models` 先于 `/me`，且 `/me` 带上刚拿到的 attestation
- `auth.refresh` / `model.for_auth` 的 AuthUpdate 不重算 FileName
- 空 email / 空 prefix 不写进 metadata 与 attributes
- 面板资源路由精确匹配（不吃裸前缀、子路径、兄弟前缀）
- 面板 HTML 不泄漏凭证/额度、无自带主题开关、工具栏在正常文档流内
- 日志脱敏（长前缀优先，`u1s1d-` 不被 `u1s1-` 抢先匹配）；`plugin_error` 信封也脱敏
- 流式桥接错误透传上游状态码（宿主返回 4xx 且无 stream_id 时不再误报"bridge unavailable"）
- 枚举失败不污染 usage 快照缓存；无快照可回退时 usage/refresh 路由返回 502
- **metadata 包含凭证全集**（逐键比对 StorageJSON），空 attestation 也显式写入，否则重新
  登录会被旧凭证覆盖
- 未建模字段（priority/note/proxy_url/weight/excluded_models/headers/…）在
  解码→编码往返与 `auth.refresh` 后完整保留
- 声明 `refresh_interval_seconds`，且小于 `attestationUnknownTTL - attestationRefreshMargin`
- thinking 后缀：从 model id 剥除；三种 request_format 各自的字段形状；未声明的等级回退到
  default；`can_disable:false` 的模型不发 disable；数字 budget；未知模型不添加字段；
  `fetchModels` 缓存 profile
- panic 不穿越 cgo 边界：转成 `plugin_panic` 信封并脱敏；pump goroutine 的 panic 变成流错误
- 同一凭证的并发 attestation 刷新合并为一次 `/models`（不再串行化聊天请求）
- usage 采集期间 `snapshotTime()` 不被阻塞
- `count_tokens` 返回正数估算且随提示长度增长（CJK 按字、拉丁按字节）
- 模型说明：免费包覆盖与价格倍数的基准选取、不足 2 倍不说倍数、老网关缺
  `free_package_eligible` 时不下覆盖结论、峰/闲价标出当前生效档、价格不被四舍五入
- `thinking.levels` 存在但 `reasoning: false` 的模型仍暴露思考等级
- 错误文本尾巴带 HTTP 状态码/错误代号/请求编号，`insufficient_quota` 归一
- 网关公告：随 `/models` 捕获、被清空时从面板消失、非 http(s) URL 不变成链接、
  经管理路由下发、缓存新鲜时不重拉 `/models`、过 TTL 后只重拉一次
- `/me` 的 `free_claim` 为 null 时不报错且不渲染角标

---

## 8. 排查过的非显而易见问题

### 流式截断被静默吞掉

`pumpStream` 原来用 `if emitted == 0` 判断要不要上报错误，本意是"emit 失败说明客户端已
断开，别往死流里写"。但它分不清失败来源：**上游**读失败（网络断、SSE 单行超 4MB）发生在
已 emit 若干 chunk 之后时，函数直接返回，宿主补上自己的 `[DONE]`，客户端看到一份截断但
"正常结束"的回答。

修法：把 emit 失败单独记成 `emitBroken`，只有它为真才静默；其余失败即使已 emit 过也照报。
逻辑抽到 `pumpStreamChunks()` 便于注入 emit/emitError 做测试。回归测试
`TestPumpStreamReportsUpstreamFailureAfterChunks`（用 hijack 制造无终止 chunk 的连接）与
`TestPumpStreamStaysSilentWhenClientDisconnects`。

### prefix 静默丢失

`AuthData.Metadata` 里写入 `"prefix": ""` 会覆盖宿主已存的 model prefix。宿主只补齐
**缺失**的 metadata 键，显式空值它照抄。结果是重启后 `u1s1/*` 全部消失，请求报
`unknown provider for model u1s1/deepseek-v4-flash`。

修法：prefix 非空才写入该键，空值交给宿主回填。回归测试
`TestAuthDataOmitsEmptyOptionalMetadata`。

另一半原因：宿主只对**原生解析**的凭证文件自动回填 `Prefix` 字段，插件解析路径必须
自己在 `AuthData.Prefix` 里回显。

同一类问题还适用于 `email`（metadata + attributes）：空值不写，交给宿主回填。

### 模型数量翻倍

`sdk/cliproxy/service_models.go` 的 `applyModelPrefixes()` 对设了 prefix 的凭证会
`addModel` 两次：

```go
if !forceModelPrefix || trimmedPrefix == baseID {
    addModel(model)      // 裸 id
}
clone := *model
clone.ID = trimmedPrefix + "/" + baseID
addModel(&clone)         // 带前缀 id
```

上游只有 6 个模型，注册出 12 条。开 `force-model-prefix: true` 跳过第一个分支即可。

副作用：撞名的裸 id 在开关打开前会同时挂着两个 provider 的凭证，调度器随机挑选；
打开后归属清晰。u1s1 独有的模型裸名会返回 400，必须带前缀访问。

### 重新登录被旧凭证覆盖

与"prefix 静默丢失"同源，但方向相反，后果严重得多。`authDataFor()` 把 `ID` 和
`FileName` 都算成 `u1s1-<email>`，因此重新批准设备后，宿主的 `saveTokenRecord`
会先读出**同名的旧文件**，再用 `MergeExistingAuthMetadata` 把旧 map 里所有键补进新记录。
`deviceToken` / `devicePrivateJwk` / `attestation` 都不在宿主的 `IsAuthTokenPayloadKey`
白名单里（那个白名单只有 `access_token` 那一族），于是旧设备令牌直接盖掉刚下发的新令牌。
旧令牌若已在网关侧失效，结果是重登之后依旧 401，且凭证文件看上去完全正常。

修法：`credentialMetadata()` 把整份凭证写进 metadata（而不只是 email/prefix），并对
`attestation` / `attestationExpiresAt` 显式写空值。回归测试
`TestAuthDataPublishesEveryCredentialKeyInMetadata` 逐键比对 metadata 与 StorageJSON，
`TestAuthDataPublishesEmptyAttestationExplicitly` 盯住空值那一半。

两条规则共存并不矛盾：`prefix`/`email` 靠 `omitempty` 保持**缺失**让宿主回填，
凭证字段靠**存在**阻止宿主回填。

### auth.refresh 从来没被调用过

文档曾经写着"`auth.refresh` 每 12 小时被宿主调用一次"，实际上一次也没调过。插件只设了
`AuthData.NextRefreshAfter`，而那个字段只能**推迟**一次已经被决定要做的刷新，它不会
发起刷新。宿主 `shouldRefresh()` 的判定链：`NextRefreshAfter` 已过 → 无
`RefreshEvaluator` → 无 `refresh_interval_seconds` → `ProviderRefreshLead("u1s1")`，
而 `refreshLeadFactories` 只注册了 codex/claude/antigravity/kimi/xai → 返回 `nil` →
`shouldRefresh` 为 false，`nextRefreshCheckAt` 也返回 `scheduled=false`，凭证根本不进
自动刷新堆。

这正好解释了为何上面两个写盘 bug 一直没被发现——写盘路径几乎没被走到。

修法：metadata 与 attributes 都写 `refresh_interval_seconds: 43200`。回归测试
`TestAuthDataRequestsRefreshInterval`，并顺手断言该值小于
`attestationUnknownTTL - attestationRefreshMargin`（否则网关缺 `expires_in` 时刷新会
追不上过期）。

### 结构体往返吞掉用户字段

`auth.refresh` 和 `model.for_auth` 都是 `parseStored()` → 改 attestation →
`json.Marshal()`。`storedAuth` 只建模 11 个字段，凭证文件里其余的键在 marshal 时消失：
`priority`、`note`、`proxy_url`、`weight`、`excluded_models`、`disabled`、
`request_retry`、`headers`。用户在管理台设的值每次刷新掉一次。

修法：`storedAuth.Extra map[string]json.RawMessage` + 自定义
`MarshalJSON`/`UnmarshalJSON`，未建模的键原样过渡，已建模字段优先。已建模键集合由结构体
tag 反射得出，以后加字段不会漏改。回归测试 `TestStoredAuthPreservesUnknownKeys` 与
`TestAuthRefreshPreservesUserFields`。

### thinking 后缀被原样发给上游

`model.for_auth` 声明了 `Thinking.Levels`，于是客户端可以请求
`u1s1/deepseek-v4-flash(high)`。宿主 `rewriteModelForAuth` 只剥 `u1s1/` 前缀，不剥后缀：

```
u1s1/deepseek-v4-flash(high)  →  executor req.Model = "deepseek-v4-flash(high)"
```

旧 `resolveModel()` 直接把它塞进 `obj["model"]`，上游返回 400。所有原生 executor 都走
`thinking.ParseSuffix(req.Model).ModelName`，插件漏了这一步；同时也没把 level 翻译成上游
要的形状。修法见 §5 的「thinking 后缀」。

### panic 穿越 cgo 边界

插件原本没有任何 `recover()`。宿主的 `defer recover()` 只保护它自己那一侧的调用；
`cliproxyPluginCall` 里的 panic 穿不回去，会直接带倒整个 CPA 进程，而不是被宿主的
`fusePlugin` 熔断。`pumpStream` 的 goroutine 更糟——那里连 cgo 帧都没有。

修法：`guardDispatchPanic()` 把 panic 转成脱敏后的 `plugin_panic` 信封；
`reportStreamPanic()` 把 pump goroutine 的 panic 转成流错误，且 `streamClose` 先 defer
后执行，客户端不会卡在一个被抛弃的流上。

### shutdown 的 SIGSEGV

`cliproxyPluginShutdown` 原本遍历 `loginSessions` 做 `Delete`。宿主在自己 Go runtime
开始拆解**之后**才调 shutdown，随即 `dlclose`；此时触碰任何 Go runtime 状态（含
`sync.Map`）在 cgo 里会 SIGSEGV。workbuddy 插件把同一个函数故意留空就是这个原因
（他们每次 docker restart 都能复现）。清理本身也没意义：进程都要退了。

修法：空实现 + 注释说明为何不能动。

### 次要修正

- **attestation 刷新串行化**：`entry.mu` 原本跨整个 `/models` 往返持有，同一凭证的并发
  聊天请求全部排队。现在判定和刷新分开，`entry.fetching` 只负责合并刷新。
- **usage 缓存锁**：`usageCacheMu` 原本跨 N 个 `/me` 往返持有，一个慢账号就能把面板和
  `snapshotTime()` 一起阻住。拆成 `usageCacheMu`（只护快照）+ `usageCollectMu`（只串行化
  采集）。
- **`streamEmit` 静默失败**：无宿主桥接时现在报错而不是丢 chunk。
- **`count_tokens` 恒返 0**：宿主把它当真值写进用量日志，客户端拿它做上下文预算，0 读
  起来就是"空对话"。改为本地估算（CJK 按字、拉丁按字节，向上取整，含每消息开销），
  并同时输出 `usage` 字段方便跨格式翻译器。
- **`truncate()` 按字节切 UTF-8**：这个函数的输入全是网关的中文文本（错误信息、公告），
  中文字符 3 字节，切到一半就把非法 UTF-8 写进了 JSON 响应和日志。现在回退到最近的
  rune 边界（`utf8.RuneStart`）。

---

## 8.1 跟进 u1s1-cli 1.4.1

对照 1.3.2 → 1.4.1 的 `dist/` 变更逐项核对，与插件相关的四处已跟进：

**`client-version` → `1.4.1`**。指纹头必须跟真实发布版保持一致：网关的完整性拦截文案直接
说"请升级并重新登录 u1s1"。实测 1.3.2 今天仍然 200（`x-u1s1-version` 不在当前拦截条件
里），但押它永远不进拦截规则没有意义。其余指纹本版无变化：pi-coding-agent 0.84.4、
内嵌 openai SDK 6.40.0、node v22.23.2，与 `stainlessPackageVersion` /
`stainlessRuntimeVersion` 当前值一致。

**错误文本带上尾巴**。新增的 `dist/error-humanize.js` 把模型调用错误从
`429: {json}` 改写成"中文正文 + (HTTP 429 · code · 请求编号 …)"。尾巴的两个理由在它
的注释里写得很死：`insufficient_quota` 是 pi 区分"不要重试"的分类关键字，
`request_id` 是客服直查日志的唯一凭据。`gatewayMessage()` 因此不再只返回 `message`，
还把状态码/代号/请求编号拼在末尾（`errorTail()`），并把 `type: insufficient_quota` 与
`code: quota_exceeded` 归一到同一个词。

**模型说明**。`free_package_eligible` 是 1.4.1 新增的网关字段，CLI 用它派生选择器里那一行
"免费包可抵扣 / 不走免费包·约 N 倍"（同时删掉了内置目录的硬编码价格，价格权威全归
网关）。插件把它变成 `ModelInfo.Description`，详见 §5。

**面板向 `u1s1 usage` 新口径对齐**。CLI 把额度报告抽成 `usageReportLines()` 供会话内
`/usage` 复用，同时：`login_checkin_bonus` 标签定为"打卡加成"（插件原作"打卡加量"）；
"本月成本"改叫"本月已用"并以 Token 为主；不走免费包的模型从"仅可使用余额"改为
"可用余额或全模型包"。面板同步了这三处。另外新增了公告横幅与 `free_claim` 角标（见 §6）。

面板的 JS 不由 Go 单测执行，因此改完额外用 `node --check` 验语法，再把 `renderAccount` /
`renderNotice` 提到最小 DOM 桩上跑一遍，确认两种网关（有/无 `tokens_per_usd`）下都
不出 `undefined` / `NaN`。Go 单测只能盯住面板的结构不变式（数据不泄露、无自带主题
开关、外链带 `rel=noopener noreferrer`、用 `tokens_per_usd` 换算）。

没有跟进的部分：1.4.1 的其余变更（`/help` 会话内命令、空目录开场提示、`deploy --help`、
子命令拼错纠正、登录限流原因透传）都是 CLI 自己的 TUI 交互，与网关契约无关。
`/v1/models` 的 `price_bands`（峰/闲价）官方 CLI 自己也还没用上，只有网页价格表在读；
插件直接把当前生效的那一档写进了说明。

---

## 9. 未实现：每日签到

网页版签到端点是 `POST https://u1s1.io/api/packages/login-checkin/claim`（注意域名是
`u1s1.io`，不是 `api.u1s1.io`）。无法接入，三个原因：

**鉴权体系不同。** 网站 API 用浏览器会话 Cookie（`credentials: "same-origin"`），不认设备
DPoP。用设备凭证签名请求 `/api/me` 和签到端点均返回 `401 not logged in`。

**网关侧无等价路由。** 试过 `/v1/checkin`、`/v1/packages/login-checkin/claim`、
`/v1/me/checkin`、`/v1/login-checkin/claim`、`/v1/claim/login-checkin`、`/v1/checkin/status`
全部 404。`/v1/me` 的顶层字段不含网页版的 `login_checkin`（打卡状态、连续天数、日历数据）。
设备令牌换 Web 会话的入口也不存在（`/auth/device/session`、`/auth/device/exchange`、
`/auth/session` 均 404）。

**双重人机验证。** claim 请求体强制携带 capcat（`cap-widget`）token 和 Cloudflare
Turnstile token（action 绑定为 `claim_login_checkin`），Turnstile 处于启用状态。此外签到
还有 `phone_required` 前置门槛。这两个 token 需要真实浏览器执行挑战。

可选替代（未实现）：从 `/v1/me` 的 `login_checkin` 类型用量包的 `created_at` 可以推断历史
打卡日期，据此在面板上展示"今日是否已打卡 / 连续天数"并提供跳转到官网 dashboard 的按钮。

---

## 10. 依赖

```
github.com/router-for-me/CLIProxyAPI/v7 v7.2.30   # pluginapi / pluginabi 类型定义
gopkg.in/yaml.v3 v3.0.1                            # 解析 plugins.configs.u1s1
```

SDK 版本（v7.2.30）低于运行时宿主（v7.2.145）不影响兼容性：插件与宿主之间走稳定
C ABI + JSON envelope，SDK 只提供结构体定义。

---

## 11. 参考

- CPA 插件文档：https://help.router-for.me/plugin/development
