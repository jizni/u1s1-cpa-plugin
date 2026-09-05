# u1s1 CPA 插件 — 开发文档

CLIProxyAPI (CPA) 插件，把 u1s1 网关（`https://api.u1s1.io/v1`）接成原生 provider。

- 开发日期：2026-09-01 ~ 2026-09-03
- 目标宿主：CPA v7.2.147（Docker，`eceasy/cli-proxy-api:latest`）
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

| 文件 | 职责 |
|---|---|---|
| `abi.go` | cgo C ABI 骨架：C preamble、四个导出入口、触碰 C 符号的 `writeResponse` / `hostCall` |
| `dispatch.go` | 方法分发 `handleMethod`、`dispatchMethod`、panic 屏障 |
| `bridge.go` | 插件↔宿主信封协议（`{ok,result,error}`）、`hostBridgeUnwrap` |

配置与共享状态：

| 文件 | 职责 |
|---|---|---|
| `config.go` | 插件配置（base-url/client/client-version/user-agent/web-origin/checkin-*）、注册声明 |
| `state.go` | 全部包级可变状态集中处（每块标注读写者，为拆包留口子） |

凭证与安全原语：

| 文件 | 职责 |
|---|---|---|
| `credentials.go` | 凭证结构 `storedAuth`（含 Extra 保留往返）、解析校验 |
| `dpop.go` | JWK 解析与配对校验、P-256 密钥生成、P1363 签名、DPoP 头构造 |
| `headers.go` | 客户端指纹头、签名头（指纹 + DPoP + attestation） |
| `attestation.go` | client_attestation 令牌缓存（提前刷新、失败退避、并发合并） |

网关端点（wire 层，按端点一文件）：

| 文件 | 职责 |
|---|---|---|
| `gateway_models.go` | `/v1/models` 端点与响应 wire 类型 |
| `profiles.go` | 每模型 thinking 契约缓存（由 `/models` 喂养，executor 读取） |
| `gateway_me.go` | `/v1/me` 端点与额度 wire 类型 |
| `gateway_device.go` | `/auth/device/start` / `poll` 端点 |
| `gateway_errors.go` | 上游错误解析与错误尾巴（HTTP 状态 · code · 请求编号） |
| `diagnostics.go` | 最近上游失败的环形缓存（请求编号留痕，管理路由读取） |
| `checkin.go` | 每日打卡：网页 Cookie sidecar 存取、`/api/me` 去重、claim 提交、北京时间调度器、管理路由 |

能力实现：

| 文件 | 职责 |
|---|---|---|
| `auth.go` | 登录会话、poll 状态机、`auth.parse`、refresh、AuthData 与 metadata 构造 |
| `models.go` | 模型表映射为 ModelInfo（含价格/免费包说明）、attestation 回写 |
| `thinking.go` | 模型后缀拆解、等级映射、按 request_format 写上游推理字段 |
| `executor.go` | 请求体归一化、非流式/流式执行、SSE 扫描与 framing、token 估算 |
| `upstream.go` | 宿主 HTTP 桥接（buffered + streaming）、stream emit/close、日志脱敏 |
| `management.go` | 管理路由、额度快照缓存（双锁）、用量包标签 |
| `host_auth.go` | `host.auth.list` / `host.auth.get` 封装 |

面板与工具：

| 文件 | 职责 |
|---|---|---|
| `panel.go` | 面板 HTML 嵌入与 base path 注入 |
| `panel.html` | 365 | 额度面板（内嵌，不加载任何第三方脚本） |
| `util.go` | UUID / 随机 hex |

---

## 3. 构建与部署

### 构建

构建命令见 README「构建」。本文件只补充工具链细节：

工具链：Go 1.27.0。产物 7.9MB，最高 glibc 符号需求 `GLIBC_2.34`。

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

### 插件替换需重启容器（除非用带版本号的文件名）

CPA 宿主只在**插件文件路径变化**时重建插件：覆盖同一个 `u1s1.so` + `touch config.yaml`
不会触发重载（宿主仍持有旧库 inode）。因此覆盖式替换后必须重启容器：

```bash
cp dist/u1s1.so <cpa>/plugins/linux/amd64/u1s1.so && docker restart cli-proxy-api
```

重启后核对日志（模型重新注册 `Registered new model u1s1/...`、宿主调 `auth.refresh`）确认
新版本已加载。

宿主自 v7.2.147 支持不重启热替换，前提是**换文件名**：写成 `u1s1-v<版本>.so`
（`pluginFileFromPath` 按 `-v` 拆版本号），放进同一目录后触发一次配置重载；路径变化后
`ApplyConfig` 走替换分支（先 `plugin.quiesce` 旧库——本插件没实现，宿主当不支持放过——
加载新库注册成功才把旧库挪进 `retired`，失败回滚）。两个坑：**旧文件会被删**——进程首次
`ApplyConfig` 会把同 id 未选中的 `.so` 直接 `os.Remove`，目录里一旦有了 `u1s1-v*.so`，下次
重启会删掉无版本号的 `u1s1.so`；**旧库不会被卸载**——`dlclose` 只在 `UnloadPlugin` /
`ShutdownAll` 做，热替换后旧库仍映射在进程里直到下次重启。

这条路径本插件尚未实测，当前部署仍是无版本号的 `u1s1.so` + 重启。

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

**刷新反馈**：`刷新` 按钮在飞行中改文案并禁用，状态行（`aria-live="polite"`）先显示
"正在读取 /v1/me…"、完成后换成快照时间。额度变化慢且网关计数有延迟，一次成功的强制
刷新经常前后一模一样，没有这层反馈就无法判断按钮到底有没有生效。`load()` 另带重入锁：
禁用按钮盖不住密钥表单的 Enter 和首屏加载。

**不展示网关公告**：`/v1/models` 带回的 `announcement`（维护窗口、政策变更）曾在页首
渲染过一版，现已整条链路移除：面板是这份缓存唯一的消费方，留缓存就是留一堆没人读的
状态。附带好处是采集额度不再搭一次 `/v1/models`（原来的 `refreshAnnouncementIfStale`
要拉一次模型表才能刷新公告）。维护公告仍可以从官方 CLI 或官网看到。

**也不展示充值与邀请入口**：CLI 的 `usageCtaLines()` 在 `u1s1 usage` 尾部接了充值锚点和
邀请加量两条行动项。那是付费用户自己跑的客户端，说得通；面板是 CPA 管理台里的额度
读数页，不是发这种提醒的地方。回归测试直接钉住了“面板不得出现 `usage-topup-card`”。
保留的唯一官网外链是 `free_claim` 角标，因为领取确实只能在浏览器里完成。

**免费包待领取**：`/v1/me` 的 `free_claim` 为 `"first"`（首月包）或 `"renew"`（年度包）
时，账号行上出现指向官网 dashboard 的角标。只能跳转不能代领：领取接口在 `u1s1.io`
（非网关）且要浏览器会话 Cookie 加两道人机验证，同 §9 的签到结论。

JSON 路由（需管理密钥）：`GET /v0/management/plugins/u1s1/usage`、
`POST /v0/management/plugins/u1s1/refresh` 与
`GET /v0/management/plugins/u1s1/diagnostics`（用途、参数见 README「额度面板」）。

**请求编号留痕**（`diagnostics.go`）：网关给每个失败请求铸一个 `request_id`，客服凭它直查
日志。它原本只出现在 `errorTail()` 拼出的错误文本里，也就是只存在于当时盯着屏幕的那
个人的刷屏里；等到要报障时已经找不回来。现在 `gatewayMessage()`（所有非 2xx 响应的唯一
共经之路）顺手把每次失败记进一个长 10 的环，面板工具栏的「最近错误」按钮列出来。

三个刻意的选择：只在内存（这是排查辅助，不是审计日志，重启清空）；存之前就过
`redactSecrets()`（这份数据会走 HTTP 吐出去，不能只在日志那一侧脱敏）；`code` 按
`errorTail()` 同一套规则归一（`quota_exceeded` → `insufficient_quota`），否则面板与
客户端看到的不是同一个词。

错误语义：`/v1/me` 逐凭证读失败时，对应账号在 `accounts` 里带 `error` 字段（面板显示"读取失败"）；
而 `host.auth.list` 枚举本身失败时，若有旧快照则继续返回旧快照（不污染缓存、不刷新时间戳），
没有任何可用快照时返回 502 + `{"error": ...}`，避免把"暂时读不到"伪装成"没有凭证"。

锁的划分：`usageCacheMu` 只护快照本身，`usageCollectMu` 只负责把并发采集合并成一次。
两者分开是因为采集是 N 个 `/me` 往返：若把缓存锁持有到采集结束，一个慢账号就能把所有
缓存命中和 `snapshotTime()` 一起阻住。

缓存新鲜度：普通加载接受 30 秒 TTL 内的快照；强制刷新（`POST /refresh` 或 `?refresh=1`）
不看 TTL，只接受采集时间晚于本次请求发起时刻的快照——即与本次调用真正重叠的采集，
并发刷新仍然合并成一趟 `/me`。这一条是为了修正面板刷新按钮无效的 bug（见 §8）。

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
当前离线测试：77 个测试函数、6 个子测试用例（`go test ./...` 全绿），按域覆盖：

- **DPoP/指纹**：证明可验签、私钥不出现在 JWK；公私钥不配对在解析期被拒；指纹头完整性与
  版本形状（缺一个即线上 403）
- **凭证**：`auth.parse` 只认领 u1s1 文件；metadata 含凭证全集（空 attestation 也显式写入）；
  未建模字段在解码→编码往返后保留；AuthUpdate 不重算 FileName；声明 `refresh_interval_seconds`
- **executor**：请求体归一化、SSE 扫描、流式中途上游断开必须报错而客户端断开静默；
  空流/4xx 错误路径；`count_tokens` 估算；不回放上游传输头
- **attestation**：未知 TTL 有界、并发刷新合并、刷新与读取共用缓存键
- **设备登录**：`interval` 钳制保留更慢的值；永久性 4xx 结束会话；`/models` 先于 `/me`
- **thinking**：后缀剥离、三种 request_format 字段形状、未声明等级回退、未知模型不猜字段
- **面板/管理**：路由精确匹配、HTML 无泄漏、刷新反馈与重入锁、强制刷新新鲜度与并发合并、
  枚举失败不污染快照缓存、`free_claim` 为 null 不报错
- **错误与诊断**：错误尾巴带请求编号且 `insufficient_quota` 归一、失败入环且有界/脱敏、
  diagnostics 路由已注册、日志脱敏长前缀优先
- **边界**：panic 不穿越 cgo、`snapshotTime()` 不被采集阻塞、模型说明与价格不四舍五入

---

## 8. 排查过的非显而易见问题

### 流式截断被静默吞掉

`pumpStream` 用 `if emitted == 0` 判断是否上报错误，分不清失败来源：**上游**读失败（网络断、
SSE 单行超 4MB）发生在已 emit 若干 chunk 之后时，函数直接返回，宿主补上自己的 `[DONE]`，
客户端看到一份截断却"正常结束"的回答。

修法：emit 失败单独记成 `emitBroken`，只有它为真才静默；逻辑抽到 `pumpStreamChunks()`
便于注入测试。回归：`TestPumpStreamReportsUpstreamFailureAfterChunks` /
`TestPumpStreamStaysSilentWhenClientDisconnects`。

### prefix 静默丢失

`AuthData.Metadata` 写 `"prefix": ""` 会覆盖宿主已存的 model prefix（宿主只补齐**缺失**键，
显式空值照抄），重启后 `u1s1/*` 全部消失。修法：prefix 非空才写入，空值交给宿主回填；
`email` 同理。另一半原因：宿主只对**原生解析**的凭证自动回填 `Prefix`，插件解析路径
必须在 `AuthData.Prefix` 回显。回归：`TestAuthDataOmitsEmptyOptionalMetadata`。

### 模型数量翻倍

宿主 `applyModelPrefixes()` 对设了 prefix 的凭证 `addModel` 两次（裸 id + 带前缀 id），
6 个模型注册出 12 条。开 `force-model-prefix: true` 跳过裸 id 分支。副作用：撞名的裸 id
在开关打开前同时挂着两个 provider，调度随机；u1s1 独有裸名上游返回 400，必须带前缀。

### 重新登录被旧凭证覆盖

与"prefix 静默丢失"同源但方向相反。`authDataFor()` 把 `ID`/`FileName` 算成 `u1s1-<email>`，
重登后宿主 `saveTokenRecord` 读出**同名旧文件**，`MergeExistingAuthMetadata` 把旧 map 所有键
补进新记录；`deviceToken`/`devicePrivateJwk`/`attestation` 不在宿主
`IsAuthTokenPayloadKey` 白名单（只有 `access_token` 一族），旧令牌直接盖掉新令牌，
重登后依旧 401 且凭证文件看似正常。

修法：`credentialMetadata()` 把整份凭证写进 metadata，`attestation`/`attestationExpiresAt`
显式写空值。回归：`TestAuthDataPublishesEveryCredentialKeyInMetadata` /
`TestAuthDataPublishesEmptyAttestationExplicitly`。两条规则不矛盾：`prefix`/`email` 靠
`omitempty` 保持**缺失**让宿主回填，凭证字段靠**存在**阻止宿主回填。

### auth.refresh 从来没被调用过

插件只设 `AuthData.NextRefreshAfter`，但那个字段只能**推迟**一次已被决定要做的刷新，
不会发起刷新。宿主 `shouldRefresh()` 判定链里第三方 provider 的 `ProviderRefreshLead`
返回 `nil`（`refreshLeadFactories` 只注册 codex/claude/antigravity/kimi/xai），凭证
根本不进自动刷新堆——这正好解释了为何上面两个写盘 bug 一直没被发现。

修法：metadata 与 attributes 都写 `refresh_interval_seconds: 43200`。回归：
`TestAuthDataRequestsRefreshInterval`，并断言该值小于
`attestationUnknownTTL - attestationRefreshMargin`（否则缺 `expires_in` 时刷新追不上过期）。

### 结构体往返吞掉用户字段

`storedAuth` 只建模 11 个字段，`auth.refresh`/`model.for_auth` 的
`parseStored()` → 改 attestation → `json.Marshal()` 往返会让其余键（`priority`、`note`、
`proxy_url`、`weight`、`excluded_models`、`disabled`、`request_retry`、`headers`）消失，
用户设置每次刷新掉一次。

修法：`storedAuth.Extra map[string]json.RawMessage` + 自定义
`MarshalJSON`/`UnmarshalJSON`，未建模键原样过渡，已建模字段优先；键集合由结构体 tag
反射得出，加字段不会漏改。回归：`TestStoredAuthPreservesUnknownKeys` /
`TestAuthRefreshPreservesUserFields`。

### thinking 后缀被原样发给上游

宿主 `rewriteModelForAuth` 只剥 `u1s1/` 前缀不剥后缀，`u1s1/deepseek-v4-flash(high)`
进入 executor 时 `req.Model` 仍带 `(high)`，旧 `resolveModel()` 原样塞进 `obj["model"]`，
上游 400。所有原生 executor 都走 `thinking.ParseSuffix(req.Model).ModelName`，插件漏了
这一步，也没把 level 翻译成上游要的形状。修法见 §5「thinking 后缀」。

### panic 穿越 cgo 边界

插件原本没有任何 `recover()`：宿主 `defer recover()` 只护自己那一侧，`cliproxyPluginCall`
里的 panic 会带倒整个 CPA 进程而非被熔断；`pumpStream` goroutine 更糟（连 cgo 帧都没有）。

修法：`guardDispatchPanic()` 把 panic 转成脱敏后的 `plugin_panic` 信封；
`reportStreamPanic()` 把 pump goroutine 的 panic 转成流错误，`streamClose` 先 defer
后执行，客户端不会卡在被抛弃的流上。

### shutdown 的 SIGSEGV

`cliproxyPluginShutdown` 原遍历 `loginSessions` 做 `Delete`；宿主在自己 Go runtime 开始
拆解**之后**才调 shutdown 随即 `dlclose`，此时触碰任何 Go runtime 状态（含 `sync.Map`）
在 cgo 里 SIGSEGV（workbuddy 插件留空同因）。清理本身也没意义：进程都要退了。

修法：空实现 + 注释说明为何不能动。

### 刷新按钮点了没反应

`cachedUsage()` 拿到 `usageCollectMu` 后复查缓存时写死 `freshUsageSnapshot(false)`，
"TTL 内的快照就够"——首屏 `usage` 刚填满缓存，用户几秒后点刷新，30 秒内的强制刷新
一律被自己的旧快照满足（日志：GET `usage` 冷路径 ~1s，`refresh` 只花 67ms，根本没出网）。

修法：`freshUsageSnapshot(force, requestedAt)` 把"够新"判据换成**时间点**——强制调用只
接受采集时间晚于本次请求发起时刻的快照，既保住并发合并又不把要替换的快照还给它；
TTL 只对普通加载有意义。UI 侧：按钮飞行中改文案并禁用 + `aria-live` 播报 + `load()`
重入锁（额度变化慢，数字不变时必须有"按钮已生效"的反馈）。

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
- **`truncate()` 按字节切 UTF-8**：这个函数的输入全是网关的中文文本（错误信息），
  中文字符 3 字节，切到一半就把非法 UTF-8 写进了 JSON 响应和日志。现在回退到最近的
  rune 边界（`utf8.RuneStart`）。

---

## 8.1 跟进 u1s1-cli 1.4.1（历史）

对照 1.3.2 → 1.4.1 的 `dist/` 变更，与插件相关的四处已跟进：`client-version` → `1.4.1`
（其余指纹无变化：pi-coding-agent 0.84.4 / openai SDK 6.40.0 / node v22.23.2）；错误文本带
`(HTTP 429 · code · 请求编号 …)` 尾巴且 `insufficient_quota` 归一（`errorTail()`）；
`free_package_eligible` 纳入模型说明；面板向 `u1s1 usage` 新口径对齐（Token 为主、
`login_checkin_bonus` 标签、`free_claim` 角标）。未跟进项（`/help`、`deploy --help`、限流
原因透传等）都是 CLI 自己的 TUI 交互，与网关契约无关。

---

## 8.2 跟进 u1s1-cli 1.5.0

1.4.1 → 1.5.0 之间还发了 1.4.2 和 1.4.3，因此逐版对照的是四份 `dist/`（1.4.2 引入
`secret-env.js` 与原子落盘、1.4.3 引入 `stripEnvOverrides`、1.5.0 引入 telemetry /
feedback / nudges / prompt / request-trace 五个新模块）。

### 已跟进

**`client-version` → `1.5.0`**（本次唯一影响线上可用性的项）。其余指纹核实无变化：
pi-coding-agent 仍 0.84.4、openai SDK 仍 6.40.0、node 仍 v22.23.2。新增
`TestClientVersionLooksLikeARelease` 钉住形状（三段数字、SDK 的 x.y.z、node 的 vX.Y.Z），
让改常量成为一次有意的编辑。

**请求编号留痕**（`diagnostics.go` + 面板「最近错误」）。CLI 1.5.0 新增 `request-trace.js`
把最近报错 `request_id` 落盘供 `u1s1 feedback` 附上。插件没有 feedback 命令但有同一个
需求：编号是客服唯一的检索键。详见 §6。

**上游传输头不回放**（回归测试，无产品代码改动）。CLI 修的是本地签名代理把上游
`content-encoding` 原样 replay 到已解码 body，SDK 去解压纯 JSON，所有非流式错误变成
`<status> terminated`。插件不会犯这个错（`host.http.do` 回的是已解码 body，executor
自己构造响应头），但属于"现在恰好对"而非"被钉住"，因此补了
`TestExecutorDoesNotReplayUpstreamTransportHeaders`。用 `br` 而非 `gzip` 造场景：Go
transport 自动解 gzip 并摘头，用 gzip 测试是空转的。

### 明确不跟进

| 变更 | 不跟进理由 |
| --- | --- |
| `usageCtaLines()` 充值/邀请入口 | 面板是 CPA 管理台读数页，不是提醒页；回归钉住"不得出现 `usage-topup-card`" |
| `POST /v1/telemetry` | 围绕"一个 TUI 进程 = 一次会话"；插件无会话概念，且 CLI 自己给了 `U1S1_TELEMETRY=0` 开关 |
| `POST /v1/support/tickets` | 建工单是终端用户交互；工单需要的 `request_id` 已由 diagnostics 路由提供 |
| `GET /public/announcements/latest` | 公告链路上版已整体移除（§6），维护公告仍可从官方 CLI/官网看到 |
| `secret-env.js` 子进程密钥守卫 | 插件不 spawn 子进程、不把凭证放进环境变量，用完即弃 |
| `writePrivateFile` / `stripEnvOverrides` | CLI 对 `~/.u1s1/config.json` 的写盘行为；插件凭证由宿主落盘，无自己的写盘路径 |
| `install.sh` SHA256 校验 | 插件分发是 GitHub Release 的 `u1s1.so` + `u1s1.so.sha256`，校验已在那条链路里 |
| 项目信任透传 / 字面量密钥 / deploy/nudges / import 时机 / `PI_SKIP_VERSION_CHECK` | 都在 CLI 的 pi 宿主一侧，插件没有对应面 |

面板 JS 依旧不由 Go 单测执行，本次按 §8.1 的做法验证：`node --check` 过两个 script 块，
再把 `renderAccount` / `renderDiagnostics` 提到最小 DOM 桩上跑四种账号形态与三种
diagnostics 形态，确认不出 `undefined` / `NaN`，并断言上游文本经过转义。

---

## 8.3 跟进 u1s1-cli 1.8.1（2026-09-05）

1.5.0 → 1.8.1 中间跨了 1.6.0 / 1.7.0 / 1.7.1 / 1.8.0 / 1.8.1 五个版本，逐版对照了五份
`dist/`（模块清单 + `api.js` / `device-auth.js` / `usage.js` / `model.js` 的路由与头部）。

### 已跟进

**`client-version` → `1.8.1`**（唯一影响线上可用性的项）。其余指纹逐项核实无变化：
pi-coding-agent 仍 0.84.4、openai SDK 仍 6.40.0、node 仍 v22.23.2；`x-u1s1-platform`
（1.8.x 签名代理新增）插件早已在 `headers.go` 硬编码 `linux-x64`，与官方
`${process.platform}-${process.arch}` 在本机一致。无新增网关路由：`api.js` / `device-auth.js`
的端点在 1.5.0 与 1.8.1 之间完全一致（`/v1/models`、`/v1/me`、`/v1/endpoints`、
`/public/announcements/latest`、打卡 claim）。

### 明确不跟进

| 变更 | 不跟进理由 |
| --- | --- |
| `mcp/*`（client / command / config / extension / tools） | pi 宿主侧的 MCP 子命令与扩展加载，插件没有对应面 |
| `import/skills.js` | 历史会话导入新格式；插件凭证由宿主落盘，无导入路径 |
| `shortcut.js` | CLI 的快捷命令功能，纯终端交互 |
| `/v1/endpoints`（自定义模型端点） | dashboard 侧的用户配置，由 CLI 拉取后本地缓存；插件模型目录只认 `/v1/models`，不代理该路由 |

---

## 9. 每日打卡（已实现，2026-09-04）

网页版签到端点 `POST https://u1s1.io/api/packages/login-checkin/claim`（注意是
`u1s1.io` 不是 `api.u1s1.io`）用浏览器会话 Cookie 鉴权，设备 DPoP 凭证不通用
（返回 401）。之前未实现，卡在两个误判：

- **验证码无法绕过** —— 实际是 fail-open：仪表盘在 capcat / Turnstile 失败时
  照样提交 claim（`solveCap(false)` 与 Turnstile 探针失败都返回 `null`），服务端
  只记一条风控事件、不拦请求。所以请求体里两个 token 传 `null` 即可。
- **网关侧没有等价路由** —— 确实没有，但也不需要：直接打网站 API 就行。

现在的实现（`checkin.go`）：

- **Cookie 存哪**：凭证文件旁的 sidecar（`<凭证路径>.checkin`，0600 权限，
  写盘是 write+rename）。路径从 `host.auth.get` 返回的 `Path` 推导，因此随
auth-dir 卷持久化、跟着凭证走。Cookie 只在进程内读写，管理路由和日志只回显
`cookie_preview`（前 8 后 4 字符）。后缀刻意**不用 `.json`**——宿主扫描
auth-dir 的 `*.json` 会把 sidecar 当成第二份凭证（v0.2.4 的踩坑，见下）。
- **没有 Cookie 怎么办**：面板签到视图显示「需要登录」，提示用户用浏览器登录
u1s1.io 后把 Cookie 粘贴进来。保存时插件先调网站 `/api/me` 验证：401 = 会话已
失效，拒绝落盘。
- **调度**：独立 goroutine（`startCheckinScheduler`，register 时启动一次，宿主
  桥不可用或 `checkin-enabled: false` 时不启）。按北京时间（固定 UTC+8，无夏令
  时）`08:00` / `20:00`（`checkin-times` 可配）各跑一轮。启动时若当日首档已过则
  立即补一次——服务端按天去重（`claimed_today`），重复提交是无害的 no-op。
- **去重**：每轮先 `GET /api/me` 看 `login_checkin.claimed_today`，已打卡则记为
  `already` 不重复提交；未打卡才 POST claim。结果（ok / already / no_cookie /
  error）写回 sidecar，面板展示。
- **管理路由**：`checkin/status`（状态）、`checkin/cookie`（POST 设 / DELETE
  清）、`checkin/run`（手动立即打卡）。

为什么不自动登录网站：登录本身要人机验证（注册/登录链路里 capcat 是 `required`
的，`requireCapToken()` 失败会抛错），且会话 Cookie 绑定浏览器指纹和风控上下文，
服务端能识别异常的纯服务端登录。让用户自己登录一次、粘贴 Cookie 是唯一可靠的接
入方式——之后自动签到就不再需要浏览器了。

### 时区与计划时刻

北京时间无夏令时，直接 `time.FixedZone("Asia/Shanghai", 8*3600)`，不依赖系统
tzdata。`nextCheckinAfter` 返回严格晚于 now 的下一个 `HH:MM`；当天全过则取次日
首档。计划时刻解析失败时回退默认 `08:00,20:00`，避免配置笔误静默停签。
档位解析后升序排序：`nextCheckinAfter` 与启动补签都假设 `slots[0]` 是最早档，
不排序的 `20:00,08:00` 会永久漏掉早晨那档。

### 代码审查修复（v0.2.6）

发布前静态审查发现的九项，全部修复并补测试：

- **sidecar 并发（P1）**：读-改-写整体无锁，清 Cookie 与定时打卡交错时旧对象
  整体写回会把已清除的 Cookie 复活。现在每路径一把互斥锁（`checkinSidecarLocks`），
  所有写路径走 `updateCheckinSidecar(path, fn)`（锁内读→改→写），只读走
  `readCheckinSidecar`。打卡的 `LastRun` 写回同样走锁，且只改 `LastRun` 字段、
  不动 Cookie，所以清 Cookie 只能输给显式写 Cookie，不会被打卡写回复活。
- **档位排序（P2）**：见「时区与计划时刻」。
- **Cookie 归属（P2）**：保存时 `webMe` 返回的邮箱与凭证 `sa.Email` 都非空且
  不一致则拒绝落盘，避免多账号把 A 的会话粘到 B 上、打卡串号。
- **callbackID 透传（P2）**：手动「立即签到」的 `HostCallbackID` 一路透传到
  `webMe` / `claimLoginCheckin`，宿主调用链保持关联。
- **sidecar 排除（P2）**：`hostAuthList` 对名字含 `.checkin` 的文件无条件排除
  （先于 Provider/Type 判断），宿主即使给旧 `.checkin.json` 标了 Provider=u1s1
  也不会再冒出伪账号；旧文件在首次读取时自动改名迁移。
- **配置热更新（P3）**：调度循环每轮重读 `activeConfig()`，改 `checkin-times` /
  `web-origin` 下一轮即生效，不再等到重启。
- **Cookie 归一化（P3）**：粘贴 `Cookie: xxx` / 带引号时自动剥离后再验证。
- **预览按 rune（P3）**：`cookiePreview` 按 rune 切片，多字节 Cookie 不产生
  无效 UTF-8。
- **损坏自愈（P3）**：sidecar JSON 损坏时改名 `.corrupt` 备份并重置为空，
  面板可重新录入而不是永久写不进。

---

## 10. 依赖

```
github.com/router-for-me/CLIProxyAPI/v7 v7.2.147  # pluginapi / pluginabi 类型定义
gopkg.in/yaml.v3 v3.0.1                            # 解析 plugins.configs.u1s1
```

SDK 版本与运行时宿主（v7.2.147）对齐。插件与宿主之间走稳定 C ABI + JSON envelope，
SDK 只提供结构体定义，因此版本偏离本身不会破兼容（`ABIVersion` 仍为 1）；对齐的目的
是能读到宿主当前的契约声明（新方法名、新能力位、`SchemaVersion` 的含义）。

插件在 `plugin.register` 里回 `schema_version: 1`，而 v7.2.147 的宿主已经声明到 4。这是
有意保留的：2、3、4 分别引入请求生命周期回调、流式 chunk 不再携带 request body、
WebSocket 响应观察，三项能力本插件都不声明，升版只会把契约变得更严而不多任何收益。
`resp.SchemaVersion > pluginabi.SchemaVersion` 才是宿主拒载的条件，声明低版本安全。

---

## 11. 参考

- CPA 插件文档：https://help.router-for.me/plugin/development
