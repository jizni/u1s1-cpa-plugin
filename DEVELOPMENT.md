# u1s1 CPA 插件 — 开发文档

CLIProxyAPI (CPA) 插件，把 u1s1 网关（`https://api.u1s1.io/v1`）接成原生 provider。

- 目标宿主：CPA v7.2.147（Docker，`eceasy/cli-proxy-api:latest`），SDK 版本见 §10
- 本文件只记**非显而易见的坑**；用户向内容在 README，各文件职责见各文件头注释

---

## 1. 为什么需要插件而不是反向代理

u1s1 不接受普通 Bearer token。每个请求需要**四层**凭证同时成立，缺任何一层网关返回
`403 client_integrity_review`（响应里还带"继续使用非 u1s1 客户端将封禁账号"的警告）：

| # | 层 | 内容 | 来源 |
|---|---|---|---|
| 1 | 设备令牌 | `authorization: DPoP u1s1d-…` | 设备登录时下发 |
| 2 | 每请求签名 | `dpop:` JWT，ES256 签 `{jti, htm, htu, iat, ath}`；`ath` = base64url(sha256(deviceToken))；`htu` 去掉 query 和 fragment | 本地 P-256 私钥 |
| 3 | 完整性令牌 | `x-u1s1-attestation`，TTL 7 天 | `GET /v1/models` 响应的 `client_attestation` 字段 |
| 4 | 客户端指纹 | `user-agent: pi (...)`、`x-u1s1-client/version/platform`、全套 `x-stainless-*`（官方 CLI 内嵌 OpenAI SDK 指纹） | 固定值 |

关键实现坑：

- **签名格式**必须是 IEEE P1363 的裸 `r||s`（64 字节，WebCrypto `subtle.sign` 输出格式）。
  Go 的 `ecdsa.SignASN1` 输出 DER，会被网关直接拒绝。见 `dpop.go:signP1363()`。
- **指纹头是强制的**，不是装饰。只带合法 DPoP 证明的请求同样被 403 拦下。

逆向方法：两个 preload 钩子抓官方 CLI 真实流量——`dump-fetch.mjs`（包装
`globalThis.fetch`）与 `dump-dc.mjs`（订阅 `undici:request:*` diagnostics channel，抓 pi
agent 捆绑版 undici 的流量），配合 `probe-*.mjs` 逐层验证（只带 DPoP → 403；补
attestation → 仍 403；补齐指纹头 → 200）。

---

## 2. 架构

三层：入口层（cgo 边界 + 方法分发 + panic 屏障：`abi.go` / `dispatch.go` / `bridge.go`）、
能力实现层（auth / models / thinking / executor / upstream / management / host_auth）、
wire 层（按网关端点一文件：`gateway_models.go` / `gateway_me.go` / `gateway_device.go` /
`gateway_errors.go`，加凭证与安全原语 `credentials.go` / `dpop.go` / `headers.go` /
`attestation.go` / `diagnostics.go` / `checkin.go`）。每文件的职责在文件头注释，此处只记
跨层设计：

- **声明的能力**：auth_provider / model_provider / executor / management_api；
  `executor_model_scope: oauth`，输入输出均为 `chat-completions`。
- **出网路径**：所有上游请求走 `host.http.do` / `host.http.do_stream` 宿主桥接，因此继承
  CPA 的 `proxy-url`、传输策略和请求日志。桥接不可用时（单测）回落插件自己的
  `http.Client`；`host.stream.emit` 没有回落可言（异步流的 stream id 来自宿主），桥接
  缺失时它报错而不是静默丢 chunk。
- **错误隔离**：插件在宿主进程内过 cgo 运行，宿主的 `defer recover()` 护不到插件侧的
  panic，会直接带倒整个 CPA 进程。`guardDispatchPanic()` 把方法分发侧的 panic 转成
  `plugin_panic` 信封（宿主可据此熔断）；`reportStreamPanic()` 护住 `pumpStream` 的
  goroutine（那里连 cgo 帧都没有，转成流错误）。`cliproxyPluginShutdown` 是故意的空
  实现，原因见 §8。
- **状态**：全部包级可变状态集中在 `state.go`（每块标注读写者，为拆包留口子）。

---

## 3. 构建与部署

命令见 README「构建」「安装」「配置」。本文件只补工具链细节：

- 工具链：Go 1.27，产物 ~8MB，最高 glibc 符号需求 `GLIBC_2.34`。
- **glibc 门禁**：目标容器 Debian 12（glibc 2.36），目标常量统一在
  `scripts/glibc-check.sh`（`TARGET_GLIBC="2.36"`），Makefile 与 release.yml 都调它。
  比较是 `sort -V` 版本序（max ≤ 2.36 即通过）——更老更兼容的构建不误杀，等号白名单
  会拒掉这类合法产物。`make build` 自动跑；换构建机后单独
  `GLIBC_SO=<path> scripts/glibc-check.sh` 亦可。
- **发版**：`git tag vX.Y.Z && git push origin vX.Y.Z` → release.yml 在
  `node:22-bookworm` 容器（Debian 12 / glibc 2.36，与目标一致；同时提供 checkout /
  setup-go 等 JS action 需要的 Node）构建 + glibc 门禁 + 单测，产物 `u1s1.so` +
  `u1s1.so.sha256` 挂 GitHub Release。不依赖具体 runner 镜像（ubuntu-22.04 已进弃用
  窗口），容器内构建保证符号需求不超 2.36。
- **替换需重启容器**：宿主只在插件**文件路径变化**时重建插件，覆盖同名 `u1s1.so` +
  touch config.yaml 不会重载（宿主仍持旧库 inode）。替换后必须
  `docker restart cli-proxy-api`，重启后核对日志确认新版本已注册、模型重新注册。
- **热替换（未实测）**：宿主 v7.2.147 支持不重启换文件名 `u1s1-v<版本>.so`。两个坑：
  旧文件会被删（进程首次 `ApplyConfig` 把同 id 未选中的 `.so` 直接 `os.Remove`，目录里
  一旦有了 `u1s1-v*.so`，下次重启会删掉无版本号的 `u1s1.so`）；旧库不会被卸载
  （`dlclose` 只在 `UnloadPlugin` / `ShutdownAll` 做，热替换后旧库仍映射在进程里）。
  当前部署仍是无版本号文件名 + 重启。

---

## 4. 授权与凭证持久化

### 设备登录

命令行流程见 README「登录」。细节：

- 设备批准后的顺序是**先 `/models` 拿 attestation，再带着它调 `/me`**：`/models` 是唯一
  不需要 attestation 的路由，其余请求缺这一层就可能 403 client_integrity_review。
- 网关返回的 `interval` 钳到 `[2,30]` 秒且**保留更慢的值**——限流场景下网关要求 60s，
  钳成 30s 而不是重置为 2s。轮询遇到永久性 4xx（poll_secret 失效、设备被封；429 除外）
  直接结束会话报错，不一路 pending 到会话过期。

### 凭证文件

`auth-dir/u1s1-<email>.json`，字段与官方 CLI 的 `~/.u1s1/config.json` 同名，因此把现有
CLI 登录态直接复制进 auth-dir 也能被认领。`auth.parse` 的认领条件：JSON 里同时存在
`u1s1d-` 前缀的 `deviceToken` 和完整 P-256 密钥对；不满足返回 `Handled: false`，不抢别的
provider 的文件。公私钥不配对的在解析期就被拒（`parsePrivateJWK` 校验 `d·G == (x,y)`），
避免上线后拿到难以排查的 401。

文件名归属：`auth.parse` 回显发现时的文件名；`auth.refresh` / `model.for_auth` 的
`AuthUpdate` 把 `FileName` **留空**交给宿主回填。否则 `authDataFor()` 会按 email 重算出
`u1s1-<email>.json`，把手工改名或直接拷进来的 `config.json` 改名/复制成第二份凭证
（后果：模型重复注册、面板出现两行同一账号）。

### 写盘契约：metadata 必须是凭证的全集

`AuthData.Metadata` 不是展示字段，而是**写盘的权威来源**。宿主落盘前先把同名旧文件的
键全补进 Metadata（`saveTokenRecord` → `MergeExistingAuthMetadata`），再让 Metadata 覆盖
StorageJSON。宿主自带的 `IsAuthTokenPayloadKey` 白名单只认 `access_token` 一族，u1s1
一个都不沾——没写进 metadata 的凭证字段（`deviceToken` / `devicePrivateJwk` /
`attestation`）会被**已吊销的旧值**填回来：重新批准设备后新凭证静默丢弃、重登后依旧
401 且文件看似正常。

因此 `credentialMetadata()` 把整份凭证 dump 进 metadata，`attestation` /
`attestationExpiresAt` 即使为空也显式写入（空 attestation 必须重新拉取，不能继承为旧
设备签发的令牌）。反过来 `prefix` / `email` 依赖同一条规则的另一面：`omitempty` 让它们
为空时**不出现**，而"不出现"才是宿主允许回填的信号；写成显式空串会把宿主已知的值清掉。

### 结构体往返不能吃掉未建模字段

`storedAuth` 只建模 11 个字段，`auth.refresh` / `model.for_auth` 的"解码 → 改
attestation → 重新编码"会让其余键（`priority` / `note` / `proxy_url` / `weight` /
`excluded_models` / `disabled` / `request_retry` / `headers`）每 12 小时掉一次。
`storedAuth.Extra map[string]json.RawMessage` + 自定义 Marshal/Unmarshal 保留未建模键，
已建模字段始终优先；键集合由结构体 tag 反射得出，加字段不会漏改。

### attestation 生命周期

TTL 7 天，提前 24 小时刷新，失败后 30 秒冷却。令牌同时缓存在内存（按 authID，空则按
设备令牌，`attestationCacheKey()` 统一定义）和凭证文件（重启后第一次聊天免一次
`/models` 往返）。刷新分两段加锁：判定用 `entry.mu`（只覆盖内存读写），真正的
`/models` 往返在锁外、由 `entry.fetching` 串行化——并发请求合并成一次刷新，读到旧令牌
的请求不必排在一趟网络往返后面。网关没下发 `expires_in` 时按 `attestationUnknownTTL`
（48 小时）记**有界**过期（`attestationFreshUntil()`）；凭证文件里只有 `attestation`
没有 `attestationExpiresAt` 的旧数据（或手工拷进来的 CLI config）视为过期，首次使用即
换新，不赌剩余寿命。

### 让宿主真的调用 auth.refresh

光设 `AuthData.NextRefreshAfter` **不会**触发刷新——它只是给"已被别的规则要求刷新"的
凭证加时间闸门。宿主 `shouldRefresh()` 判定链末尾是 `ProviderRefreshLead(provider)`，
`refreshLeadFactories` 只注册了 codex/claude/antigravity/kimi/xai，第三方 provider 返回
`nil` → 凭证根本不进自动刷新堆。唯一对插件开放的入口是 metadata/attributes 里的
`refresh_interval_seconds`，因此 `credentialMetadata()` 写入 `43200`（12 小时）并镜像到
attributes；该值必须小于 `attestationUnknownTTL − attestationRefreshMargin`（48h − 24h），
否则缺 `expires_in` 时刷新追不上过期。

---

## 5. 模型目录

### 模型前缀

设前缀命令与 `force-model-prefix` 宿主级开关见 README「模型前缀」。要点：

- `auth.parse` 必须回显 `Prefix`，否则管理台设的前缀会在下次刷新时消失——宿主只对
  **原生解析**的凭证文件自动回填该字段（根源见 §8「prefix 静默丢失」）。
- 宿主的 `rewriteModelForAuth` 发往上游前剥**前缀**，但**不剥 thinking 后缀**——那步归
  插件自己（见下）。
- CPA 对设前缀的凭证默认注册**两份**（裸 id + 带前缀 id），6 个模型变 12 条；
  `force-model-prefix: true` 只保留带前缀形式，且只影响声明了 prefix 的凭证。

### 模型说明：免费包覆盖与价格

`/v1/models` 每条记录三个计费字段，插件拼成 `ModelInfo.Description`（宿主原样转给客户端）：

| 字段 | 含义 |
|---|---|
| `free_package_eligible` | 免费用量包是否覆盖该模型。老网关没有这个字段 |
| `price` | 当前单价（USD / 百万 token），`cache_read` 可为 null |
| `price_bands` | 峰/闲价两档 + `current` 指出此刻生效的那一档 |

拼出「免费用量包可抵扣 · $0.22/$0.66 每百万 token（峰/闲价 · 当前闲时价）」；倍数的基准
是 `daily_free_model`（`deepseek-v4-flash`，也是 CLI 默认模型），按 `(input + output) / 2`
混合价比较，与 CLI 的 `deriveModelNote` 同一算法；不足 2 倍只说"不走免费包"（四舍五入
出来的"1 倍"是噪音）。`free_package_eligible` 缺失时**不产生**覆盖结论——猜"覆盖"会白烧
余额，猜"不覆盖"让人不敢用免费模型。价格用 `strconv.FormatFloat(v, 'f', -1, 64)` 打印
保持三位小数（`glm-5.3-flash` 输入价正是 $0.075）。

`reasoning` 不再是 thinking 的前置条件：CLI 的 `apiModelToDef` 里
`reasoning: m.reasoning || thinking !== undefined`，网关下发 `thinking.levels` 即按推理
模型处理（`gatewayModel.hasThinking()`）。

### thinking 后缀

宿主只剥前缀，**后缀原样留在 `req.Model`** 里（`u1s1/deepseek-v4-flash(high)`），直接
转发会被网关 400 unknown model 拒掉。`thinking.go` 拆后缀，并按该模型的
`request_format` 写上游字段（与官方 pi 客户端 `openai-completions` 适配层一致）：

| request_format | 上游字段 |
|---|---|
| `deepseek` | `thinking: {type: enabled\|disabled}` + `reasoning_effort` |
| `qwen` | `enable_thinking: bool` + `reasoning_effort` |
| `openai`（及其他） | 仅 `reasoning_effort` |

等级名还要经 `level_map` 换成网关词汇（如 `off → none`）。边界：未声明等级 → 回退
`default_level`；`can_disable: false` 收到 `(off)` → 给最低等级而非拒绝；数字后缀
`(8192)` 意为开启思考、`(0)` 为关闭（u1s1 没有 budget 字段）；没缓存到 profile 的模型
只剥后缀、**不**凭空加推理字段（给未知模型猜字段正是 400 的来源）。profile 由
`fetchModels()` 缓存而不是只在 `model.for_auth` 里：聊天请求带后缀但没有模型表，而
`/models` 是每条凭证路径都会经过的路由。

---

## 6. 管理面板

入口 `/v0/resource/plugins/u1s1/panel`（管理台侧边栏「u1s1」）。内容：今日免费额度
（进度条）、余额（按量）、本月已用、包内剩余 Token、额度重置时间，以及**合并后的用量包
表格**（中文名、剩余/额度进度条、今日已用、适用范围、到期时间）。数字格式与
`u1s1 usage` 的 万/亿 表达一致；金额卡片 Token 为主、美元为副（按 `/v1/me` 下发的
`tokens_per_usd` 折算，老网关无此字段时退纯美元显示）。

**余额口径对齐官网 dashboard**：CLI 1.8.1 起不再把网关 `remaining_usd` 当"永久余额"
（那是全部包剩余 Token 的美元折算，与用量包列表重复计数）；面板"余额(按量)"取
`bonus_balance_usd`（充值/赠送的现金余额），`remaining_usd` 保留在 JSON 里但不再渲染。
网关 `/v1/me` 没有官网 `/api/me` 的 `total_usd` 累计口径，不显示累计消费（硬造恒 0 的
数字比不显示更误导）。

**用量包合并对齐 dashboard 的 `mergePkgs`**（app.js）：按 `kind|scope|是否日额度|
admin_grant 备注` 分组（`groupPackagesForPanel`，服务端聚合），`count` 记合并数、
`expiry_dates` 保留全部不同到期日、`has_never_expiring` 标记永不过期成员。登录打卡每天
铸一个新包（实测账号 8 个 2M 包），不合并会刷屏；合并后一行显示 `×8`、16M 汇总剩余、
"最早 2026-09-27 到期 · 分批到期"。admin_grant 的备注是面向用户的文案，备注不同不合并，
并在行下整行展示。

**刷新反馈**：按钮飞行中改文案并禁用 + `aria-live` 状态行 + `load()` 重入锁——额度变化
慢、网关计数有延迟，一次成功的强制刷新经常前后一模一样，没有这层反馈无法判断按钮是否
生效。

**不展示公告/充值入口**：`/v1/models` 的 `announcement` 已整条链路移除（面板是这份缓存
唯一的消费方，留缓存就是留没人读的状态；附带好处是采集额度不再搭一次 `/models`）。
CLI 的 `usageCtaLines()` 充值/邀请入口是付费客户端自己的提醒，面板是管理台读数页；
回归钉住"不得出现 `usage-topup-card`"。保留的唯一官网外链是 `free_claim` 角标——领取
只能在浏览器完成（会话 Cookie + 两道人机验证），插件无法代劳。

**请求编号留痕**（`diagnostics.go`）：网关给每个失败请求铸一个 `request_id`，客服凭它
直查日志；它原本只存在于那次失败响应的错误文本里，要报障时已找不回来。
`gatewayMessage()`（所有非 2xx 响应的唯一共经之路）把每次失败记进长 10 的环，面板
「最近错误」列出。三个刻意选择：只在内存（排查辅助不是审计日志）、存前过
`redactSecrets()`（会走 HTTP 吐出）、`code` 按 `errorTail()` 同规则归一
（`quota_exceeded` → `insufficient_quota`）。

**缓存与锁**：`usageCacheMu` 只护快照，`usageCollectMu` 只把并发采集合并成一次——两者
分开是因为采集是 N 个 `/me` 往返，若把缓存锁持有到采集结束，一个慢账号会阻住全部缓存
命中和 `snapshotTime()`。普通加载接受 30 秒 TTL 内快照；强制刷新不看 TTL，只接受采集
时间晚于本次请求发起时刻的快照（与本次调用真正重叠的采集），并发刷新仍合并成一趟。
`/v1/me` 逐凭证读失败 → 对应账号带 `error` 字段；`host.auth.list` 枚举本身失败 → 有旧
快照则继续返回旧快照（不污染缓存、不刷新时间戳），否则 502，避免把"暂时读不到"伪装成
"没有凭证"。

**安全边界**：资源页按宿主契约不做管理鉴权，HTML 不含任何额度/凭证数据；数据由页面带
管理密钥（URL `?key=` → sessionStorage → 内嵌时同源 localStorage）调认证路由；凭证 JSON
只在进程内经 `host.auth.list` / `host.auth.get` 读取；所有日志与错误信息过
`redactSecrets()`。主题：无自带设置，首屏读取父窗口 `data-theme` 并 `MutationObserver`
跟随，独立打开时回落系统 `prefers-color-scheme`，CSS 变量沿用管理台 token。

---

## 7. 测试

命令见 README「测试」。离线单测 93 个函数全绿（`go test ./...` + `-race` + `vet`）；联测
`U1S1_LIVE_TEST=1 go test -run TestLiveGatewayRoundTrip -v`（读 `~/.u1s1/config.json`，
覆盖 /models、/me、两条 chat 路径，会消耗额度）。按域覆盖：

- DPoP/指纹（可验签、私钥不出 JWK、版本形状）、凭证（metadata 全集、未建模字段往返、
  FileName 回填、refresh_interval）、executor（归一化、SSE framing、流断错误路径、
  token 估算、不回放上游传输头）、attestation（未知 TTL 有界、并发合并）、thinking
  （后缀/三种字段形状/回退）、面板与路由（全路由表、安全契约、强制刷新新鲜度、枚举失败
  不污染）、错误与诊断（请求编号留痕、脱敏）、边界（panic 不穿 cgo、模型价格不四舍五入）。

面板 JS 不由 Go 单测执行：提取两个 script 块 `node --check`，再把 `renderAccount` /
`renderDiagnostics` 挂到最小 DOM 桩上跑真实数据形态，断言不出 `undefined` / `NaN`、上游
文本经过转义（与 §8「跟进 u1s1-cli 发布」同一套做法，脚本见 git 历史）。

---

## 8. 排查过的非显而易见问题

每条：症状一句话 → 修法一句话 → 回归测试名。细节见 §4/§5/§6 对应小节。

| 问题 | 症状 → 修法 | 回归测试 |
|---|---|---|
| 流式截断被静默吞掉 | 上游读失败（断网、SSE 单行超 4MB）发生在已 emit 若干 chunk 之后 → 宿主补 `[DONE]`，回答截断却"正常结束"。emit 失败单独记 `emitBroken`，只有它为真才静默；逻辑抽到 `pumpStreamChunks()` | TestPumpStreamReportsUpstreamFailureAfterChunks / TestPumpStreamStaysSilentWhenClientDisconnects |
| prefix 静默丢失 | Metadata 写 `"prefix": ""` 覆盖宿主已存前缀（宿主只补**缺失**键）→ 重启后 `u1s1/*` 全消失。非空才写、空值交宿主回填；原生解析路径必须回显 `AuthData.Prefix` | TestAuthDataOmitsEmptyOptionalMetadata |
| 模型数量翻倍 | 宿主 `applyModelPrefixes()` 对设前缀凭证 `addModel` 两次 → 开 `force-model-prefix: true` 跳过裸 id 分支。副作用：撞名裸 id 同时挂两个 provider、调度随机 | TestRegisterDeclaresCapabilities |
| 重新登录被旧凭证覆盖 | `MergeExistingAuthMetadata` 把旧文件所有键补进新记录，而 `deviceToken`/私钥/`attestation` 不在宿主 `IsAuthTokenPayloadKey` 白名单 → 重登后旧令牌盖新令牌、依旧 401。`credentialMetadata()` 整份凭证写进 metadata，attestation 显式写空 | TestAuthDataPublishesEveryCredentialKeyInMetadata / TestAuthDataPublishesEmptyAttestationExplicitly |
| auth.refresh 从没被调用 | 只设 `NextRefreshAfter` 不会发起刷新；宿主 `ProviderRefreshLead` 只注册 codex/claude/antigravity/kimi/xai，第三方返回 nil → 凭证不进自动刷新堆。metadata+attributes 写 `refresh_interval_seconds: 43200` | TestAuthDataRequestsRefreshInterval |
| 结构体往返吞用户字段 | `storedAuth` 只建模 11 字段，refresh 往返后 `priority`/`note`/`proxy_url` 等消失。`Extra` 保留未建模键，键集合由 tag 反射 | TestStoredAuthPreservesUnknownKeys / TestAuthRefreshPreservesUserFields |
| thinking 后缀被原样发上游 | 宿主只剥前缀，`req.Model` 带 `(high)` 直接塞 `obj["model"]` → 400。`thinking.ParseSuffix` + 按 `request_format` 翻译，见 §5 | TestPrepareBody*（executor_test.go） |
| panic 穿越 cgo | 宿主 recover 护不到插件侧，panic 带倒整个 CPA；pump goroutine 连 cgo 帧都没有。`guardDispatchPanic()` → `plugin_panic` 信封；`reportStreamPanic()` → 流错误 | TestDispatchPanicBecomesEnvelope / TestStreamPanicIsReportedNotFatal |
| shutdown 的 SIGSEGV | 宿主在自己 Go runtime 开始拆解**之后**才调 shutdown 随即 dlclose，此时触碰任何 Go runtime 状态（含 `sync.Map`）即 SIGSEGV（workbuddy 留空同因）；清理也没意义。空实现 + 注释 | —（注释说明） |
| 刷新按钮点了没反应 | 复查缓存时写死 `freshUsageSnapshot(false)`，首屏刚填缓存 → 30s 内强制刷新被自己的旧快照满足（日志：refresh 只花 67ms 根本没出网）。`freshUsageSnapshot(force, requestedAt)` 按**时间点**判定，TTL 只对普通加载有意义 | TestForcedRefreshRejectsSnapshotOlderThanTheRequest / TestForcedRefreshReusesOverlappingCollection |
| attestation 刷新串行化 | `entry.mu` 原跨整个 `/models` 往返持有，同凭证并发聊天全排队。判定与刷新分开，`entry.fetching` 只合并刷新 | TestAttestationRefreshCollapsesConcurrentCallers |
| usage 缓存锁 | `usageCacheMu` 原跨 N 个 `/me` 往返持有，一个慢账号阻住面板和 `snapshotTime()`。拆 `usageCacheMu`（护快照）+ `usageCollectMu`（串行化采集） | TestUsageCacheLockNotHeldDuringCollection |
| `streamEmit` 静默失败 | 无宿主桥接时丢 chunk → 改为报错 | TestCollectStreamSurfacesUpstreamStatus |
| `count_tokens` 恒返 0 | 宿主当真值写用量日志、客户端拿它做上下文预算 → 本地估算（CJK 按字、拉丁按字节，含每消息开销），同时输出 `usage` 字段 | TestCountTokensEstimatesPrompt |
| `truncate()` 按字节切 UTF-8 | 输入全是网关中文错误文本（3 字节/字），切到一半写非法 UTF-8 进 JSON 和日志 → 回退最近 rune 边界（`utf8.RuneStart`） | TestRedactSecrets |

### 跟进 u1s1-cli 发布（活规则）

**唯一影响线上可用性的活规则：`client-version` 必须随真实 CLI 发布版本升级**
（`config.go:defaultClientVersion` + README 配置表）——网关完整性检查会提示"升级并重新
登录 u1s1"。`TestClientVersionLooksLikeARelease` 钉住形状（三段数字 / SDK x.y.z / node
vX.Y.Z），让改常量成为有意的编辑。历次跟进（1.4.1 / 1.5.0 / 1.8.1 逐版对照的全文）在 git
历史，此处只留汇总：

| 已跟进 | 说明 |
|---|---|
| `client-version` → 1.4.1 / 1.5.0 / 1.8.1 | 每次唯一影响可用性的项；其余指纹核实无变化：pi-coding-agent 0.84.4、openai SDK 6.40.0、node v22.23.2 |
| 错误文本 `(HTTP 429 · code · 请求编号 …)` + `insufficient_quota` 归一 | `errorTail()` |
| `free_package_eligible` 纳入模型说明 | §5 |
| 面板向 `u1s1 usage` 新口径对齐（Token 为主、`login_checkin_bonus` 标签、`free_claim` 角标） | §6 |
| 请求编号留痕 | 1.5.0 引入 `request-trace.js` 后插件补 `diagnostics.go`，§6 |
| 上游传输头不回放 | 1.5.0 签名代理 bug 的对照：补 TestExecutorDoesNotReplayUpstreamTransportHeaders；用 `br` 而非 `gzip` 造场景——Go transport 自动解 gzip 并摘头，用 gzip 测试是空转 |
| `x-u1s1-platform` | 1.8.x 签名代理新增，插件早已在 `headers.go` 硬编码 `linux-x64`（本机与官方 `${process.platform}-${process.arch}` 一致） |

| 明确不跟进 | 理由 |
|---|---|
| `usageCtaLines()` 充值/邀请入口 | 面板是管理台读数页；回归钉住无 `usage-topup-card` |
| `POST /v1/telemetry` / `/v1/support/tickets` | 围绕 TUI 会话/终端用户交互；工单要的 `request_id` 已由 diagnostics 提供 |
| `GET /public/announcements/latest` | 公告链路已整体移除（§6） |
| `secret-env.js` / `writePrivateFile` / `stripEnvOverrides` / `install.sh` 校验 | CLI 的凭证写盘/安装行为；插件凭证由宿主落盘，分发校验已在 Release 链路 |
| `mcp/*`、`import/skills.js`、`shortcut.js`、deploy/nudges、`/v1/endpoints` | 都在 CLI/pi 宿主一侧，插件没有对应面；`/v1/endpoints` 是 dashboard 用户配置，模型目录只认 `/v1/models` |

---

## 9. 每日打卡（2026-09-04）

端点 `POST https://u1s1.io/api/packages/login-checkin/claim`（注意是 **u1s1.io** 不是
api.u1s1.io）用浏览器会话 Cookie 鉴权，设备 DPoP 凭证不通用（返回 401）。卡过的两个
误判：

- **验证码无法绕过** —— 实际是 fail-open：仪表盘在 capcat / Turnstile 失败时照样提交
  claim（`solveCap(false)` 与探针失败都返回 `null`），服务端只记风控事件不拦请求，所以
  请求体里两个 token 传 `null` 即可。
- **网关侧没有等价路由** —— 确实没有，但也不需要：直接打网站 API。

实现（`checkin.go`）：

- **Cookie 存哪**：凭证旁的 sidecar `<凭证路径>.checkin`（0600，写盘 write+rename），路径
  从 `host.auth.get` 返回的 `Path` 推导，随 auth-dir 卷持久化、跟着凭证走。后缀刻意
  **不用 `.json`**——宿主扫描 auth-dir 的 `*.json` 会把 sidecar 当第二份凭证（v0.2.4 踩
  坑）。Cookie 只在进程内读写，管理路由和日志只回显 `cookie_preview`（前 8 后 4 字符）。
- **保存校验**：先调网站 `/api/me`——401 = 会话失效拒绝落盘；返回邮箱与凭证 `sa.Email`
  都非空且不一致也拒绝（防多账号把 A 的会话粘到 B 上、打卡串号）。
- **调度**：独立 goroutine（register 时启动，宿主桥不可用或 `checkin-enabled: false` 不
  启）。北京时间（固定 UTC+8，无夏令时）08:00 / 20:00（`checkin-times` 可配）各一轮；
  启动时当日首档已过立即补一次——服务端按天去重（`claimed_today`），重复提交是无害
  no-op。每轮先 `GET /api/me` 看 `claimed_today`，已打卡记为 `already` 不重复提交。
  `nextCheckinAfter` 返回严格晚于 now 的下一时刻；档位解析后升序排序——不排序的
  `20:00,08:00` 会永久漏掉早晨那档。调度循环每轮重读 `activeConfig()`，改配置下一轮即
  生效。
- **管理路由**：checkin/status（状态）、checkin/cookie（POST 设 / DELETE 清）、
  checkin/run（手动立即打卡，`HostCallbackID` 一路透传到 `/api/me` 与 claim）。
- **为什么不能自动登录**：登录链路 capcat 是 `required`（`requireCapToken()` 失败会抛错），
  且会话 Cookie 绑定浏览器指纹与风控上下文，纯服务端登录会被识别；用户登录一次粘贴
  Cookie 是唯一可靠接入方式，之后自动签到不再需要浏览器。

v0.2.6 静态审查九项修复（全部有回归测试）：**sidecar 并发（P1）** 读-改-写无锁会复活
已清除的 Cookie → 每路径互斥锁，写路径全走 `updateCheckinSidecar(path, fn)` 锁内读改写，
打卡 `LastRun` 写回只改自身字段不动 Cookie；**档位排序（P2）**；**Cookie 归属（P2）**；
**callbackID 透传（P2）**；**sidecar 排除（P2）** `hostAuthList` 对名字含 `.checkin` 的
无条件排除，旧 `.checkin.json` 首读自动改名迁移；**配置热更新（P3）**；**Cookie 归一化
（P3）** 剥离 `Cookie:` 前缀与引号；**预览按 rune（P3）**；**损坏自愈（P3）** JSON 损坏
改名 `.corrupt` 备份并重置。

---

## 10. 依赖

```
github.com/router-for-me/CLIProxyAPI/v7 v7.2.147  # pluginapi / pluginabi 类型定义
gopkg.in/yaml.v3 v3.0.1                            # 解析 plugins.configs.u1s1
```

SDK 版本与运行时宿主（v7.2.147）对齐。插件与宿主走稳定 C ABI + JSON envelope，SDK 只
提供结构体定义，版本偏离本身不破兼容（ABIVersion 仍 1）；对齐的目的是能读到宿主当前的
契约声明（新方法名、能力位、SchemaVersion）。

插件回 `schema_version: 1`，而宿主已声明到 4——有意保留：2/3/4 分别引入请求生命周期
回调、流式 chunk 不再携带 request body、WebSocket 响应观察，三项都不声明，升版只会把
契约变严而不多任何收益；`resp.SchemaVersion > pluginabi.SchemaVersion` 才是宿主拒载的
条件，声明低版本安全。

---

## 11. 参考

- CPA 插件文档：https://help.router-for.me/plugin/development
