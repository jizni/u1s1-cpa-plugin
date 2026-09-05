# u1s1 CPA 插件

[![CI](https://github.com/jizni/u1s1-cpa-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/jizni/u1s1-cpa-plugin/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一个 CLIProxyAPI（CPA）插件，把 [u1s1](https://u1s1.io) 网关（`https://api.u1s1.io/v1`）接成原生 provider。

- [为什么用插件而不是反向代理](#为什么用插件而不是反向代理)
- [功能](#功能)
- [构建](#构建)
- [安装](#安装)
- [配置](#配置)
- [登录](#登录)
- [模型前缀](#模型前缀)
- [思考强度](#思考强度)
- [额度面板](#额度面板)
- [测试](#测试)
- [进一步阅读](#进一步阅读)

## 为什么用插件而不是反向代理

u1s1 不接受普通 Bearer token。每个请求需要**四层**凭证同时成立，缺任何一层返回
`403 client_integrity_review`（响应里还带封号警告）：

1. `authorization: DPoP <deviceToken>` — `u1s1d-` 前缀的设备凭证。
2. `dpop: <JWT>` — 每请求一个 ES256 证明，覆盖 `{jti, htm, htu, iat, ath}`，用设备的
   P-256 私钥签名。签名必须是 IEEE P1363 裸 `r||s` 格式（WebCrypto 输出格式）；
   Go 默认的 DER 编码会被网关拒绝。
3. `x-u1s1-attestation` — 客户端完整性令牌，由 `GET /v1/models` 下发（有效期 7 天）。
4. 客户端指纹：`user-agent: pi (...)`、`x-u1s1-client/version/platform`，
   以及官方 CLI 内嵌 OpenAI SDK 的全套 `x-stainless-*` 请求头。

只带合法 DPoP 证明也会被拦下 —— 指纹头是强制的，不是装饰。四层缺一不可。

## 功能

| 能力 | 方法 | 说明 |
| --- | --- | --- |
| `auth_provider` | `auth.login.start`、`auth.login.poll`、`auth.parse`、`auth.refresh` | 浏览器设备登录；宿主负责把凭证持久化到 `auth-dir`。 |
| `model_provider` | `model.for_auth` | 实时目录来自 `GET /v1/models`，缓存 5 分钟；每个模型带一行说明（免费包覆盖、相对默认模型的价格倍数、当前单价与峰/闲时段）。 |
| `executor` | `executor.execute`、`executor.execute_stream`、`executor.count_tokens` | chat-completions 进出，流式经 `host.stream.emit`，本地估算 token 数。 |
| `management_api` | `management.register`、`management.handle` | 额度面板加 JSON 路由（见下），含每日登录打卡的 Cookie 管理与手动签到。 |

所有出站 HTTP 都走 `host.http.do` / `host.http.do_stream`，因此宿主的 `proxy-url`、
传输策略和请求日志全部生效。上游报错原样转达，并在末尾附上
`(HTTP 429 · insufficient_quota · 请求编号 …)`。

与宿主的调用交互细节（cgo ABI、panic 屏障）见 DEVELOPMENT.md §2；各文件职责见各文件头注释。

## 构建

```bash
make build          # 产物在 dist/u1s1.so
```

等价于（不带版本注入时插件版本号为 `dev`）：

```bash
CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -ldflags "-s -w" -o dist/u1s1.so .
```

`make build` 会顺带校验产物对 glibc 的需求（`make glibc-check`）。

## 版本与发布

插件版本号在构建时注入（`-ldflags "-X main.pluginVersion=$VERSION"`），`make build`
默认取最近的 git tag（`git describe --tags --always --dirty`）。发版流程：

```bash
git tag v0.2.0 && git push origin v0.2.0
```

GitHub Actions 的 [Release](.github/workflows/release.yml) 流水线会构建 `u1s1.so`、校验
glibc 兼容性（≤ 2.36）、跑单测，然后把 `u1s1.so` 和 `u1s1.so.sha256` 挂到 Release 资产上。

注意：构建机的 glibc 不能比 CPA 容器的新（官方镜像为 Debian 12 / glibc 2.36；目标常量统一
在 `scripts/glibc-check.sh`，比较是 `sort -V` 版本序：只要 ≤ 2.36 就通过，更老更兼容的构建
不会误杀）。`make build` 已自动跑 `make glibc-check`；换构建机后也可单独
`GLIBC_SO=<path> scripts/glibc-check.sh` 确认。

## 安装

```bash
cp dist/u1s1.so <cpa>/plugins/linux/amd64/u1s1.so
docker restart cli-proxy-api   # 插件替换后必须重启容器才能生效，见 DEVELOPMENT.md §3
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

## 配置

| 键 | 默认值 | 用途 |
| --- | --- | --- |
| `base-url` | `https://api.u1s1.io/v1` | 网关基础 URL（鉴权路由挂在 origin 根路径下）。 |
| `client` | `terminal` | `x-u1s1-client` 的值。 |
| `client-version` | `1.8.1` | `x-u1s1-version` 的值;需与真实 CLI 发布版本保持一致。 |
| `user-agent` | `pi (linux ...; x64)` | 必须保持 `pi (...)` 指纹。 |
| `web-origin` | `https://u1s1.io` | 网站 origin：`/api/me`、打卡领取接口所在（与网关 `api.u1s1.io` 不同宿主，用会话 Cookie 鉴权）。 |
| `checkin-enabled` | `true` | 是否运行每日打卡调度器。 |
| `checkin-times` | `08:00,20:00` | 打卡的北京时间时刻，逗号分隔（`HH:MM`）。 |

同名环境变量也生效：`U1S1_BASE_URL`、`U1S1_CLIENT`、`U1S1_CLIENT_VERSION`、
`U1S1_USER_AGENT`、`U1S1_WEB_ORIGIN`、`U1S1_CHECKIN_ENABLED`、`U1S1_CHECKIN_TIMES`。

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

凭证声明了 `refresh_interval_seconds: 43200`，宿主每 12 小时调一次 `auth.refresh`
（这是第三方 provider 能被自动刷新的唯一入口，详见 DEVELOPMENT.md §4）。

## 模型前缀

u1s1 的模型 id（`deepseek-v4-flash`、`glm-5.3-flash` 等）会与其他 provider 冲突。
设置前缀让两边都能访问：

```bash
curl -X PATCH -H "Authorization: Bearer $MGMT_KEY" -H "Content-Type: application/json" \
  -d '{"name":"u1s1-<email>.json","prefix":"u1s1"}' \
  http://127.0.0.1:8317/v0/management/auth-files/fields
```

之后模型会注册为 `u1s1/deepseek-v4-flash` 等。CPA 默认会**同时**注册裸 id 和带前缀的
id（模型数量翻倍），只保留带前缀的形式需设置宿主级开关：

```yaml
force-model-prefix: true
```

它只影响声明了前缀的凭证，其他 provider 不受影响。前缀为何必须由插件在 `auth.parse`
里回显、翻倍的根源在哪，见 DEVELOPMENT.md §5。

## 思考强度

声明了 `thinking.levels` 的模型支持 CPA 的思考强度后缀：

```
u1s1/deepseek-v4-flash(high)
u1s1/glm-5.3-flash(max)
u1s1/qwen3.8-flash(off)
```

宿主只剥离鉴权前缀，所以插件自行把后缀从模型 id 上拆开，按该模型的
`request_format`（`deepseek`、`qwen` 或 `openai`）把强度翻译成对应的上游字段，并套用
网关自己的 `level_map`。模型不支持的强度回退到其 `default_level`；对 `can_disable:
false` 的模型，`(off)` 会落到最低强度而不是被拒绝。不带后缀的请求原样透传。
字段形状与各边界详见 DEVELOPMENT.md §5。

## 额度面板

管理控制台里会出现一个 `u1s1` 菜单项，指向：

```
/v0/resource/plugins/u1s1/panel
```

页面展示与 `u1s1 usage` 相同的数据：每日免费额度、余额（按量，取 `bonus_balance_usd`）、
本月开销，以及**合并后的用量包**。数额以 Token 为主、美元为辅（按网关下发的
`tokens_per_usd` 折算）。同种类的用量包按官网 dashboard 的规则合并成一行
（登录打卡每天会铸一个新包，不合并表格会涨到几十行）：显示 `×N` 合并数、汇总剩余，
到期列写“最早 X 到期 · 分批到期”（含永不过期额度时追加说明）；官方赠送包按备注分
组，不会因合并丢失面向用户的说明。有待领取的免费用量包时，账号行上出现指向官网
dashboard 的角标（领取需要浏览器会话和两道人机验证，插件无法代劳）。

工具栏的「最近错误」按钮列出最近 10 次上游失败的时间、HTTP 状态、错误代号和网关
请求编号。网关给每个失败请求都铸了一个 `request_id`，客服凭它直查日志；在此之前它
只存在于那一次失败响应的错误文本里（也就是客户端的刷屏里）。记录只在内存，重启清空。

「签到」按钮进入每日打卡视图：每个凭证一行，显示是否已设置网页会话 Cookie（只露
前后几位）、上次打卡结果，以及一个 Cookie 输入框。「保存」会用网站 `/api/me` 验证
Cookie 有效后落盘（存在凭证文件旁的 `<凭证名>.checkin.json`，随 auth-dir 卷持久化）；
「立即签到」手动触发一次。「自动签到在北京时间 08:00 / 20:00（可配）运行，无 Cookie
时跳过并在面板提示需要登录。

JSON 路由（需要管理密钥）：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/v0/management/plugins/u1s1/usage` | 所有 u1s1 凭证的额度；加 `?refresh=1` 跳过 30 秒缓存。 |
| POST | `/v0/management/plugins/u1s1/refresh` | 强制重新读取 `/v1/me`，忽略缓存。 |
| GET | `/v0/management/plugins/u1s1/diagnostics` | 最近 10 次上游失败的网关请求编号（报障用）。 |
| GET | `/v0/management/plugins/u1s1/checkin/status` | 各凭证打卡状态：Cookie 是否已设、上次结果、下次运行时刻。 |
| POST | `/v0/management/plugins/u1s1/checkin/cookie` | 校验并保存某凭证的网页会话 Cookie（body：`auth_index` + `cookie`）。 |
| DELETE | `/v0/management/plugins/u1s1/checkin/cookie` | 清除某凭证的打卡 Cookie（query：`auth_index`）。 |
| POST | `/v0/management/plugins/u1s1/checkin/run` | 立即打卡（query：`auth_index`，缺省=全部凭证）。 |

资源页面本身不做管理鉴权（宿主契约），所以 HTML 里**不带**任何额度或凭证数据。它从
`?key=`、`sessionStorage` 或控制台同源 `localStorage` 取管理密钥，再调用带鉴权的路由；
凭证 JSON 只在插件进程内通过 `host.auth.list` / `host.auth.get` 读取，永远不会到达
浏览器。面板的缓存与锁划分见 DEVELOPMENT.md §6。

## 测试

```bash
go test ./...                                    # 离线单元测试
go test -race ./...                              # 并发路径
U1S1_LIVE_TEST=1 go test -run TestLiveGateway -v # 真实网关联测，会消耗额度
```

联测读取 `~/.u1s1/config.json`，覆盖模型列表、`/me` 以及两条 chat 路径。

## 进一步阅读

设计细节、逆向过程、凭证写盘契约、排查过的非显而易见问题见
[DEVELOPMENT.md](DEVELOPMENT.md)。