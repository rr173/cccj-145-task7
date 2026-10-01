# wrelay — 并行窗口审计中继（parallel-window relay）

让同一审计租户**并行**处理多个相邻数据窗口，而不是等上一包确认后才发下一包。
中继把互不重叠的原序区间 `[start_offset, end_offset)` 租给不同 worker；靠后的
窗口先完成时**只登记完成事实**，对外可见的**连续提交屏障（commit barrier）**
必须等前面的空洞补齐后才一次推进连续前缀。零第三方依赖，仅用 Python 3.11 标准库。

## 核心语义

| 需求 | 实现 |
|---|---|
| 并行相邻窗口 | 每租户按固定 `window_size` 切窗；可同时持有至多 `max_inflight` 个**活动（未超时）**在途窗口，区间相邻且互不重叠 |
| 连续提交屏障 | 窗口乱序完成只写 `completed`；每次提交后从屏障起顺序吃掉 `completed` 窗口，一次推进到最长连续前缀末端；空洞补齐前屏障不动 |
| 窗口边界/字节稳定 | `window_id = afw_‖HMAC(secret, canon(tenant,seq,start,end))`；窗口首次物化即固化原始字节。超时重投/进程重启后重领返回**同一 window_id 与逐字节相同字节** |
| 栅栏令牌 fencing | 每窗口单调 `lease_epoch`；超时接管 `epoch+1`、`retry_count+1`，旧持有者迟到提交返回 `409 stale_lease` |
| 收缩不抢持有者 | `max_inflight` 可动态收缩/放大；收缩只阻止继续领新窗口，**绝不回收**仍有效的租约，槽位随完成/到期自然释放 |
| 超时接管 | 任意 worker 可接管已超时窗口（同 id/字节），同持有者租约内重领为幂等重放（不增重试） |
| 慢窗口不阻塞 | 屏障/租约/在途上限均按租户隔离；一个慢窗口只挡它正前方的连续前缀，不挡同租户后续窗口，也不挡其他租户 |
| 重复提交 | 已完成窗口同末端重复提交幂等成功（`idempotent=true`），不重复推进 |
| 越过窗口末端 | 提交末端 `!=` 窗口固定末端 → `409 window_end_mismatch`，屏障不动 |
| 跨租户 window_id | 不属于该租户的 id → `403 bad_window`，不泄露归属 |
| 停用租户 | claim/fetch/commit 一律 `403 tenant_inactive`，窗口历史与屏障保留 |
| 筛选规则变更 | 规则只前进版本（`filter_version+1`），不抢占租约；旧版本在途窗口提交 `409 filter_changed`，持有者租约内重领刷新到新版本后可提交 |
| 在途上限 | 活动（未超时）窗口数 `== max_inflight` 时再领 → `409 inflight_cap_reached`；超时窗口不计活动数、可立即接管 |
| 拒绝可审计 | 每次拒绝单独落 `reject` 事件（稳定 reason），HTTP/CLI/运维页可见 |
| 重启恢复 | SQLite `synchronous=FULL`；重启时从窗口完成事实重算连续前缀屏障，窗口边界/完成记录/提交顺序不变 |

## 数据模型（`wrelay.sqlite`）

- `tenants`：窗口大小、`max_inflight`、筛选 JSON 与 `filter_version`、启停、
  流长/封口、**`commit_barrier`（连续提交屏障）**；
- `stream_chunks`：每租户一条只增字节流（append 源数据）；
- `windows`：`(tenant, seq)` 唯一，固化 `start_offset/end_offset/payload`，
  `state ∈ pending|leased|completed`，`lease_owner/lease_epoch/lease_expires_at/
  retry_count/filter_version/completed_by`；
- `wrelay_events`：`tenant_created / window_leased / window_taken_over /
  window_completed / barrier_advanced / barrier_recovered /
  window_filter_refreshed / max_inflight_changed / filter_updated /
  tenant_deactivated / stream_appended / stream_sealed / reject`。

**空洞**定义为：连续提交屏障之后、**最远完成窗口**之前仍未完成的窗口
（更远的、尚未物化的积压不算空洞，由 `available_windows` 表达）。
**高水位 `high_water`** 是最远完成窗口的末端，屏障可能因空洞落后于它。

## 快速开始

```bash
export PYTHONPATH=$(pwd)

python -m wrelay init ./wrelay-home --window-size 60 --max-inflight 4 --ttl 30
# 打印管理员令牌 afra_…（仅显示一次）

python -m wrelay serve ./wrelay-home --port 8095
# 运维页 http://127.0.0.1:8095/ui
```

管理员（也可全部走 CLI，默认 `--base-url http://127.0.0.1:8095`）：

```bash
python -m wrelay tenants create --tenant-id aud-a --name "A组审计" \
    --window-size 60 --max-inflight 4 --admin-token afra_…      # 返回 dprt_…
python -m wrelay append  aud-a --records rows.json --admin-token afra_…
python -m wrelay seal    aud-a --admin-token afra_…            # 尾窗定型
python -m wrelay inflight aud-a --max 2 --admin-token afra_…   # 动态收缩/放大
python -m wrelay filter  aud-a --filter filter.json --admin-token afra_…
python -m wrelay deactivate aud-a --reason "离场" --admin-token afra_…
python -m wrelay status --admin-token afra_…
```

worker（租户令牌）：

```bash
python -m wrelay claim  --token dprt_… --worker w1 --ttl 30
python -m wrelay fetch  --token dprt_… --worker w1 --window-id afw_… --out win.bin
python -m wrelay commit --token dprt_… --worker w1 --window-id afw_… --end-offset 60
```

claim/fetch 返回窗口元数据与 `payload_b64`（原始字节的 base64）、`payload_sha256`、
持有者、`lease_epoch`、筛选版本、到期时间与重试次数。

## HTTP API

租户（`dprt_…`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/relay/claim` | `{worker, ttl_seconds?}`：优先接管最靠前的超时窗口补洞，否则领最靠前未完成窗口 |
| POST | `/v1/relay/fetch` | `{worker, window_id, ttl_seconds?}`：同持有者重放原窗口/字节；超时则接管；已完成返回 completed 事实 |
| POST | `/v1/relay/commit` | `{window_id, end_offset, worker, filter_version?}`：登记完成 + 补洞推进屏障 |
| GET  | `/v1/relay/status` | 本租户逐窗口区间/持有者/状态/epoch/重试、屏障、高水位、空洞、在途数、拒绝 |

管理员（`afra_…`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET  | `/v1/admin/status` | 全部租户 + 窗口 + 拒绝统计 + 最近事件 |
| GET  | `/v1/admin/tenants` | 租户列表 |
| POST | `/v1/admin/tenants` | 创建租户（`window_size/max_inflight/filter`，返回一次性令牌） |
| POST | `/v1/admin/tenants/<id>/inflight` | `{max_inflight}` 动态调整 |
| POST | `/v1/admin/tenants/<id>/filter` | `{filter}` 前进筛选版本 |
| POST | `/v1/admin/tenants/<id>/deactivate` | `{reason}` |
| POST | `/v1/admin/tenants/<id>/append` | `{records:[...]}` 或 `{bytes_b64}` |
| POST | `/v1/admin/tenants/<id>/seal` | 封口（尾窗按真实长度定型） |

错误码：`401 unauthorized`、`403 {tenant_inactive,bad_window}`、
`409 {lease_conflict,stale_lease,window_end_mismatch,filter_changed,
inflight_cap_reached,tenant_already_exists,stream_sealed}`、
`404 {tenant_not_found,window_not_found}`、`400 {invalid_body,invalid_param}`。
无窗口可领（未封口尾窗/全部在途或完成）返回 `200 {"window": null, ...}`。

## 运维页 `/ui`

每租户一条窗口色带（completed/leased/超时/空洞/pending），展示连续提交屏障、
高水位、空洞序号、窗口大小、最大在途、活动/超时/完成数、在途窗口序号、筛选
版本；展开可见每个窗口的区间、持有者、状态、`lease_epoch`、重试次数、完成者与
时刻；可直接调整在途上限、停用/创建租户，并观察最近事件（领取、超时接管、
乱序完成、补洞推进、屏障重建、筛选刷新、收缩、停用）。

## 目录结构

```
wrelay/
  canonical.py  确定性 JSON / HMAC
  errors.py     稳定错误码 + HTTP 状态 + 拒绝归类
  store.py      独立 SQLite 持久化（流/租户/窗口租约/事件）
  relay.py      窗口切分、租约/接管、提交、补洞推进屏障、重启恢复
  server.py     ThreadingHTTPServer JSON API（租户 + 管理）
  webui.py      零依赖运维单页（/ui）
  app.py        home 引导/密钥/打开 Relay（打开时自动 recover）
  cli.py        命令行（init/serve + HTTP 客户端）
tests/test_wrelay.py    19 个场景测试（可控时钟 + 真实 HTTP）
tests/demo_wrelay.py    真实子进程服务 + 跨进程重启的六场景演示
```

## 运行测试 / 演示

```bash
PYTHONPATH=$(pwd) python3 -m unittest tests.test_wrelay -v
PYTHONPATH=$(pwd) python3 tests/demo_wrelay.py
```

## 可观察的验收场景

1. **并发领取上限**：领满 `max_inflight` 后第 N+1 个 claim 返回 `409 inflight_cap_reached`；
2. **乱序补洞**：先完成 #3/#2 时屏障停在 0（高水位 240、空洞 [0,1]），补齐 #0 后到 60，
   补齐 #1 后一次跳到 240，`filled_windows=[1,2,3]`；
3. **超时接管**：TTL 到期后新 worker 接管，window_id/字节不变、`epoch 1→2`、
   `retry_count=1`，旧持有者提交 `409 stale_lease`；
4. **收缩冲突**：持两个有效窗口时把上限收缩到 1，持有者不被抢占、新 claim 被拒，
   槽位随完成释放后恢复领取；其他租户的屏障照常推进；
5. **停用拒绝**：停用后 claim/commit 均 403，屏障与窗口历史保留；
6. **重启恢复**：乱序完成后杀进程重启，屏障不越洞、窗口边界/字节/完成记录不变，
   重领返回同 id 同字节，补齐空洞后屏障一次推进；
7. 另含重复提交幂等、越过末端、跨租户 id、筛选版本变更、封口尾窗、拒绝审计、HTTP/UI。
