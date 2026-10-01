# afrelay — 独立审计馈送中继（audit-feed relay）

只读镜像现有 DPGW 网关的防分叉透明度日志，并向多个互相隔离的**审计租户**
发放可验证、可重放的连续投递包。中继是一个**独立运行**的进程与一套
**独立持久化**：它只通过网关的只读 HTTP 接口拉取数据，从不打开网关
SQLite、从不调用任何写接口，**绝不自行补造记录**。

零第三方依赖，仅用 Python 3.11 标准库；信任锚只有机构带外分发的
`transparency_secret`（与网关 `secrets.json` 中同名字段一致）。

## 核心安全语义

| 需求 | 实现 |
|---|---|
| 只经只读接口拉取 | 仅 `GET /v1/transparency{,/checkpoint,/inclusion/<i>}`；不打网关库，不调写接口 |
| 验证后才镜像 | 每个高度的签名 checkpoint 用 transparency_secret 独立验 HMAC；每片叶子校验内容地址 `SHA256(0x00‖规范信封)`、event 绑定、inclusion_path 折到已签名根、checkpoint prev 链接到本库存档的上一高度 |
| 失败停止并保留最后可信位置 | 上游不可用 / 回退高度 / 坏签名 / 证明缺口 / 坏叶子 → 本轮不落任何新行，`trusted_tree_size` 不动，记录停止原因；恢复后从同一高度续传 |
| 绝不补造 | 区间内任一叶子验证不过即停在该叶之前；不存在“跳过缺口继续”路径，镜像叶子按原始序号稠密 0..n-1 |
| 冻结上游封顶 | 上游 `frozen` 时只读到 `frozen_tree_size`（最后可信树头），之后的高度即使返回也不镜像 |
| 多租户隔离 | 每租户独立令牌（`dprt_…`）、独立筛选规则、独立消费位点；越租户 delivery_id 返回 `403 bad_delivery` 且不泄露归属、不动位点 |
| 连续投递包 | 包跨越 `[start,end)` **原始序号连续区间**（区间内不匹配叶子跳过），确认只接受 `end == 当前包末端`；跳段/部分确认 `409 ack_end_mismatch` |
| 短租约 + 稳定重投 | 包是已镜像叶子的确定性纯函数：超时回收或进程重启后，重投返回**同一 `delivery_id` 与逐字节相同 JSON**，`lease_count/retries` 增长 |
| 租约互斥 | 活动短租约只属于当前 holder；第二消费者抢租约 `409 lease_conflict`；超时改投后旧 holder 的确认 `409 stale_lease` |
| 确认幂等 | 对已确认包以正确末端重复确认返回同一结果且 `idempotent=true`；错误末端 `ack_end_mismatch` |
| 运行中改筛选拒绝 | 租户一旦发出过投递包（含在途），筛选规则锁定，修改返回 `409 filter_locked` 且规则不变 |
| 已停用租户拒绝 | 停用后 claim/ack 一律 `403 tenant_inactive`，位点与历史保留，永不前移 |
| 慢租户不阻塞 | 每租户位点/租约相互独立，后台同步在独立线程；一个租户不确认不影响他人消费与镜像推进 |
| 拒绝可审计 | 每次拒绝（回滚业务写之后）单独落一条 `reject` 事件，带稳定 `reason`，运维页/状态/CLI 可见 |

## 数据与包格式

镜像库（`relay.sqlite`，与 `gateway.sqlite` 完全分离）：

- `mirror_state`：`trusted_tree_size`（最后可信高度）、上游观察高度、
  冻结观察、`last_status`（`never|caught_up|caught_up_frozen|stopped`）、
  `last_stop_reason`、`consecutive_failures` 等；
- `mirror_leaves`：稠密叶子 0..trusted-1（内容寻址 + 规范信封）；
- `mirror_cps`：每个已验证高度的签名 checkpoint（逐字节存档）；
- `tenants`：令牌哈希、筛选 JSON、`cursor_end`、`filter_locked`、启停；
- `deliveries`：持久化的 afp1 包字节、租约 holder/到期 epoch、
  `lease_count`、状态（`leased|acked`）；部分唯一索引保证每租户至多一个
  在途包、包序号唯一；
- `relay_events`：`first_sync / mirror_advanced / sync_stopped /
  upstream_frozen_cap / delivery_issued / delivery_retried / delivery_acked /
  reject / tenant_created / tenant_deactivated / filter_updated`。

投递包 `afp1`：`{packet_version, delivery_id, tenant_id, seq,
start_index, end_index, leaf_count, leaf_hashes, filter, records[],
checkpoint, sig}`。

- `records[i]` 含原始 `leaf_index`、规范信封、`leaf_hash`、以及锚定到
  `end_index` 高度的 `inclusion_path`/`root_hash`；
- `delivery_id = afd_‖HMAC(packet_secret, 规范(tenant,seq,start,end,
  leaf_hashes))` 的前 32 hex；同输入永远同 id；
- `sig` 是对去 `sig` 规范包体的 HMAC-SHA256。

## 快速开始

```bash
export PYTHONPATH=$(pwd)

# 1) 初始化独立中继 home（只复制 transparency_secret 这一个信任锚）
python -m afrelay init ./relay-home \
    --upstream-url http://127.0.0.1:8080 \
    --upstream-token dpa_...或任一团队只读令牌 \
    --gateway-secrets ./home/secrets.json     # 或 --transparency-secret <hex>
# 打印管理员令牌 afra_…（仅显示一次）

# 2) 运行（后台定时拉取 + HTTP API + 运维页 http://127.0.0.1:8090/ui）
python -m afrelay serve ./relay-home --port 8090 --interval 2

# 手动拉一轮 / 查全局状态
python -m afrelay sync   ./relay-home
python -m afrelay status ./relay-home --admin-token afra_…
```

租户管理（管理员）：

```bash
python -m afrelay tenants ./relay-home create --tenant-id aud-a --name "A组审计" \
    --filter filter.json --admin-token afra_…      # 返回 dprt_… 一次性令牌
python -m afrelay tenants ./relay-home list --admin-token afra_…
python -m afrelay filter  ./relay-home aud-a --filter filter.json --admin-token afra_…
python -m afrelay deactivate ./relay-home aud-a --reason "离场" --admin-token afra_…
```

筛选规则（消费开始前可改，开始后锁定；无 eval/正则）：

```json
{"event_types": ["release_sealed", "share_issued"],
 "event_key_prefix": "share_issued:",
 "subject_prefix": "shr_",
 "payload_field_equals": {"field": "value"}}
```

消费（审计租户）：

```bash
# 领取当前包并保存字节（短租约，默认 30s）
python -m afrelay fetch ./relay-home --token dprt_… --consumer c1 --out pkt.json
# 只确认“当前包末端”；重复确认幂等
python -m afrelay ack ./relay-home --token dprt_… \
    --delivery-id afd_xxx --end-index 42 --consumer c1
```

## HTTP API

租户（`dprt_…`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/relay/claim` | `{consumer, ttl_seconds?}`：领取/租约内重放/超时重投 |
| POST | `/v1/relay/ack` | `{delivery_id, end_index, consumer}`：只接受当前包末端 |
| GET  | `/v1/relay/status` | 本租户镜像高度、位点、积压、在途租约/重试、拒绝事件 |
| GET  | `/v1/relay/mirror` | 镜像高度/冻结/停止原因（无需租户作用域） |

管理员（`afra_…`）：`GET /v1/admin/status`、`POST /v1/admin/sync`、
`GET /v1/admin/mirror/leaves`、`POST /v1/admin/tenants`、
`GET /v1/admin/tenants`、`POST /v1/admin/tenants/<id>/filter`、
`POST /v1/admin/tenants/<id>/deactivate`。运维页 `/ui`。

错误码：`401 unauthorized`、`403 {tenant_inactive,bad_delivery}`、
`409 {lease_conflict,stale_lease,ack_end_mismatch,filter_locked,
tenant_already_exists}`、`404 tenant_not_found`、
`400 {invalid_body,filter_invalid}`。

## 离线投递包校验器

无需中继进程，只需包文件 + 中继 `secrets.json`（内含 relay_packet_secret
与 transparency_secret）：

```bash
python -m afrelay verify packet --packet pkt.json \
    --secrets ./relay-home/secrets.json [--expect-tenant aud-a]
# 退出码：0 有效；2 验签/折根失败；3 参数/文件错误
```

校验：包级 HMAC、`delivery_id` 确定性重算、每叶内容地址与 event 绑定、
锚 checkpoint 的 transparency 签名、每条 inclusion_path 折到已签名根、
区间连续与记录边界。篡改叶子/信封/证明/换钥都会失败。

## 目录结构

```
afrelay/
  canonical.py  确定性 JSON / HMAC（与 dpgw 规范编码一致）
  merkle.py     RFC 9162 Merkle 纯函数（叶哈希/折根/包含路径）
  errors.py     稳定错误码 + HTTP 状态 + 拒绝归类
  store.py      独立 SQLite schema（镜像/租户/位点/租约/事件）
  upstream.py   网关只读客户端：只 GET，独立验签/折根
  relay.py      同步推进、筛选、短租约投递、确认/拒绝、后台轮询、状态
  verify.py     离线 afp1 投递包校验器
  server.py     ThreadingHTTPServer JSON API（租户 + 管理）
  webui.py      零依赖运维单页（/ui）
  app.py        home 引导/密钥/打开 Relay
  cli.py        命令行
tests/test_relay.py      35 个场景测试（真实网关 HTTP + 可脚本化故障上游）
tests/relay_harness.py   真实已签名叶子网关 + 故障注入代理
```

## 可观察的验收场景（测试覆盖）

首次同步（genesis→稠密叶子，`first_sync/mirror_advanced` 事件）、空上游仅
genesis、增量断线续传；上游不可用/回退/坏签名/坏叶子/证明缺口时停在最后
可信位置、连续失败计数与恢复后续传；冻结上游封顶到最后可信树头；绝不跨
缺口补造；筛选隔离与连续区间；消费开始前可改规则、开始后 `filter_locked`；
双消费者抢租约、租约内字节重放、超时同 id 同字节重投、旧租约拒绝、重启后
同包同 id 且可确认；重复确认幂等、跳段/越租户/未知 id/错 consumer 拒绝且
位点不动；租户停用后 claim/ack 拒绝且位点保留；慢租户不阻塞他人与镜像；
有效包离线验签、篡改/错包钥/错锚钥失败；完整 HTTP 流程、管理员鉴权与运维页。
