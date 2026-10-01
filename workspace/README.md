# DPGW — 差分隐私查询网关

供分析团队查询敏感统计数据的差分隐私（DP）网关。数据管理员发布**带确定版本、内容寻址**的
数据集快照并为团队划拨隐私预算（ε、δ）；分析者提交计数 / 分组计数 / 受限直方图查询时，
网关依次执行：**规范化查询 → 计算敏感度与预计消耗 → 预算与冻结检查 → 以稳定噪声种子
执行并出具签名收据**。

零第三方依赖，仅使用 Python 3.11 标准库（含自带的 MT19937 噪声 RNG 实现，保证跨解释器可复算）。

## 核心安全语义

| 需求 | 实现 |
|---|---|
| 重试幂等、不重复扣费 | 规范查询哈希 `query_hash` + `(team, snapshot, query_hash)` 唯一约束；缓存命中返回原结果，`cached=true, charged=false` |
| 并发不透支 | 所有变更经 `RLock` 串行，执行在单条 `BEGIN IMMEDIATE` 事务中完成「查重/冻结/查预算/写结果/扣预算」，失败整体回滚 |
| 失败查询不扣费 | 无效查询、快照停用、查询族冻结、预算不足、快照篡改 —— 全部在提交前回滚，预算分文不动，仅写审计 |
| 稳定可复算的噪声 | 噪声 = HMAC 派生种子（主种子, team, snapshot, query_hash, 坐标）→ 规格化 MT19937；离线工具可逐坐标复算 |
| 快照版本替换 | 双层身份：`data_fingerprint`（schema+行，篡改检测）与 `snapshot_id`（name@version+指纹）。旧版本停用后**新查询一律拒绝**，旧预算命名空间独立，旧缓存无法花新版本的钱 |
| 旧结果仍可验证 | 旧快照目录保留；HMAC 签名收据 + 离线工具可随时验签、重哈希数据、重算真值与噪声 |
| 冻结疑似组合攻击族 | 族指纹忽略 ε/δ 与过滤字面量（`age > 30` 与 `age > 40` 同族），支持 global/team/snapshot/team+snapshot 四种作用域 |
| 冻结策略 | **已执行**结果与审计完整保留、仍可复取；**未执行**的同族请求统一 403 拒绝；冻结前已缓存的重试仍返回原结果且免费 |
| 多语句作业 | 两阶段票据：先出具带截止时间的签名票据并锁定 ε/δ（`budget_holds`），确认后单事务**全部出结果或全部回滚**；取消/过期归还未消费额度；`request_key` 幂等且防混用；重启后可继续或安全清理 |

审计日志为只增表，记录所有执行（`ok_executed`）、缓存重放（`ok_cached`）与各类拒绝
（`reject_budget` / `reject_frozen` / `reject_inactive` / `reject_invalid`），
以及多语句作业的 `job_reserved` / `job_completed` / `job_cancelled` /
`job_expired` / `job_interrupted` / `reject_conflict`，
和联合发布批次的 `pub_created` / `pub_registered` / `pub_reregistered` /
`pub_withdrawn` / `pub_sealed` / `pub_voided` / `pub_amended` /
`reject_quorum` / `reject_late`，
以及受控共享包的 `share_grant_set` / `share_created` / `share_replayed` /
`share_revoked` / `share_creation_failed` /
`reject_share_audience` / `reject_share_field` / `reject_share_state` /
`reject_share_invalid` / `reject_share_not_found` /
`reject_revoked` / `reject_expired` / `reject_audience`，
含时间、操作者、团队、快照、family、请求 id 与扣费量。

## 可恢复的多语句分析作业（两阶段票据）

分析者一次提交若干统计语句，语义为**预留 → 确认**：

1. **解析与预订（POST /v1/jobs）**：每个成员都要能解析、所属快照仍生效、查询族未被冻结，
   任一不满足则整张票据都不出、一分钱不锁；通过后服务生成带 `expires_at` 的**签名票据**，
   并按 (团队, 快照) 在 `budget_holds` 中锁定所需 ε/δ（作业内重复的规范查询、以及已是缓存
   重放的成员不锁）。
2. **确认（POST /v1/jobs/&lt;id&gt;/confirm）**：在**单条 `BEGIN IMMEDIATE` 事务**内重新校验
   （票据未过期、快照仍 active、族未冻结、锁定仍被预算覆盖），随后写入全部结果、扣减预算、
   删除锁定并完成作业——要么全部产出带签名的结果与一张**整批签名清单（job manifest）**，
   要么整体回滚：作业置 `failed`、锁定全部释放、不留部分结果与部分扣减。
3. **取消 / 过期**：`cancel` 或票据到期（惰性 + `sweep_expired_jobs`）会把尚未消费的额度
   全部归还；取消幂等。
4. **幂等与冲突**：`(team_id, request_key)` 唯一；同键重放**第一张票据**（同载荷、同 job_id、
   不重复锁定），同键不同载荷返回 `409 job_conflict` 并审计 `reject_conflict`。
5. **并发不透支**：所有锁定在写事务内取得，且**单条查询路径**同样把活跃锁定计入不可用额度
   （可用 = 上限 − 已用 − 锁定），因此作业与作业、作业与即时查询并发竞争时都不可能超额。
6. **崩溃恢复**：服务重启时 `recover_pending_jobs` 将过期的 `reserved` 置为 `expired`、
   将卡在 `executing` 的作业置为 `failed`（结果与扣减本就在同一事务，不可能只提交一半），
   并清理任何孤儿锁定；未过期的 `reserved` 作业与锁定保留，重启后仍可确认。

作业状态：`reserved → executing → completed | failed | cancelled | expired`。

## 可修订的联合发布批次（amendable joint publications）

多个分析团队要把**同一套统计口径**的 DP 结果联合发布为**一个签名版本**时，
分析负责人（管理员）先固定三件事，随后各团队在自己的预算内登记贡献：

1. **固定统计口径**：有序的 (快照, 规范查询) 语句清单，身份为 `spec_hash`，
   修订时**必须完全相同**，旧版本与新版本可逐坐标比较；
2. **最少参与团队数** `min_participants`（门槛 / quorum）：不同团队数达到门槛才允许封账；
3. **封账时刻** `close_at`：每版独立的截止时间。

生命周期：`collecting → sealed`（一份签名发布清单）或 `void`
（到期仍不足门槛，全部预算锁归还）。版本链 `v1 ← v2 ← …` **线性**，
同一批次至多一个开放版本，迟到贡献归属无歧义。

- **登记 / 撤回**：团队对一个 `collecting` 版本登记即放置 `pub_holds`
  （与作业锁同权：已用不变但额度对所有竞争者不可用），撤回即归还；
  登记时与封账时都逐团队重算「未缓存、批内去重」后的真实需求，已缓存语句免费。
- **重复登记幂等、不重复计费**：同团队同版本重复登记直接重放（`registration=replayed`），
  不加第二把锁；封账时同一 (团队,快照,query_hash) 全版本只产生一条结果、只扣一次费。
- **封账**：负责人提前封账或到期清扫触发。单条 `BEGIN IMMEDIATE` 事务内对**每个**
  参与团队重新校验（快照仍 active、查询族未冻结、快照文件完整、预算仍覆盖锁定），
  随后全员出结果、扣费、删锁、写归属与唯一的签名 release manifest——要么全部成功，
  要么整体回滚，**批次与账本保持原状**（`reject_budget / reject_frozen /
  reject_inactive / reject_invalid / reject_quorum`，拒绝原因随版本状态返回）。
- **迟到贡献**：对已封账（或已 void）版本的登记返回 `410 publication_closed`，
  必须进入下一版；负责人对 sealed 版本 `amend` 即开一个同口径 child 版本。
- **修订与可验证性**：修订只新建版本；父版的签名清单与 `manifest_digest` 永久保留，
  新版清单内嵌 `parent_manifest_digest` 形成谱系链，离线可逐版核验。
- **并发安全**：所有变更经同一把 `RLock` + 写事务串行；封账与登记/撤回/封账并发时
  只会成功一次发布、扣一次费（批次锁与作业锁一起计入可用额度，作业与批次间也不透支）。
- **崩溃恢复**：重启时 `recover_open_publications` 把到期且达标的版本自动封账、
  不足门槛的置 `void` 并归还锁、删除孤儿锁；未到期的 `collecting` 版本与其锁保留，
  重启后仍可登记/封账。封账事务本身原子，崩溃不可能留下半发布或半扣费。
- **页面**：`/ui` 展示版本谱系、参与/门槛、口径哈希、封账/作废时刻、拒绝原因；
  团队可用自己的令牌在页面上登记/撤回并查看参与状态。

```bash
# 负责人：固定口径 + 门槛 + 封账时刻（规格文件同作业批文件格式）
python -m dpgw publications HOME create --admin-token dpa_... \
    --name weekly-joint --batch examples/job_batch.json \
    --min-participants 3 --close-at 2026-09-30T18:00:00Z

# 各团队：登记（幂等）/ 撤回；ref 可用 pubv_ 版本 id 或批次 id/名称（解析为最新版）
python -m dpgw publications HOME register --token dpt_... --ref pubv_xxx
python -m dpgw publications HOME withdraw --token dpt_... --ref pubv_xxx

# 负责人：封账发布（达标即可提前封），或到期清扫；不足门槛的到期版本可作废
python -m dpgw publications HOME seal   --admin-token dpa_... --ref pubv_xxx --out r1.json
python -m dpgw publications HOME sweep  --admin-token dpa_...
python -m dpgw publications HOME void   --admin-token dpa_... --ref pubv_xxx

# 修订：对 sealed 版本开同口径新版；查看谱系 / 参与状态 / 拒绝原因 / 批次锁
python -m dpgw publications HOME amend   --admin-token dpa_... --ref pubv_xxx --close-at 2026-10-07T18:00:00Z
python -m dpgw publications HOME lineage --token dpt_... --ref weekly-joint
python -m dpgw publications HOME get     --token dpt_... --ref pubv_xxx
python -m dpgw publications HOME holds

# 离线：重算每版参与集合、预算归属与签名摘要（修订版可带 --parent-digest 验谱系）
python -m dpgw verify publication --manifest r1.json \
    --secrets HOME/secrets.json --snapshots-dir HOME/snapshots
```

发布清单（`pr1`）含固定语句（含 canonical 查询）、参与团队及其 ε/δ 归属、
稠密的 位置×团队 成员表（每个 `result_id` 是否由该团队付费）、去重后的全部结果收据，
以及版本谱系字段；HMAC 签名，规范体 `sha256` 即 `manifest_digest`。

发布清单（`pr1`）含固定语句（含 canonical 查询）、参与团队及其 ε/δ 归属、
稠密的 位置×团队 成员表（每个 `result_id` 是否由该团队付费）、去重后的全部结果收据，
以及版本谱系字段；HMAC 签名，规范体 `sha256` 即 `manifest_digest`。

## 受控共享包（按团队授权的字段裁剪分发）

联合发布封账后，分析负责人可把同一份签名发布清单按**受众团队**裁剪为字段级共享包：

1. **白名单先行**：负责人先为 `(发布版本, 受众团队)` 设置字段白名单
   （`statements.*` / `participants.*` / `members.*` / `receipts.*`，
   裸集合名表示整组授权）；创建包时的字段集合**必须是白名单子集**，
   越权字段、不存在的受众、未封账/已作废版本、过去的过期时间一律拒绝，
   且拒绝路径在任何写事务之前，**不留半笔状态**。
2. **一份授权 = 一个包**：部分唯一索引保证同一 `(版本, 受众, 字段集)` 至多一个
   live 包；并发创建时一方写入 `creating` 预留行，其余请求帮忙完成同一确定性密封，
   最终只有一个 `share_id`、一把 `share_key`、一个内容寻址文件与一个摘要。
   重复创建幂等重放（不同 ttl 也不会改过期时间），重复取回返回**逐字节相同**的包，
   永不生成第二份。
3. **签名绑定**：包格式 `sh1`，独立 `share_secret` 的 HMAC 绑定
   `release_digest`（发布清单 `manifest_digest`）、`release_parent_digest`（父版本摘要）、
   受众团队、裁剪字段集（`fields_hash`）与 `expires_at`；篡改任何绑定或裁剪内容
   都会使离线验签失败。整组授权 `receipts` 时收据保留原 HMAC（含 `sig`），
   可逐张从种子+快照复算。
4. **撤销与过期**：撤销是幂等状态翻转，之后的新取回返回 `410 share_revoked`；
   过期返回 `410 share_expired`。两者都只阻止在线取回，**已下载文件仍可离线验签**
   （验签报告单列 `expired` 标志，真实性独立于网关状态）。撤销/过期释放授权作用域，
   之后可重新创建新包。
5. **崩溃恢复**：`creating` 预留行先落库（字段、ttl、过期、父摘要全部固定），
   包体是该行的确定性纯函数；重启时 `recover_pending_shares` 要么补全密封，
   要么在受众/白名单/发布已失效时安全置 `failed`（无包文件、无 key）并释放作用域。
6. **版本修订不改变旧包**：修订只产生新发布版本；旧包永久绑定旧 `manifest_digest`
   与父摘要链，旧文件照常离线验证。

```bash
# 负责人：设置字段白名单 → 创建裁剪包（share_key 仅此一次返回）
python -m dpgw shares HOME grant  --admin-token dpa_... --ref pubv_xxx \
    --team team_xxx --fields statements.position,members.charged,receipts.values
python -m dpgw shares HOME create --admin-token dpa_... --ref pubv_xxx \
    --team team_xxx --fields statements.position,members.charged,receipts.values \
    --ttl 604800 --out pkg.json
# 收件方：用团队令牌 + share_key 取回同一包（重复取回字节不变）
python -m dpgw shares HOME fetch --token dpt_... --share-key shk_... --out mine.json
# 管理：列出/查看（--reveal-key 再显一次 key）/撤销/取回审计/恢复未完成申请
python -m dpgw shares HOME list [--state sealed|revoked|failed]
python -m dpgw shares HOME get        --admin-token dpa_... --share shr_xxx --reveal-key
python -m dpgw shares HOME revoke     --admin-token dpa_... --share shr_xxx --reason "..."
python -m dpgw shares HOME retrievals --admin-token dpa_... --share shr_xxx
python -m dpgw shares HOME recover    --admin-token dpa_...
python -m dpgw shares HOME grants [--ref pubv_xxx]

# 离线：无需服务进程，仅凭包文件 + secrets.json 验签（撤销/过期后仍可验）；
#   有完整发布清单时逐字段重算裁剪并核对 release_digest/父摘要，整组收据逐张复算
python -m dpgw verify share --package mine.json --secrets HOME/secrets.json \
    [--release r1.json --snapshots-dir HOME/snapshots \
     --parent-digest <父版 manifest_digest>] [--now 2099-01-01T00:00:00Z]
```

`verify ledger` / `verify bundle` 同步审计共享包：作用域与 share_key 唯一、
释放字段不得宽于白名单、绑定的 `manifest_digest`/父摘要必须与发布版本一致、
`creating` 不得残留、`failed` 不得带包/密钥、撤销后取回审计存在。

## 防分叉透明度账本（所有签名发布与裁剪分发的只增 Merkle 日志）

所有**已签名发布版本**（封账 `sealed` / 作废 `void`）与**受控共享包**
（签发 `share_issued` / 撤销 `share_revoked`）都进入同一条只增透明度日志：

1. **业务事务 ⇄ outbox 原子**：每个事件在执行业务变更的**同一个
   `BEGIN IMMEDIATE` 事务**里先写 `tl_outbox`（event_key + 内容寻址叶哈希 +
   完整载荷），提交后仍持网关锁、按 `seq` 确定顺序 drain：一片叶子 + 一个
   新签名 checkpoint。进程中断只可能留下「业务已提交、叶子待补」的 outbox
   行，重启时 `recover_transparency_log` 按固定顺序补齐——**不丢叶、不重号、
   根不回退、不可能长出第二棵历史**；崩溃后若叶子已落而 checkpoint 未签，
   恢复逻辑由叶子纯函数重建缺失的 checkpoint 尾部。
2. **内容寻址叶子 + 单调 checkpoint**：叶哈希
   `SHA256(0x00 || 规范信封)`，内节点 `SHA256(0x01 || L || R)`
   （RFC 9162 风格）。checkpoint 对 `(tree_size, root, prev_size, prev_root)`
   用独立 `transparency_secret` 签名，高度从空树 genesis（size 0）逐 1 递增，
   prev 链严格单调。
3. **event_key 幂等**：`release_sealed:<version_id>` /
   `release_voided:<version_id>` / `share_issued:<share_id>` /
   `share_revoked:<share_id>`。相同 key 重放永远返回**原叶序号**（封账重放、
   同作用域制包重放、重复撤销都不产生第二片叶子）；相同 key 配不同载荷即
   `transparency_conflict`，事务回滚、既有账本不变。
4. **包含证明 / 一致性证明**：调用方可取任意叶的包含证明（折到任一已签名高度），
   以及任意两个 checkpoint 之间的追加一致性证明（旧 frontier + `[old,new)`
   扩展子树，区间由两个高度**由验证方自行推导**，无法丢/换节点）；离线工具
   独立验签、折根。不存在的叶 404，高度超过最新 checkpoint 410
   `checkpoint_expired`，篡改证明一律验签/折根失败。
5. **分叉证据 → 冻结**：审计员观察到**同一高度、不同根**的两个有效签名
   checkpoint 时提交证据（`tl_submit_fork` / HTTP / CLI）；验签通过即把日志
   置为 frozen（原因 `fork_evidence`）。冻结后封账、作废、制包、撤销**全部
   423 `transparency_frozen` 明确失败且不改变既有账本**；读取、证明、已封账
   包的幂等重放不受影响。同根/坏签名/高度不同的证据 400 拒绝且不改账。本地
   根链自洽校验失败则以 `local_integrity_failure` 冻结而非带病追加。

```bash
# 当前高度/根/冻结状态、叶子列表
python -m dpgw transparency HOME state  --token dpa_...
python -m dpgw transparency HOME leaves --token dpa_...
# 叶 0 在最新（或指定高度）的包含证明；按 event_key 反查
python -m dpgw transparency HOME inclusion 0 --token dpt_...
python -m dpgw transparency HOME event release_sealed:pubv_xxx --token dpt_...
# 相邻（或任意）checkpoint 的追加一致性证明
python -m dpgw transparency HOME consistency 0 --new-size 3 --token dpa_... --out c.json
# 审计员提交分叉证据并冻结；重启后补齐 outbox
python -m dpgw transparency HOME submit-fork --first cpA.json --second cpB.json \
    --admin-token dpa_...
python -m dpgw transparency HOME recover --admin-token dpa_...

# 离线验证（无需服务进程，只需 secrets.json 里的 transparency_secret）
python -m dpgw verify checkpoint  --checkpoint cp.json --secrets HOME/secrets.json
python -m dpgw verify inclusion   --proof inc.json --secrets HOME/secrets.json
python -m dpgw verify consistency --proof c.json   --secrets HOME/secrets.json
python -m dpgw verify fork-evidence --first cpA.json --second cpB.json \
    --secrets HOME/secrets.json
```

`verify ledger` / `verify bundle` 同时审计透明度日志：叶序号稠密 0..n-1、
每个根都能由叶重算、checkpoint prev 链不断裂、outbox 不得残留、每个
sealed/void 版本与 sealed/revoked 包都有恰好一片绑定相同摘要的叶子；冻结
状态（原因/高度/证据）随 bundle 导出。HTTP：团队与管理员均可读
`GET /v1/transparency{,/leaves,/checkpoint,/inclusion/<i>,/events/<key>,
/consistency}`，管理员 `POST /v1/admin/transparency/fork`、
`POST /v1/admin/transparency/recover`。管理台 /ui 有专门卡片展示高度、根、
冻结原因、叶子、证明并支持提交分叉证据。

```bash
python -m dpgw jobs HOME submit --token dpt_... --request-key weekly-batch-1 \
    --batch examples/job_batch.json
python -m dpgw holds HOME                       # 查看当前锁定（作业 + 批次）
python -m dpgw jobs HOME confirm --token dpt_... --job job_xxx --out results.json
python -m dpgw jobs HOME cancel  --token dpt_... --job job_xxx   # 取消并归还额度
python -m dpgw jobs HOME get     --token dpt_... --job job_xxx --out manifest.json
python -m dpgw jobs HOME list [--state reserved]
```

## 目录结构

```
dpgw/
  canonical.py   查询规范化、query_hash、族指纹、过滤器→SQL
  privacy.py     L1 敏感度、Laplace/Gaussian 校准、确定性 MT19937 噪声
  engine.py      真实聚合（固定域 + 溢出桶 + NULL 桶），服务端与离线校验共用
  snapshot.py    不可变快照构建/发布/完整性校验（CSV → 只读 sqlite）
  store.py       SQLite schema（团队/快照/预算/结果/冻结/作业/锁定/发布批次/审计）
  gateway.py     核心服务：事务、预算、幂等、冻结、审计
  jobs.py        可恢复多语句作业：两阶段票据、budget_holds、取消/过期、重启恢复
  publications.py 可修订联合发布批次：登记/撤回、封账、版本谱系、重启恢复
  shares.py      受控共享包：字段白名单、按团队裁剪、签名绑定、幂等取回、撤销/过期、恢复
  transparency.py 防分叉透明度日志：可恢复 outbox、内容寻址叶子、Merkle 包含/一致性证明、分叉冻结
  server.py      ThreadingHTTPServer JSON API
  webui.py       内嵌预算、冻结、作业/发布/共享包/透明度管理界面（/ui，零依赖单页）
  verify.py      离线收据/作业清单/发布清单/共享包/透明度证明/账本/导出包校验
  cli.py         命令行
tests/           106 个 unittest（含 12 线程并发、作业/批次/共享包并发抢占与真实 HTTP 测试）
examples/        示例规格、500 行数据与查询
```

## 快速开始

```bash
export PYTHONPATH=$(pwd)

# 1) 初始化（生成噪声主种子、收据 HMAC 密钥、管理员令牌，仅显示一次）
python -m dpgw init ./home

# 2) 数据管理员构建并发布确定版本快照
python -m dpgw snapshot build --spec examples/spec.json --csv examples/employees.csv --out ./snap_v1
python -m dpgw publish ./home --snapshot-dir ./snap_v1

# 3) 建团队、划拨预算
python -m dpgw team ./home create --name "风控分析组"      # 返回 dpt_ 团队令牌
python -m dpgw budget ./home allocate --team team_xxx --snapshot <sid> --epsilon 3 --delta 1e-6

# 4) 先估算（不扣费）再执行
python -m dpgw plan  ./home --token dpt_... --snapshot <sid> --query examples/q_count.json
python -m dpgw query ./home --token dpt_... --snapshot <sid> --query examples/q_count.json
# 再次执行同一规范查询：cached=true, charged=false，ε 不重复扣减

# 5) 管理：冻结 / 审计 / 版本替换
python -m dpgw freeze ./home <family_id> --scope global --reason "疑似组合重构"
python -m dpgw audit ./home --family <family_id>
python -m dpgw deactivate ./home --snapshot <old_sid>

# 6) 启动 HTTP API + 管理界面（浏览器打开 http://127.0.0.1:8080/ui）
python -m dpgw serve ./home --port 8080
```

## 查询语言

```jsonc
// 计数
{"type": "count", "epsilon": 0.5, "delta": 0.0,
 "filter": {"op": "and", "args": [
   {"op": "cmp", "column": "city", "predicate": "=", "value": "Beijing"},
   {"op": "cmp", "column": "active", "predicate": "=", "value": true}]}}

// 分组计数（分组列必须在快照清单中声明固定域；域外/NULL 归入 __other__）
{"type": "grouped_count", "epsilon": 0.8, "group_by": ["city"]}

// 受限直方图（分箱必须命中清单中声明的 bin set；NULL 行入 __null__ 桶）
{"type": "histogram", "epsilon": 0.7, "delta": 1e-6,
 "column": "salary", "bin_edges": [null, 100000, 200000, 400000, null]}
```

过滤器 AST：`and` / `or` / `not` / `cmp`（=,<>,<,<=,>,>=）/ `in` / `is_null`。
规范化时 `and|or` 参数集合按规范 JSON 排序、单子节点合取直接坍缩、`in` 去重排序，
因此语义相同的不同写法哈希一致。`delta=0` 用 Laplace（纯 ε-DP），`delta>0` 用
Gaussian 机制（(ε,δ)-DP）。

## HTTP API

分析者（团队令牌）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/plan` | 规范化 + 敏感度 + 预计消耗 + 冻结/缓存状态，**不扣费** |
| POST | `/v1/query` | 执行（或幂等返回缓存） |
| POST | `/v1/jobs` | 提交多语句作业：解析全部成员 → 出签名票据 + 锁定额度（`request_key` 幂等） |
| POST | `/v1/jobs/<id>/confirm` | 确认：单事务全部产出或全部回滚；已完成则幂等重放 |
| POST | `/v1/jobs/<id>/cancel` | 取消（幂等）并归还尚未消费的锁定额度 |
| GET | `/v1/jobs/<id>` | 作业状态（完成时附整批签名清单与全部结果） |
| GET | `/v1/publications` | 列出版本（可按 `state` / `batch_id` 过滤） |
| GET | `/v1/publications/<ref>` | 版本状态：参与团队、门槛、拒绝原因（封账后附签名发布） |
| GET | `/v1/publications/<ref>/lineage` | 批次版本谱系（`ref` 可为版本 id 或批次 id/名称） |
| POST | `/v1/publications/<ref>/register` | 登记贡献（幂等；重复不重复计费） |
| POST | `/v1/publications/<ref>/withdraw` | 封账前撤回并归还锁定 |
| GET | `/v1/results/<id>` | 复取已执行结果（不扣费） |
| GET | `/v1/results?snapshot_id=` | 列出结果 |
| GET | `/v1/budgets` | 本团队预算（含 `epsilon_held` / `delta_held` 锁定量：作业+批次） |

管理员（管理员令牌，前缀 `/v1/admin`）：团队增/列、快照发布/列表/启停、
预算划拨/列表、冻结增/列/删、`/v1/admin/audit`、`/v1/admin/jobs`（按状态查看
锁定/执行/取消/过期/冲突）、`/v1/admin/holds`（作业额度锁定），以及联合发布批次的
`POST /v1/admin/publications`（创建）、`GET /v1/admin/publications`、
`GET /v1/admin/publications/<ref>`、`.../lineage`、
`POST .../<ref>/seal`（封账发布）、`.../<ref>/amend`（修订新版）、
`.../<ref>/void`（到期且不足门槛作废）、`POST /v1/admin/publications/sweep`
（到期清扫）、`GET /v1/admin/publications/holds`（批次额度锁定）、
`/v1/admin/bundle`（导出离线校验包，含作业清单、作业/批次锁定、发布版本与共享包）。

受控共享包：团队侧 `POST /v1/shares/fetch`（团队令牌 + `share_key`，
取回同一裁剪包；跨团队令牌不泄露存在性，撤销 410/过期 410）；
管理员侧 `POST /v1/admin/share-grants`（设置字段白名单）、
`GET /v1/admin/share-grants`、`POST /v1/admin/shares`（创建/幂等重放）、
`GET /v1/admin/shares`、`GET /v1/admin/shares/<id>?reveal_key=1`、
`POST /v1/admin/shares/<id>/revoke`、`GET /v1/admin/shares/<id>/retrievals`、
`POST /v1/admin/shares/recover`（恢复未完成申请）。

防分叉透明度账本（团队/管理员令牌均可读）：`GET /v1/transparency`
（最新高度/根/冻结状态）、`GET /v1/transparency/leaves`、
`GET /v1/transparency/checkpoint?tree_size=`、
`GET /v1/transparency/inclusion/<index>?tree_size=`（包含证明）、
`GET /v1/transparency/events/<event_key>?tree_size=`、
`GET /v1/transparency/consistency?old_size=&new_size=`（一致性证明）；
管理员侧 `POST /v1/admin/transparency/fork`（提交两个同高度不同根的已签名
checkpoint，验签通过即冻结后续签发）、`POST /v1/admin/transparency/recover`
（重启后按固定顺序补齐 outbox）。不存在的叶 404、过期高度 410、
篡改/分叉证据非法 400、冻结后的封账/作废/制包/撤销 423。

所有请求使用 `Authorization: Bearer <token>`。请求体可带 `request_id` 用于追踪。

## 离线结果校验工具

不信任服务进程：审计员拿**收据**（或导出包）+**快照目录**+**secrets.json** 即可独立复核：

```bash
# 导出（管理员）
python -m dpgw bundle ./home export --out bundle.json

# 单张收据：验签 → 重哈希快照 → 重算真值 → 从种子再生噪声 → 逐坐标比对
python -m dpgw verify receipt --receipt r.json \
    --secrets ./home/secrets.json --snapshot-dir ./home/snapshots/<sid>

# 整批作业清单：清单验签 → 逐成员收据复算 → charged 成员勾稽消费额（重放不扣费）
python -m dpgw verify job --manifest results.json \
    --secrets ./home/secrets.json --snapshots-dir ./home/snapshots

# 联合发布版本：清单验签 → 重算 spec_hash/门槛 → 逐成员收据复算 →
#   每结果恰由一个团队付费、参与团队 ε/δ 归属勾稽；带 --parent-digest 验修订谱系
python -m dpgw verify publication --manifest r1.json \
    --secrets ./home/secrets.json --snapshots-dir ./home/snapshots \
    [--parent-digest <父版 manifest_digest>]

# 整包：全部收据复算 + 每张作业清单/每版发布清单复算 + 预算账本/锁定勾稽 + 审计存在性
#       （含每个共享包的签名、裁剪、白名单覆盖与发布摘要绑定）
python -m dpgw verify bundle --bundle bundle.json \
    --secrets ./home/secrets.json --snapshots-dir ./home/snapshots

# 单个受控共享包：包 HMAC → 字段集/受众/过期/发布摘要绑定；给完整发布清单时
#   逐字段重算裁剪、核对 release_digest/父摘要、整组收据从种子+快照复算。
#   撤销/过期不影响验签（报告会标 expired=true）；退出码 0=有效, 2=验签失败, 3=已过期
python -m dpgw verify share --package mine.json \
    --secrets ./home/secrets.json [--release r1.json --snapshots-dir ./home/snapshots]

# 只查账本（可对网关 sqlite 副本离线运行）：
#   Σ results 成本 == budgets.spent、spent+活跃hold(作业+批次) 不得超限、
#   每结果恰有一条 ok_executed、无重复结果行、作业状态/锁定/成员全部勾稽、无孤儿锁定、
#   发布版本谱系线性、收集版持有=注册需求、封账版稠密成员表与扣费归属/摘要全部勾稽
python -m dpgw verify ledger --db ./home/gateway.sqlite
```

收据包含规范查询、机制、敏感度、尺度、坐标标签、发布值、时间与 HMAC-SHA256 签名。
篡改任何发布值会使签名失效；篡改快照行会使完整性校验与 `values_reproduced` 同时失败。

## 测试

```bash
python -m unittest discover -s tests -v
# 129 tests: 规范化等价性、族指纹、机制校准与确定性、幂等重试、
# 12 线程同查询只扣一次、并发不同查询绝不超限、失败不扣费、
# 多语句作业票据/锁定/原子全成功全回滚、request_key 幂等与冲突、
# 并发抢占不超额、缓存成员免费与批内去重、取消/过期归还、
# 快照停用/冻结/篡改下无部分结果、重启恢复、冻结保留已执行/拒绝未执行、
# 快照替换隔离、HTTP API、篡改检测、作业清单/账本离线勾稽、
# 联合发布批次：登记幂等不重复计费、撤回归还、门槛拒绝不变账、
# 封账单签名版本与稠密归属、缓存免费/批内重复位置、冻结/停用/预算不足回滚、
# 迟到 410、修订同口径版本谱系、到期自动封账/作废、重启恢复开放版本、
# 并发登记/撤回/封账只发布一次、发布清单/账本/bundle 离线重算与篡改检测、
# 受控共享包：受众/白名单校验与拒绝不留状态、幂等创建/取回一包一摘要、
# 跨团队拒绝、撤销 410 后文件仍可验签、过期语义、并发创建只密封一次、
# 崩溃后重启恢复或安全终止、修订不改旧摘要、字段裁剪/签名/账本/bundle 离线重算、
# 防分叉透明度账本：genesis 空树与稠密追加、逐叶根可重算/checkpoint prev 单调链、
# 包含证明各高度有效/篡改/不存在叶 404/过期 checkpoint 410、
# 任意相邻高度一致性证明与篡改拒绝、event_key 重放返回原叶序号、
# 分叉证据（同高度不同根）冻结、同根/坏签名/不同高度证据拒绝且不改账、
# 冻结后封账/作废/制包/撤销 423 而读取/证明/幂等重放照常、冻结期不清算到期版本、
# 12+ 线程并发封账/制包/撤销/读 checkpoint 不丢叶不重号根不回退、
# outbox 崩溃后固定顺序补齐且不产生第二历史、半入册叶子恢复幂等、
# 本地根篡改自愈失败转冻结、HTTP/CLI、账本/bundle/证明离线勾稽
```

## 安全注意事项（部署前阅读）

- `secrets.json`（噪声主种子与各类 HMAC 密钥）权限 0600；离线校验方需持有它。
  除噪声主种子、收据密钥、共享包密钥外还包含**透明度 checkpoint 签名密钥**
  `transparency_secret`（旧 home 首次打开自动补齐）；分叉证据的验签只信任用
  该密钥签名的 checkpoint，因此该密钥应与其他密钥一起进入机构级密钥管理流程。
  轮换噪声主种子会改变所有未来再生值，因此密钥应进入机构级密钥管理流程。
- 本系统是**可信网关**威胁模型：网关进程可见真实聚合值，但不落库真值；
  分析者只收到加噪结果。需要端到端加密或恶意管理员防护时应叠加硬件/MPC 方案。
- 预算核算采用**线性顺序组合**（ε、δ 直接相加），保守且易审计；未实现高级组合定理。
- 固定域分组与固定分箱直方图用于杜绝按输出自适应挑选分区；`max_groups` 限制维度。
  敏感度均为 L1=1（单表计数，加/删一行）。
- 噪声本身不保证小计数安全：管理员仍应通过预算上限与查询族冻结做外层流控。
