"""Embedded admin UI assets (budget + freeze management).

A single dependency-free page served at /ui.  It stores the admin token in
browser localStorage and talks to the same JSON API; it never sees raw data.
"""

from __future__ import annotations

INDEX_HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DP Gateway 管理台</title>
<style>
  :root { --bg:#0f1420; --panel:#171e2e; --line:#26314a; --fg:#e6ebf5;
          --muted:#8b97ad; --accent:#5b8cff; --ok:#34c759; --warn:#ffcc00;
          --bad:#ff5b5b; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:14px 20px; border-bottom:1px solid var(--line);
           display:flex; gap:14px; align-items:center; }
  header h1 { font-size:16px; margin:0; flex:0 0 auto; }
  header input { flex:0 1 380px; }
  main { display:grid; grid-template-columns:repeat(2,1fr); gap:16px; padding:16px 20px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px;
          padding:14px 16px; }
  .card h2 { margin:0 0 10px; font-size:13px; text-transform:uppercase;
             letter-spacing:.08em; color:var(--muted); }
  .wide { grid-column:1 / -1; }
  input, select, button, textarea { font:inherit; color:var(--fg);
        background:#0d1322; border:1px solid var(--line); border-radius:7px;
        padding:7px 9px; }
  button { cursor:pointer; background:var(--accent); border-color:var(--accent);
           color:#fff; font-weight:600; }
  button.ghost { background:transparent; color:var(--muted); border-color:var(--line); }
  button.danger { background:var(--bad); border-color:var(--bad); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:end; margin-bottom:8px; }
  .row label { display:flex; flex-direction:column; gap:3px; font-size:12px;
               color:var(--muted); }
  .bar { height:6px; border-radius:3px; background:#26314a; overflow:hidden; }
  .bar > i { display:block; height:100%; background:var(--ok); }
  .bar > i.hot { background:var(--warn); } .bar > i.over{ background:var(--bad); }
  pre { white-space:pre-wrap; word-break:break-all; font-size:12px;
        background:#0d1322; border:1px solid var(--line); border-radius:7px;
        padding:8px; max-height:260px; overflow:auto; }
  .tag { padding:1px 7px; border-radius:10px; font-size:11px; }
  .tag.ok{background:#11351d;color:var(--ok);} .tag.off{background:#3a2424;color:var(--bad);}
  .tag.frz{background:#3a3220;color:var(--warn);}
  .tag.run{background:#1d2b45;color:#7fb0ff;} .tag.done{background:#11351d;color:var(--ok);}
  .tag.exp{background:#3a2424;color:var(--bad);} .tag.cnf{background:#3a2a12;color:var(--warn);}
  #msg { min-height:18px; font-size:12px; color:var(--muted); }
  #msg.err{color:var(--bad);} #msg.good{color:var(--ok);}
</style>
</head>
<body>
<header>
  <h1>DP Gateway</h1>
  <input id="token" type="password" placeholder="管理员令牌 (dpa_…)">
  <button onclick="saveToken()">保存令牌</button>
  <button class="ghost" onclick="loadAll()">刷新</button>
  <span id="msg"></span>
</header>
<div id="freezeBanner" style="display:none;background:#3a1414;color:#ff8b8b;
     padding:10px 20px;border-bottom:1px solid var(--bad);font-weight:600"></div>
<main>
  <section class="card">
    <h2>团队</h2>
    <div class="row">
      <label>名称 <input id="teamName"></label>
      <button onclick="createTeam()">创建团队</button>
    </div>
    <table><thead><tr><th>team_id</th><th>名称</th><th>创建时间</th></tr></thead>
      <tbody id="teams"></tbody></table>
  </section>

  <section class="card">
    <h2>快照</h2>
    <div class="row">
      <label>快照目录绝对路径 <input id="snapPath" style="width:260px"></label>
      <button onclick="publishSnapshot()">发布</button>
    </div>
    <table><thead><tr><th>snapshot_id</th><th>名称@版本</th><th>状态</th><th>发布于</th><th></th></tr></thead>
      <tbody id="snaps"></tbody></table>
  </section>

  <section class="card wide">
    <h2>隐私预算</h2>
    <div class="row">
      <label>团队 <select id="bTeam"></select></label>
      <label>快照 <select id="bSnap"></select></label>
      <label>ε 上限 <input id="bEps" type="number" step="0.1" value="1.0" style="width:110px"></label>
      <label>δ 上限 <input id="bDelta" type="number" step="0.0000001" value="0" style="width:140px"></label>
      <button onclick="allocateBudget()">划拨 / 调整</button>
    </div>
    <table><thead><tr><th>团队</th><th>快照</th><th>ε 已用/上限</th><th>δ 已用/上限</th><th>占用</th></tr></thead>
      <tbody id="budgets"></tbody></table>
  </section>

  <section class="card wide">
    <h2>查询族冻结</h2>
    <div class="row">
      <label>family_id（32位，来自 /v1/plan） <input id="fFamily" style="width:300px"></label>
      <label>范围 <select id="fScope">
        <option value="global">global</option>
        <option value="team">team</option>
        <option value="snapshot">snapshot</option>
        <option value="team_snapshot">team+snapshot</option></select></label>
      <label>team_id（可选） <input id="fTeam" style="width:150px"></label>
      <label>snapshot_id（可选） <input id="fSnap" style="width:150px"></label>
      <label>原因 <input id="fReason" style="width:200px"></label>
      <button onclick="freeze()">冻结</button>
    </div>
    <p style="color:var(--muted);font-size:12px;margin:4px 0">
      冻结只拒绝未执行的请求；已执行结果与审计保留。缓存命中（同一团队/快照/规范查询的重试）仍返回原结果且不再扣费。</p>
    <table><thead><tr><th>freeze_id</th><th>family_id</th><th>范围</th><th>对象</th><th>原因</th><th>时间</th><th></th></tr></thead>
      <tbody id="freezes"></tbody></table>
  </section>

  <section class="card wide">
    <h2>多语句分析作业（两阶段票据）</h2>
    <div class="row">
      <label>状态 <select id="jState">
        <option value="">全部</option>
        <option value="reserved">reserved（锁定中）</option>
        <option value="executing">executing</option>
        <option value="completed">completed</option>
        <option value="failed">failed</option>
        <option value="cancelled">cancelled</option>
        <option value="expired">expired</option></select></label>
      <label>team_id <input id="jTeam" style="width:160px"></label>
      <button class="ghost" onclick="loadJobs()">查询作业</button>
      <span style="color:var(--muted);font-size:12px">
        查看锁定 / 执行 / 取消 / 过期与冲突；取消或过期会归还尚未消费的 ε、δ</span>
    </div>
    <table><thead><tr><th>job_id</th><th>团队</th><th>request_key</th><th>状态</th>
      <th>语句</th><th>锁定 ε/δ</th><th>消费 ε/δ</th><th>创建</th><th>截止</th><th>完成/错误</th>
      </tr></thead><tbody id="jobs"></tbody></table>
  </section>

  <section class="card wide">
    <h2>额度锁定（budget holds）</h2>
    <table><thead><tr><th>来源</th><th>id</th><th>团队</th><th>快照</th><th>ε</th><th>δ</th>
      <th>状态</th><th>创建</th><th>截止</th></tr></thead>
      <tbody id="holds"></tbody></table>
  </section>

  <section class="card wide">
    <h2>联合发布批次（可修订版本谱系）</h2>
    <div class="row">
      <label>批次名称 <input id="pbName" style="width:170px"></label>
      <label>规格文件内容（statements JSON） <input id="pbBatch" style="width:260px"
             placeholder='{"statements":[...]}（同作业批文件）'></label>
      <label>最少团队数 <input id="pbMin" type="number" value="2" min="1" style="width:90px"></label>
      <label>封账时刻（ISO-8601） <input id="pbClose" style="width:200px"
             placeholder="2026-09-30T18:00:00Z"></label>
      <button onclick="createPub()">创建批次（v1）</button>
      <button class="ghost" onclick="loadPubs()">刷新</button>
    </div>
    <p style="color:var(--muted);font-size:12px;margin:4px 0">
      分析负责人固定统计口径、最少参与团队数与封账时刻；各团队在自己预算内登记/撤回。
      达到门槛封账只产生一个签名版本；重复登记不重复计费；迟到贡献须进入修订新版。
      修订只新建版本，旧版签名与谱系继续可验证。</p>
    <table><thead><tr><th>批次/版本</th><th>谱系</th><th>状态</th><th>参与/门槛</th>
      <th>口径哈希</th><th>创建</th><th>封账时刻</th><th>封账/作废</th><th>操作</th>
      </tr></thead><tbody id="pubs"></tbody></table>
  </section>

  <section class="card wide">
    <h2>批次参与登记 / 撤回（团队令牌）</h2>
    <div class="row">
      <label>团队令牌（dpt_…） <input id="pbTeamToken" type="password" style="width:260px"></label>
      <label>版本 id（pubv_…）或批次 id/名称 <input id="pbRef" style="width:180px"></label>
      <button onclick="pubRegister()">登记贡献</button>
      <button class="ghost" onclick="pubWithdraw()">撤回</button>
      <button class="ghost" onclick="pubGet()">查看参与状态 / 拒绝原因</button>
      <label>修订新版封账时刻 <input id="pbAmendClose" style="width:200px"
             placeholder="2026-10-07T18:00:00Z"></label>
      <button class="ghost" onclick="pubAmend()">修订（新建版本）</button>
    </div>
    <pre id="pubDetail" style="display:none"></pre>
  </section>

  <section class="card wide">
    <h2>受控共享包（按团队授权的字段裁剪分发）</h2>
    <div class="row">
      <label>发布版本（pubv_…） <input id="shRef" style="width:170px"></label>
      <label>受众 team_id <input id="shTeam" style="width:170px"></label>
      <label>字段白名单（逗号分隔，all=全集）
        <input id="shGrantFields" style="width:280px"
          placeholder="members.charged,receipts.values,…"></label>
      <button onclick="shareGrant()">设置白名单</button>
    </div>
    <div class="row">
      <label>裁剪字段（必须 ⊆ 白名单）
        <input id="shFields" style="width:280px"></label>
      <label>有效期秒 <input id="shTtl" type="number" value="604800"
        style="width:110px"></label>
      <button onclick="shareCreate()">创建共享包</button>
      <button class="ghost" onclick="loadShares()">刷新</button>
    </div>
    <p style="color:var(--muted);font-size:12px;margin:4px 0">
      签名绑定发布清单 manifest_digest、父版本摘要、受众团队、字段集与过期时间。
      重复创建/取回重放同一份包（同一 share_key、同一摘要），撤销后新取回一律拒绝，
      已下载文件仍可离线验签。受众不存在、字段越权、版本未封账/已作废或过期均不留半笔状态。</p>
    <table><thead><tr><th>share_id</th><th>发布版本</th><th>受众</th><th>字段</th>
      <th>状态</th><th>包摘要</th><th>创建/过期</th><th>操作</th>
      </tr></thead><tbody id="shares"></tbody></table>
  </section>

  <section class="card wide">
    <h2>共享包取回（团队令牌 + share_key）</h2>
    <div class="row">
      <label>团队令牌（dpt_…） <input id="shToken" type="password" style="width:240px"></label>
      <label>share_key（shk_…） <input id="shKey" type="password" style="width:300px"></label>
      <button onclick="shareFetch()">取回同一包</button>
    </div>
    <pre id="shPkg" style="display:none"></pre>
  </section>

  <section class="card wide">
    <h2>防分叉透明度账本（内容寻址叶子 + 单调 checkpoint）</h2>
    <div class="row">
      <span style="color:var(--muted);font-size:12px">最新高度
        <b id="tlSize">–</b>，根
        <code id="tlRoot" style="word-break:break-all"></code></span>
      <span id="tlFrozenTag"></span>
      <span style="color:var(--muted);font-size:12px">待补 outbox：
        <b id="tlPending">–</b></span>
      <button class="ghost" onclick="loadTransparency()">刷新</button>
    </div>
    <p style="color:var(--muted);font-size:12px;margin:4px 0">
      每次封账 / 作废 / 包签发 / 撤销都在同一业务事务写入 outbox，提交后按确定顺序追加一片叶子并签名新
      checkpoint；相同 event_key 重放返回原叶序号，载荷冲突拒绝。冻结后的封账/制包/撤销一律 423 失败且不改账。
      旧 checkpoint 到新 checkpoint 仅允许追加；两个同高度不同根的已签名 checkpoint 即分叉证据。</p>
    <div class="row">
      <label>叶序号 <input id="tlLeafIndex" style="width:90px" value="0"></label>
      <label>at 高度（留空=最新） <input id="tlAtSize" style="width:90px"></label>
      <button class="ghost" onclick="tlInclusion()">包含证明</button>
      <label style="flex:1 1 300px">event_key（release_sealed:pubv_… / share_issued:shr_… / …）
        <input id="tlEventKey" style="width:100%"></label>
      <button class="ghost" onclick="tlEventProof()">按事件取证明</button>
    </div>
    <div class="row">
      <label>一致性 old_size <input id="tlOldSize" type="number" style="width:90px" value="0"></label>
      <label>new_size（留空=最新） <input id="tlNewSize" style="width:90px"></label>
      <button class="ghost" onclick="tlConsistency()">相邻 checkpoint 一致性</button>
      <button class="danger" onclick="tlSubmitFork()">提交分叉证据并冻结</button>
    </div>
    <table><thead><tr><th>#</th><th>事件</th><th>subject</th><th>叶哈希</th><th>入册时间</th>
      </tr></thead><tbody id="tlLeaves"></tbody></table>
    <pre id="tlProof" style="display:none"></pre>
  </section>

  <section class="card wide">
    <h2>审计日志（最近）</h2>
    <div class="row">
      <label>family_id 过滤 <input id="aFamily" style="width:260px"></label>
      <label>team_id 过滤 <input id="aTeam" style="width:180px"></label>
      <button class="ghost" onclick="loadAudit()">查询</button>
    </div>
    <table><thead><tr><th>时间</th><th>动作</th><th>结果</th><th>团队</th><th>快照</th><th>ε</th><th>δ</th><th>family</th><th>详情</th></tr></thead>
      <tbody id="audit"></tbody></table>
  </section>
</main>

<script src="app.js"></script>
</body>
</html>
"""

APP_JS = r"""
const $ = (id) => document.getElementById(id);
function token() { return localStorage.getItem("dpgw_admin_token") || ""; }
function saveToken() { localStorage.setItem("dpgw_admin_token", $("token").value.trim()); loadAll(); }
$("token").value = token();

function msg(text, kind) {
  const m = $("msg"); m.textContent = text || ""; m.className = kind || "";
}

async function api(method, path, body) {
  const opt = { method, headers: { "Authorization": "Bearer " + token() } };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json";
                            opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error + ": " + (data.message || ""));
  return data;
}

function esc(s) { return String(s ?? "").replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function short(s, n=14) { s = String(s ?? ""); return s.length > n ? s.slice(0,n)+"…" : s; }

async function loadTeams() {
  const d = await api("GET", "/v1/admin/teams");
  $("teams").innerHTML = d.teams.map(t =>
    `<tr><td title="${esc(t.team_id)}">${short(t.team_id,16)}</td><td>${esc(t.name)}</td>
     <td>${esc(t.created_at)}</td></tr>`).join("");
  const prev = $("bTeam").value;
  $("bTeam").innerHTML = d.teams.map(t =>
    `<option value="${t.team_id}">${esc(t.name)} (${short(t.team_id,10)})</option>`).join("");
  $("fTeam").value = prev && d.teams.some(t => t.team_id === prev) ? prev : "";
  if (!d.teams.some(t => t.team_id === $("bTeam").value) && d.teams[0])
    $("bTeam").value = d.teams[0].team_id;
  $("aTeam").innerHTML = `<option value=""></option>` +
    d.teams.map(t => `<option value="${t.team_id}">${esc(t.name)}</option>`).join("");
}

async function loadSnaps() {
  const d = await api("GET", "/v1/admin/snapshots");
  $("snaps").innerHTML = d.snapshots.map(s =>
    `<tr><td title="${esc(s.snapshot_id)}">${short(s.snapshot_id)}</td>
     <td>${esc(s.name)}@${esc(s.version)}</td>
     <td><span class="tag ${s.active ? "ok" : "off"}">${s.active ? "active" : "inactive"}</span></td>
     <td>${esc(s.published_at)}</td>
     <td><button class="ghost" onclick="toggleSnap('${s.snapshot_id}', ${s.active ? 0 : 1})">
         ${s.active ? "停用（版本替换）" : "重新启用"}</button></td></tr>`).join("");
  $("bSnap").innerHTML = d.snapshots.map(s =>
    `<option value="${s.snapshot_id}">${esc(s.name)}@${esc(s.version)}</option>`).join("");
  $("fSnap").innerHTML = `<option value=""></option>` +
    d.snapshots.map(s => `<option value="${s.snapshot_id}">${esc(s.name)}@${esc(s.version)}</option>`).join("");
}

async function toggleSnap(id, active) {
  try { await api("POST", `/v1/admin/snapshots/${id}/active`, { active: !!active });
        msg("快照状态已更新；旧缓存仍可凭收据验证，但不能在旧版本上产生新扣费", "good");
        loadAll(); } catch (e) { msg(e.message, "err"); }
}

async function loadBudgets() {
  const d = await api("GET", "/v1/admin/budgets");
  const teams = Object.fromEntries([...$("bTeam").options].map(o => [o.value, o.textContent]));
  $("budgets").innerHTML = d.budgets.map(b => {
    const pct = Math.min(100, 100 * b.epsilon_spent / b.epsilon_limit);
    const cls = pct > 95 ? "over" : pct > 70 ? "hot" : "";
    return `<tr><td>${esc(teams[b.team_id] || short(b.team_id))}</td>
      <td title="${esc(b.snapshot_id)}">${short(b.snapshot_id)}</td>
      <td>${b.epsilon_spent.toFixed(4)} / ${b.epsilon_limit}</td>
      <td>${b.delta_spent.toExponential(2)} / ${b.delta_limit.toExponential(2)}</td>
      <td><div class="bar"><i class="${cls}" style="width:${pct}%"></i></div></td></tr>`;
  }).join("");
}

async function createTeam() {
  try { const d = await api("POST", "/v1/admin/teams", { name: $("teamName").value.trim() });
        msg("团队已创建，分析者令牌（仅显示一次）: " + d.token, "good");
        $("teamName").value = ""; loadAll();
  } catch (e) { msg(e.message, "err"); }
}

async function publishSnapshot() {
  try { const d = await api("POST", "/v1/admin/snapshots/publish",
        { path: $("snapPath").value.trim(), active: true });
        msg("已发布 " + d.name + "@" + d.version + " id=" + d.snapshot_id, "good");
        loadAll();
  } catch (e) { msg(e.message, "err"); }
}

async function allocateBudget() {
  try { await api("POST", "/v1/admin/budgets", {
      team_id: $("bTeam").value, snapshot_id: $("bSnap").value,
      epsilon: parseFloat($("bEps").value), delta: parseFloat($("bDelta").value || "0") });
    msg("预算已划拨/调整（不可低于已消耗量）", "good"); loadBudgets();
  } catch (e) { msg(e.message, "err"); }
}

async function loadFreezes() {
  const d = await api("GET", "/v1/admin/freezes");
  $("freezes").innerHTML = d.freezes.map(f =>
    `<tr><td>${short(f.freeze_id,12)}</td><td title="${esc(f.family_id)}">${short(f.family_id)}</td>
     <td><span class="tag frz">${esc(f.scope)}</span></td>
     <td>${esc(f.team_id || "")} ${f.snapshot_id ? short(f.snapshot_id) : ""}</td>
     <td>${esc(f.reason)}</td><td>${esc(f.created_at)}</td>
     <td><button class="danger" onclick="unfreeze('${f.freeze_id}')">解冻</button></td></tr>`).join("");
}

async function freeze() {
  const body = { family_id: $("fFamily").value.trim(), scope: $("fScope").value,
                 reason: $("fReason").value.trim() };
  if ($("fTeam").value.trim()) body.team_id = $("fTeam").value.trim();
  if ($("fSnap").value) body.snapshot_id = $("fSnap").value;
  try { await api("POST", "/v1/admin/freezes", body);
        msg("查询族已冻结：该族未执行请求一律拒绝；历史结果与审计保留", "good");
        $("fFamily").value = ""; loadFreezes();
  } catch (e) { msg(e.message, "err"); }
}

async function unfreeze(id) {
  try { await api("DELETE", "/v1/admin/freezes/" + id); loadFreezes(); }
  catch (e) { msg(e.message, "err"); }
}

async function loadAudit() {
  const q = new URLSearchParams();
  if ($("aFamily").value.trim()) q.set("family_id", $("aFamily").value.trim());
  if ($("aTeam").value) q.set("team_id", $("aTeam").value);
  const d = await api("GET", "/v1/admin/audit?" + q.toString());
  $("audit").innerHTML = d.audit.map(a =>
    `<tr><td>${esc(a.ts)}</td><td>${esc(a.action)}</td><td>${esc(a.outcome)}</td>
     <td>${a.team_id ? short(a.team_id) : ""}</td><td>${a.snapshot_id ? short(a.snapshot_id) : ""}</td>
     <td>${a.epsilon ?? ""}</td><td>${a.delta ?? ""}</td>
     <td>${a.family_id ? short(a.family_id) : ""}</td>
     <td>${a.detail ? esc(JSON.stringify(a.detail)) : ""}</td></tr>`).join("");
}

const JOB_TAGS = { reserved:["run","锁定中"], executing:["run","执行中"],
  completed:["done","完成"], failed:["exp","失败"], cancelled:["cnf","取消"],
  expired:["exp","过期"] };

async function loadJobs() {
  if (!token()) return;
  const q = new URLSearchParams();
  if ($("jState").value) q.set("state", $("jState").value);
  if ($("jTeam").value.trim()) q.set("team_id", $("jTeam").value.trim());
  const d = await api("GET", "/v1/admin/jobs?" + q.toString());
  $("jobs").innerHTML = d.jobs.map(j => {
    const [cls, label] = JOB_TAGS[j.state] || ["cnf", j.state];
    const end = j.error_code
      ? `<span class="tag exp">${esc(j.error_code)}</span> ${esc(j.error_message || "")}`
      : esc(j.finished_at || "");
    return `<tr><td title="${esc(j.job_id)}">${short(j.job_id,18)}</td>
      <td>${short(j.team_id,12)}</td><td title="${esc(j.request_key)}">${short(j.request_key,14)}</td>
      <td><span class="tag ${cls}">${label}</span></td>
      <td>${j.statement_count}</td>
      <td>${(j.epsilon_reserved||0).toFixed(4)} / ${(j.delta_reserved||0).toExponential(1)}</td>
      <td>${(j.epsilon_consumed||0).toFixed(4)} / ${(j.delta_consumed||0).toExponential(1)}</td>
      <td>${esc(j.created_at)}</td><td>${esc(j.expires_at)}</td><td>${end}</td></tr>`;
  }).join("");
}

async function loadHolds() {
  const [jh, ph] = await Promise.all([
    api("GET", "/v1/admin/holds"), api("GET", "/v1/admin/publications/holds")]);
  const rows = [
    ...jh.holds.map(h => ({src:"作业", id:h.job_id, team:h.team_id, snap:h.snapshot_id,
      e:h.epsilon, d:h.delta, state:h.state, created:h.created_at, until:h.expires_at})),
    ...ph.holds.map(h => ({src:"批次", id:h.version_id, team:h.team_id, snap:h.snapshot_id,
      e:h.epsilon, d:h.delta, state:h.batch_name + " (" + h.state + ")",
      created:h.created_at, until:h.close_at})),
  ];
  $("holds").innerHTML = rows.map(h =>
    `<tr><td><span class="tag ${h.src==="批次"?"frz":"run"}">${h.src}</span></td>
     <td title="${esc(h.id)}">${short(h.id,18)}</td>
     <td>${short(h.team,12)}</td><td title="${esc(h.snap)}">${short(h.snap)}</td>
     <td>${h.e.toFixed(4)}</td><td>${h.d.toExponential(1)}</td>
     <td><span class="tag run">${esc(h.state)}</span></td>
     <td>${esc(h.created)}</td><td>${esc(h.until)}</td></tr>`).join("");
}

const PUB_TAGS = { collecting:["run","登记中"], sealed:["done","已封账"], void:["exp","已作废"] };

async function loadPubs() {
  if (!token()) return;
  const d = await api("GET", "/v1/admin/publications");
  $("pubs").innerHTML = d.publications.map(p => {
    const [cls, label] = PUB_TAGS[p.state] || ["cnf", p.state];
    const lineage = p.seq + (p.parent_version_id ? " ← " + short(p.parent_version_id, 10) : " (原版)");
    const end = p.sealed_at || p.voided_at || "";
    const ops = p.state === "collecting"
      ? `<button onclick="sealPub('${p.version_id}')">封账发布</button>
         <button class="ghost" onclick="voidPub('${p.version_id}')">作废</button>`
      : `<button class="ghost" onclick="amendPub('${p.version_id}')">修订新版</button>`;
    return `<tr><td>${esc(p.batch_name)}<br><span title="${esc(p.version_id)}">${short(p.version_id,16)}</span></td>
      <td>${esc(lineage)}</td>
      <td><span class="tag ${cls}">${label}</span></td>
      <td>${p.participant_count}/${p.min_participants}
          ${p.quorum_met ? '<span class="tag done">达标</span>' : '<span class="tag exp">不足</span>'}</td>
      <td title="${esc(p.manifest_digest||"")}">${short(p.spec_hash,10)}</td>
      <td>${esc(p.created_at)}</td><td>${esc(p.close_at)}</td><td>${esc(end)}</td>
      <td style="white-space:nowrap">${ops}</td></tr>`;
  }).join("");
}

async function createPub() {
  let statements;
  try { statements = JSON.parse($("pbBatch").value).statements; }
  catch (e) { msg("规格文件必须是包含 statements 数组的 JSON", "err"); return; }
  try {
    const d = await api("POST", "/v1/admin/publications", {
      name: $("pbName").value.trim(), statements,
      min_participants: parseInt($("pbMin").value, 10),
      close_at: $("pbClose").value.trim() });
    msg("批次已创建，版本 " + d.version_id, "good");
    loadPubs();
  } catch (e) { msg(e.message, "err"); }
}

async function sealPub(vid) {
  try { const d = await api("POST", `/v1/admin/publications/${vid}/seal`, {});
        msg("已封账发布：v" + d.seq + "，签名摘要 " + short(d.manifest_digest, 16), "good");
        loadAll();
  } catch (e) { msg("封账被拒绝（批次与账本保持原状）：" + e.message, "err"); }
}

async function voidPub(vid) {
  try { await api("POST", `/v1/admin/publications/${vid}/void`, {});
        msg("版本已作废，全部预算锁已归还", "good"); loadAll();
  } catch (e) { msg(e.message, "err"); }
}

function amendPub(vid) {
  const close = prompt("新版封账时刻（ISO-8601，例如 2026-10-07T18:00:00Z）");
  if (!close) return;
  api("POST", `/v1/admin/publications/${vid}/amend`, { close_at: close })
    .then(d => { msg("已创建修订版本 v" + d.seq + "，口径不变，旧版仍可验证", "good");
                 loadAll(); })
    .catch(e => msg(e.message, "err"));
}

async function teamApi(method, path) {
  const t = $("pbTeamToken").value.trim();
  const r = await fetch(path, { method,
    headers: { "Authorization": "Bearer " + t, "Content-Type": "application/json" },
    body: "{}" });
  return r.json().catch(() => ({}));
}

async function pubRegister() {
  const ref = $("pbRef").value.trim();
  const d = await teamApi("POST", `/v1/publications/${encodeURIComponent(ref)}/register`);
  if (d.error) { msg("登记被拒绝：" + d.message, "err"); return; }
  msg(`登记成功（${d.registration}），参与团队 ${d.participant_count}/${d.min_participants}` +
      (d.quorum_met ? "，已达门槛" : ""), "good");
  showPubDetail(d); loadHolds();
}

async function pubWithdraw() {
  const ref = $("pbRef").value.trim();
  const d = await teamApi("POST", `/v1/publications/${encodeURIComponent(ref)}/withdraw`);
  if (d.error) { msg("撤回失败：" + d.message, "err"); return; }
  msg(`已撤回（${d.registration}），预算锁已归还`, "good");
  showPubDetail(d); loadHolds();
}

async function pubGet() {
  const ref = $("pbRef").value.trim();
  const t = $("pbTeamToken").value.trim();
  const r = await fetch(`/v1/publications/${encodeURIComponent(ref)}`,
    { headers: { "Authorization": "Bearer " + t } });
  const d = await r.json().catch(() => ({}));
  if (d.error) { msg(d.message, "err"); return; }
  showPubDetail(d);
}

function showPubDetail(d) {
  const view = {
    batch: d.batch_name, version: d.version_id, seq: d.seq, state: d.state,
    participant_count: d.participant_count, min_participants: d.min_participants,
    close_at: d.close_at, manifest_digest: d.manifest_digest,
    participants: d.participants,
    rejections: (d.rejections || []).map(r => ({
      ts: r.ts, outcome: r.outcome, team: r.team_id,
      reason: r.detail && r.detail.message, error: r.detail && r.detail.error})),
  };
  $("pubDetail").style.display = "block";
  $("pubDetail").textContent = JSON.stringify(view, null, 2);
}

async function pubAmend() {
  const ref = $("pbRef").value.trim();
  const close = $("pbAmendClose").value.trim();
  try {
    const d = await api("POST", `/v1/admin/publications/${encodeURIComponent(ref)}/amend`,
      { close_at: close });
    msg("已创建修订版本 v" + d.seq + "，口径不变，旧版仍可验证", "good");
    $("pbRef").value = d.version_id; loadAll();
  } catch (e) { msg(e.message, "err"); }
}

const SHARE_TAGS = { creating:["run","生成中"], sealed:["done","可用"],
  revoked:["exp","已撤销"], failed:["cnf","已终止"] };

async function loadShares() {
  if (!token()) return;
  const d = await api("GET", "/v1/admin/shares");
  $("shares").innerHTML = d.shares.map(s => {
    const [cls, label] = SHARE_TAGS[s.state] || ["cnf", s.state];
    const ops = s.state === "sealed"
      ? `<button class="ghost" onclick="shareReveal('${s.share_id}')">查看 share_key</button>
         <button class="danger" onclick="shareRevoke('${s.share_id}')">撤销</button>`
      : (s.state === "creating"
         ? `<button class="ghost" onclick="shareRecover()">恢复未完成申请</button>` : "");
    return `<tr><td title="${esc(s.share_id)}">${short(s.share_id,18)}</td>
      <td title="${esc(s.version_id)}">${short(s.version_id,16)}</td>
      <td title="${esc(s.team_id)}">${short(s.team_id,14)}</td>
      <td style="max-width:260px">${esc((s.fields||[]).join(", "))}</td>
      <td><span class="tag ${cls}">${label}</span>${s.expired ? ' <span class="tag exp">已过期</span>' : ""}</td>
      <td title="${esc(s.package_digest||"")}">${short(s.package_digest||"",14)}</td>
      <td>${esc(s.created_at)}<br>${esc(s.expires_at)}</td>
      <td style="white-space:nowrap">${ops}</td></tr>`;
  }).join("");
}

async function shareGrant() {
  try {
    const fields = $("shGrantFields").value.trim() === "all"
      ? ["statements","participants","members","receipts"]
      : $("shGrantFields").value.split(",").map(s => s.trim()).filter(Boolean);
    await api("POST", "/v1/admin/share-grants", {
      ref: $("shRef").value.trim(), team_id: $("shTeam").value.trim(), fields });
    msg("字段白名单已设置（创建时字段必须在此集合内）", "good");
  } catch (e) { msg(e.message, "err"); }
}

async function shareCreate() {
  try {
    const fields = $("shFields").value.split(",").map(s => s.trim()).filter(Boolean);
    const d = await api("POST", "/v1/admin/shares", {
      ref: $("shRef").value.trim(), team_id: $("shTeam").value.trim(), fields,
      ttl_seconds: parseInt($("shTtl").value, 10) });
    msg("共享包已生成（share_key 仅此一次完整显示）: " + d.share_key, "good");
    loadShares();
  } catch (e) { msg("创建被拒绝，未留下半笔状态：" + e.message, "err"); }
}

async function shareReveal(id) {
  try { const d = await api("GET", `/v1/admin/shares/${id}?reveal_key=1`);
        msg("share_key: " + d.share_key, "good"); }
  catch (e) { msg(e.message, "err"); }
}

async function shareRevoke(id) {
  if (!confirm("撤销后新的取回将被拒绝（已下载文件仍可离线验签）。确认？")) return;
  try { await api("POST", `/v1/admin/shares/${id}/revoke`, { reason: "admin UI" });
        msg("已撤销；新取回一律 410 拒绝", "good"); loadShares(); }
  catch (e) { msg(e.message, "err"); }
}

async function shareRecover() {
  try { const d = await api("POST", "/v1/admin/shares/recover", {});
        msg("未完成申请已恢复或安全终止: " + JSON.stringify(d), "good"); loadShares(); }
  catch (e) { msg(e.message, "err"); }
}

async function shareFetch() {
  const t = $("shToken").value.trim();
  const r = await fetch("/v1/shares/fetch", {
    method: "POST",
    headers: { "Authorization": "Bearer " + t, "Content-Type": "application/json" },
    body: JSON.stringify({ share_key: $("shKey").value.trim() }) });
  const d = await r.json().catch(() => ({}));
  if (d.error) { msg(`取回被拒绝（${d.error}）：${d.message}`, "err"); return; }
  msg(`取回到同一包：share ${short(d.share_id,14)}，过期 ${d.expires_at}`, "good");
  $("shPkg").style.display = "block";
  $("shPkg").textContent = JSON.stringify(d, null, 2);
}

async function loadAll() {
  if (!token()) { msg("请先输入管理员令牌", "err"); return; }
  try {
    await loadTeams(); await loadSnaps(); await loadBudgets();
    await loadFreezes(); await loadJobs(); await loadHolds(); await loadPubs();
    await loadShares(); await loadTransparency();
    await loadAudit();
    msg("已刷新", "good");
  } catch (e) { msg(e.message, "err"); }
}

// ---------------------------------------------------------------------
// anti-fork transparency ledger
// ---------------------------------------------------------------------

const TL_TAGS = {
  release_sealed: "封账", release_voided: "作废",
  share_issued: "包签发", share_revoked: "包撤销"
};

async function loadTransparency() {
  if (!token()) return;
  const d = await api("GET", "/v1/transparency");
  $("tlSize").textContent = d.tree_size;
  $("tlRoot").textContent = d.root_hash;
  $("tlPending").textContent = d.pending_outbox;
  const banner = $("freezeBanner");
  if (d.frozen) {
    banner.style.display = "block";
    banner.textContent = `透明度账本已冻结（${d.freeze_reason}，高度 ${d.frozen_tree_size}，`
      + `${d.frozen_at} by ${d.frozen_by}）：封账 / 作废 / 制包 / 撤销均被拒绝，既有账本只读可验证。`;
    $("tlFrozenTag").innerHTML = '<span class="tag exp">已冻结</span>';
  } else {
    banner.style.display = "none";
    $("tlFrozenTag").innerHTML = '<span class="tag done">追加中</span>';
  }
  const leaves = await api("GET", "/v1/transparency/leaves");
  $("tlLeaves").innerHTML = leaves.leaves.map(l =>
    `<tr><td>${l.leaf_index}</td>
     <td><span class="tag run">${esc(TL_TAGS[l.event_type] || l.event_type)}</span></td>
     <td title="${esc(l.event_key)}">${short(l.event_key.replace(/^[^:]+:/, ""), 20)}</td>
     <td title="${esc(l.leaf_hash)}">${short(l.leaf_hash, 14)}</td>
     <td>${esc(l.incorporated_at)}</td></tr>`).join("");
}

function showTlProof(title, d) {
  $("tlProof").style.display = "block";
  $("tlProof").textContent = title + "\n\n" + JSON.stringify(d, null, 2);
}

async function tlInclusion() {
  try {
    const idx = parseInt($("tlLeafIndex").value, 10);
    const at = $("tlAtSize").value.trim();
    const d = await api("GET",
      `/v1/transparency/inclusion/${idx}` + (at ? `?tree_size=${at}` : ""));
    showTlProof(`叶 ${idx} 的包含证明（折到 ${d.tree_size} 高度根）`, d);
  } catch (e) { msg(e.message, "err"); }
}

async function tlEventProof() {
  try {
    const key = encodeURIComponent($("tlEventKey").value.trim());
    const at = $("tlAtSize").value.trim();
    const d = await api("GET", `/v1/transparency/events/${key}`
      + (at ? `?tree_size=${at}` : ""));
    $("tlLeafIndex").value = d.leaf_index;
    showTlProof(`事件 ${d.event_key} → 叶 ${d.leaf_index} 的包含证明`, d);
  } catch (e) { msg(e.message, "err"); }
}

async function tlConsistency() {
  try {
    const m = parseInt($("tlOldSize").value, 10);
    const nv = $("tlNewSize").value.trim();
    const d = await api("GET", `/v1/transparency/consistency?old_size=${m}`
      + (nv ? `&new_size=${nv}` : ""));
    showTlProof(`追加一致性 ${d.old_size} → ${d.new_size}`, d);
  } catch (e) { msg(e.message, "err"); }
}

async function tlSubmitFork() {
  const raw = prompt("粘贴两个同高度不同根的已签名 checkpoint（JSON 数组 "
    + "[checkpointA, checkpointB]）：");
  if (!raw) return;
  let pair;
  try { pair = JSON.parse(raw); }
  catch (e) { msg("分叉证据必须是 JSON 数组", "err"); return; }
  if (!Array.isArray(pair) || pair.length !== 2) {
    msg("需要恰好两个 checkpoint", "err"); return;
  }
  if (!confirm("确认分叉证据有效？提交后将冻结所有后续签发，且不可在 UI 解除。")) return;
  try {
    const d = await api("POST", "/v1/admin/transparency/fork",
      { first: pair[0], second: pair[1], reason: "admin UI" });
    msg("账本已冻结：" + d.reason + " @ 高度 " + d.tree_size, "err");
    loadTransparency();
  } catch (e) { msg("分叉证据被拒绝（账本未改动）：" + e.message, "err"); }
}
loadAll();
setInterval(() => {}, 0);
"""

UI_ASSETS = {
    "index.html": INDEX_HTML,
    "app.js": APP_JS,
}
