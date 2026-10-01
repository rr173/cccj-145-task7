"""零依赖运维单页（/ui）。

展示每个租户的窗口大小/在途上限/连续提交屏障/高水位/空洞、逐窗口区间/
持有者/完成状态/租约 epoch/重试次数、拒绝原因统计与最近事件（领取、
超时接管、乱序完成、补洞推进屏障、收缩、停用等）。纯原生 HTML/JS。
"""

from __future__ import annotations

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>并行窗口中继 · 运维台</title>
<style>
  :root { --bg:#0f1420; --card:#1a2233; --line:#2a3450; --fg:#e6ecf7;
          --muted:#8b97b0; --ok:#3ddc84; --warn:#ffb020; --bad:#ff5d5d;
          --accent:#5aa7ff; --hole:#ff8f3f; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,"PingFang SC",
         "Microsoft YaHei",sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:16px 22px; border-bottom:1px solid var(--line);
           display:flex; gap:14px; align-items:center; flex-wrap:wrap; }
  h1 { font-size:17px; margin:0; }
  main { padding:20px; display:grid; gap:16px;
         grid-template-columns:repeat(auto-fit,minmax(420px,1fr)); }
  .card { background:var(--card); border:1px solid var(--line);
          border-radius:10px; padding:16px 18px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em;
             color:var(--muted); margin:0 0 12px; }
  .pill { display:inline-block; padding:1px 8px; border-radius:999px;
          font-size:12px; border:1px solid var(--line); }
  .ok { color:var(--ok); border-color:var(--ok); }
  .warn { color:var(--warn); border-color:var(--warn); }
  .bad { color:var(--bad); border-color:var(--bad); }
  .hole { color:var(--hole); border-color:var(--hole); }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th,td { text-align:left; padding:5px 7px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
  input,button,textarea,select {
    background:#101725; color:var(--fg); border:1px solid var(--line);
    border-radius:6px; padding:7px 9px; font:inherit; }
  button { cursor:pointer; background:var(--accent); color:#061226;
           border-color:var(--accent); font-weight:600; }
  button.ghost { background:transparent; color:var(--fg); }
  button.danger { background:transparent; color:var(--bad); border-color:var(--bad); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .events { font-size:12px; max-height:380px; overflow:auto; }
  .events .r { padding:5px 0; border-bottom:1px dashed var(--line); }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          font-size:12px; word-break:break-all; }
  .muted { color:var(--muted); }
  .span2 { grid-column:1 / -1; }
  label { font-size:12px; color:var(--muted); display:block; margin:6px 0 2px; }
  #msg { color:var(--warn); font-size:12px; }
  .bar { height:10px; border-radius:6px; background:#101725; overflow:hidden;
         display:flex; border:1px solid var(--line); margin:6px 0; }
  .seg { height:100%; }
  .seg.completed { background:var(--ok); }
  .seg.leased { background:var(--warn); }
  .seg.expired { background:var(--bad); }
  .seg.hole { background:repeating-linear-gradient(45deg,#3a2b1a,#3a2b1a 4px,
       var(--hole) 4px,var(--hole) 8px); }
  .seg.pending { background:#243049; }
  details summary { cursor:pointer; color:var(--accent); font-size:12.5px; }
</style>
</head>
<body>
<header>
  <h1>并行窗口中继 <span class="muted">parallel-window relay</span></h1>
  <input id="tok" type="password" placeholder="管理员令牌 afra_…" size="20">
  <button class="ghost" onclick="refresh()">刷新</button>
  <label class="row" style="margin:0"><input type="checkbox" id="auto"> 自动 2s</label>
  <span id="msg"></span>
</header>
<main>
  <section class="card span2">
    <h2>审计租户：连续提交屏障 / 高水位 / 空洞 / 在途上限</h2>
    <div id="tenants"></div>
  </section>
  <section class="card">
    <h2>拒绝原因（全租户）</h2>
    <div id="rejects" class="row"></div>
  </section>
  <section class="card">
    <h2>新建租户</h2>
    <div class="row">
      <input id="nid" placeholder="tenant_id">
      <input id="nname" placeholder="名称">
      <input id="nsize" type="number" value="64" style="width:90px" title="窗口字节数">
      <input id="ncap" type="number" value="4" style="width:80px" title="最大在途">
    </div>
    <label>筛选（JSON，留空匹配全部）</label>
    <textarea id="nfilter" rows="2" style="width:100%"></textarea>
    <div style="margin-top:8px"><button onclick="createTenant()">创建（返回一次性令牌）</button></div>
    <pre id="created" class="mono"></pre>
  </section>
  <section class="card span2">
    <h2>最近事件（领取 / 超时接管 / 乱序完成 / 补洞推进 / 收缩 / 停用）</h2>
    <div id="events" class="events mono"></div>
  </section>
</main>
<script>
let timer = null;
function token(){ return document.getElementById('tok').value.trim(); }
function hdr(){ return {'Authorization':'Bearer '+token(),
  'Content-Type':'application/json'}; }
function msg(s, bad){ const el=document.getElementById('msg');
  el.textContent=s||''; el.style.color=bad?'var(--bad)':'var(--warn)'; }
async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:hdr()}, opts||{}));
  const body = await r.json().catch(()=>({}));
  if(!r.ok) throw Object.assign(new Error(body.message||r.status),
    {status:r.status, code:body.error, body});
  return body;
}
function pill(text, cls){ return `<span class="pill ${cls||''}">${text}</span>`; }
function esc(s){ return String(s??'').replace(/[&<>]/g, c=>({'&':'&amp;',
  '<':'&lt;','>':'&gt;'}[c])); }
function iso(t){ return t ? new Date(t).toLocaleTimeString() : '—'; }

async function refresh(){
  try {
    const s = await api('/v1/admin/status');
    renderTenants(s.tenants); renderRejects(s.reject_counts);
    renderEvents(s.events); msg('');
  } catch(e){ msg(e.message||String(e), true); }
}

function statePill(w, curFv){
  if(w.state==='completed') return pill('completed','ok');
  if(w.state==='pending') return pill('pending','');
  if(w.lease_expired) return pill('leased·已超时','bad');
  if(w.filter_version!==curFv) return pill('leased·筛选过期','warn');
  return pill('leased','warn');
}

function windowTable(t){
  const curFv = t.filter_version;
  const rows = t.windows.map(w=>`<tr>
    <td class="num">#${w.seq}</td>
    <td class="num mono">${w.start_offset}–${w.end_offset}</td>
    <td>${statePill(w,curFv)}</td>
    <td>${w.holder?esc(w.holder):'—'}</td>
    <td class="num">${w.lease_epoch}</td>
    <td class="num">${w.retry_count}</td>
    <td class="num">${w.filter_version}</td>
    <td>${w.completed_by?esc(w.completed_by):'—'}</td>
    <td>${iso(w.completed_at)}</td>
  </tr>`).join('');
  return `<details><summary>窗口明细（${t.windows.length}/${t.available_windows} 已物化）</summary>
  <table style="margin-top:8px"><thead><tr>
    <th class="num">#</th><th class="num">区间 [start,end)</th><th>状态</th>
    <th>持有者</th><th class="num">epoch</th><th class="num">重试</th>
    <th class="num">筛选版</th><th>完成者</th><th>完成时刻</th>
  </tr></thead><tbody>${rows||
    '<tr><td colspan="9" class="muted">尚无窗口被领取物化</td></tr>'}</tbody></table>
  </details>`;
}

function barHtml(t){
  // 从屏障/空洞推一条色带：completed / leased / expired / hole / pending
  const n = Math.max(t.available_windows, t.windows.length);
  let seg = '';
  const bySeq = {}; t.windows.forEach(w=>bySeq[w.seq]=w);
  for(let i=0;i<n;i++){
    const w = bySeq[i];
    let cls='pending', title='#'+i;
    if(w){ title += ' '+w.start_offset+'-'+w.end_offset;
      if(w.state==='completed') cls='completed';
      else if(w.lease_expired) cls='expired';
      else if(w.state==='leased') cls='leased';
      if(w.holder) title += ' holder='+w.holder;
    }
    if(t.holes.includes(i) && !(w && w.state==='completed')) cls='hole';
    seg += `<div class="seg ${cls}" style="width:${100/Math.max(n,1)}%"
      title="${esc(title)}"></div>`;
  }
  return `<div class="bar">${seg}</div>`;
}

function renderTenants(ts){
  document.getElementById('tenants').innerHTML = ts.map(t=>{
    const active = pill('active','ok');
    const st = t.active ? active : pill('已停用','bad');
    const holeTxt = t.holes.length
      ? t.holes.slice(0,12).map(h=>pill('#'+h,'hole')).join(' ')
        + (t.holes.length>12?' …':'')
      : '<span class="muted">无</span>';
    const barrierAhead = t.high_water > t.commit_barrier;
    return `<div class="card" style="margin-bottom:14px">
      <div class="row" style="justify-content:space-between">
        <div><b>${esc(t.tenant_id)}</b>
          <span class="muted">${esc(t.name)}</span> ${st}</div>
        <div class="row">
          ${t.active?`<button class="danger" onclick="deact('${esc(t.tenant_id)}')">停用</button>`:''}
        </div>
      </div>
      ${barHtml(t)}
      <div class="row" style="margin:8px 0">
        <span>连续提交屏障 <b class="num">${t.commit_barrier}</b></span>
        ${barrierAhead?pill('高水位 '+t.high_water+'（屏障等待补洞）','hole'):
          pill('高水位 '+t.high_water,'ok')}
        <span class="muted">窗口大小 ${t.window_size} · 已封口 ${t.stream_sealed?
          '是':'否'} · 流长 ${t.stream_length}</span>
      </div>
      <div class="row" style="margin:6px 0">
        <span>最大在途 <b>${t.max_inflight}</b></span>
        <input id="cap-${esc(t.tenant_id)}" type="number" min="1"
          value="${t.max_inflight}" style="width:70px">
        <button class="ghost" onclick="setCap('${esc(t.tenant_id)}')">调整在途</button>
        <span class="muted">活动 ${t.active_inflight} · 超时 ${t.expired_inflight}
          · 已完成 ${t.completed_count}</span>
      </div>
      <div class="row" style="margin:6px 0">
        <span class="muted">空洞窗口：</span>${holeTxt}
      </div>
      <div class="row" style="margin:6px 0">
        <span class="muted">在途序号：</span>
        <span class="mono">${t.leased_window_seqs.length?
          t.leased_window_seqs.map(s=>'#'+s).join(' ') : '—'}</span>
        <span class="muted">· 筛选版 ${t.filter_version}</span>
      </div>
      ${windowTable(t)}
    </div>`;
  }).join('') || '<div class="muted">尚无租户</div>';
}

function renderRejects(rc){
  const keys = Object.keys(rc||{});
  document.getElementById('rejects').innerHTML = keys.length
    ? keys.map(k=>`<span class="pill bad">${esc(k)} × ${rc[k]}</span>`).join(' ')
    : '<span class="muted">无拒绝</span>';
}
function eventColor(k){
  if(k==='reject') return 'var(--bad)';
  if(k==='window_taken_over') return 'var(--bad)';
  if(k==='barrier_advanced'||k==='barrier_recovered') return 'var(--ok)';
  if(k==='window_completed') return 'var(--accent)';
  if(k==='max_inflight_changed'||k==='filter_updated') return 'var(--warn)';
  return 'inherit';
}
function renderEvents(ev){
  document.getElementById('events').innerHTML = (ev||[]).slice().reverse().map(e=>{
    return `<div class="r" style="color:${eventColor(e.kind)}">
      ${iso(e.created_at)} <b>${esc(e.kind)}</b>
      ${e.reason?pill(esc(e.reason),'bad'):''}
      ${e.tenant_id?esc(e.tenant_id):''}
      ${e.window_id?'<span class="muted">'+esc(e.window_id.slice(0,22))+'…</span>':''}
      <div class="muted" style="color:var(--muted)">${esc(JSON.stringify(e.detail))}</div></div>`;
  }).join('') || '<span class="muted">无事件</span>';
}

async function setCap(id){
  const v = parseInt(document.getElementById('cap-'+id).value,10);
  if(!(v>=1)){ msg('max_inflight 必须 >=1',true); return; }
  try { await api('/v1/admin/tenants/'+encodeURIComponent(id)+'/inflight',
    {method:'POST', body:JSON.stringify({max_inflight:v})});
    msg(v>=0?'在途上限已更新（不抢占有效持有者）':''); refresh();
  } catch(e){ msg(e.message,true); }
}
async function deact(id){
  const reason = prompt('停用原因（窗口历史与屏障保留，拒绝一切领取/提交）','');
  if(reason===null) return;
  try { await api('/v1/admin/tenants/'+encodeURIComponent(id)+'/deactivate',
    {method:'POST', body:JSON.stringify({reason})}); refresh();
  } catch(e){ msg(e.message,true); }
}
async function createTenant(){
  let filter = {};
  const t = document.getElementById('nfilter').value.trim();
  if(t){ try{ filter=JSON.parse(t); }catch(e){ msg('筛选 JSON 非法',true); return; } }
  const body = {tenant_id:document.getElementById('nid').value.trim(),
    name:document.getElementById('nname').value.trim(), filter,
    window_size:parseInt(document.getElementById('nsize').value,10),
    max_inflight:parseInt(document.getElementById('ncap').value,10)};
  try{
    const r = await api('/v1/admin/tenants', {method:'POST',
      body:JSON.stringify(body)});
    document.getElementById('created').textContent =
      '租户令牌（仅显示一次）：\n'+r.token;
    refresh();
  }catch(e){ msg(e.message,true); }
}
document.getElementById('auto').onchange = (e)=>{
  if(e.target.checked){ refresh(); timer=setInterval(refresh,2000); }
  else clearInterval(timer);
};
refresh();
</script>
</body>
</html>
"""

UI_ASSETS = {"index.html": INDEX_HTML}
