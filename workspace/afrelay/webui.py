"""零依赖运维单页（/ui）。

展示镜像高度、上游观察高度/冻结、停止原因；每个租户的**连续提交屏障**、
最大在途窗口数与在途数、每个**窗口**（相邻区间 [start,end)、持有者、
leased/completed/committed 状态、租约 epoch/到期/重试次数）、挡住屏障的
阻塞窗口与未覆盖空洞、拒绝原因、最近事件。支持管理员触发立即同步、
动态收缩/放大在途上限、强制窗口超时接管、停用/创建租户。纯原生 HTML/JS，
单文件内嵌。
"""

from __future__ import annotations

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>审计馈送中继 · 运维台</title>
<style>
  :root { --bg:#0f1420; --card:#1a2233; --line:#2a3450; --fg:#e6ecf7;
          --muted:#8b97b0; --ok:#3ddc84; --warn:#ffb020; --bad:#ff5d5d;
          --accent:#5aa7ff; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,"PingFang SC",
         "Microsoft YaHei",sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:16px 22px; border-bottom:1px solid var(--line);
           display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
  h1 { font-size:17px; margin:0; }
  main { padding:20px; display:grid; gap:16px;
         grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); }
  .card { background:var(--card); border:1px solid var(--line);
          border-radius:10px; padding:16px 18px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em;
             color:var(--muted); margin:0 0 12px; }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:4px 14px; }
  .kv dt { color:var(--muted); } .kv dd { margin:0; font-variant-numeric:tabular-nums; }
  .pill { display:inline-block; padding:1px 8px; border-radius:999px;
          font-size:12px; border:1px solid var(--line); }
  .ok { color:var(--ok); border-color:var(--ok); }
  .warn { color:var(--warn); border-color:var(--warn); }
  .bad { color:var(--bad); border-color:var(--bad); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
  input,select,button,textarea {
    background:#101725; color:var(--fg); border:1px solid var(--line);
    border-radius:6px; padding:7px 9px; font:inherit; }
  button { cursor:pointer; background:var(--accent); color:#061226;
           border-color:var(--accent); font-weight:600; }
  button.ghost { background:transparent; color:var(--fg); }
  button.danger { background:transparent; color:var(--bad); border-color:var(--bad); }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .events { font-size:12px; max-height:330px; overflow:auto; }
  .events .r { padding:5px 0; border-bottom:1px dashed var(--line); }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          font-size:12px; word-break:break-all; }
  .muted { color:var(--muted); }
  .span2 { grid-column:1 / -1; }
  .stack { display:flex; flex-direction:column; gap:12px; }
  .tblock { border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
  .tblock.head { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  .tblock .meta { color:var(--muted); font-size:12px; }
  .winbar { display:flex; gap:4px; flex-wrap:wrap; margin:8px 0; }
  .win { border:1px solid var(--line); border-radius:6px; padding:3px 8px;
         font-size:12px; font-variant-numeric:tabular-nums; }
  .win.leased { border-color:var(--warn); color:var(--warn); }
  .win.completed { border-color:var(--accent); color:var(--accent); }
  .win.committed { border-color:var(--ok); color:var(--ok); }
  .win .own { color:var(--muted); }
  .hole { border:1px dashed var(--bad); color:var(--bad); border-radius:6px;
          padding:3px 8px; font-size:12px; }
  label { font-size:12px; color:var(--muted); display:block; margin:6px 0 2px; }
  #msg { color:var(--warn); font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>审计馈送中继 <span class="muted">audit-feed relay</span></h1>
  <input id="tok" type="password" placeholder="管理员令牌 afra_…" size="22">
  <button onclick="syncNow()">立即同步</button>
  <button class="ghost" onclick="refresh()">刷新</button>
  <label class="row" style="margin:0"><input type="checkbox" id="auto"> 自动 3s</label>
  <span id="msg"></span>
</header>
<main>
  <section class="card">
    <h2>镜像与上游</h2>
    <dl class="kv" id="mirror"><dt class="muted">加载中…</dt><dd></dd></dl>
  </section>
  <section class="card">
    <h2>拒绝原因（全租户）</h2>
    <div id="rejects" class="row"></div>
  </section>
  <section class="card span2">
    <h2>审计租户：连续提交屏障 / 在途窗口 / 持有者 / 空洞 / 重试</h2>
    <div id="tenantblocks" class="stack"></div>
  </section>
  <section class="card">
    <h2>新建租户</h2>
    <label>tenant_id</label><input id="nid" placeholder="auditor-a">
    <label>名称</label><input id="nname" placeholder="A 组审计员">
    <label>最大在途窗口数（可之后动态收缩）</label>
    <input id="ninf" type="number" min="1" max="1024" value="8">
    <label>筛选（JSON，留空匹配全部）</label>
    <textarea id="nfilter" rows="3" style="width:100%"
      placeholder='{"event_types":["release_sealed","share_issued"]}'></textarea>
    <div style="margin-top:8px"><button onclick="createTenant()">创建（返回一次性令牌）</button></div>
    <pre id="created" class="mono"></pre>
  </section>
  <section class="card">
    <h2>最近事件</h2>
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
    renderMirror(s.mirror); renderRejects(s.reject_counts);
    renderTenants(s.tenants); renderEvents(s.events); msg('');
  } catch(e){ msg(e.message||String(e), true); }
}
function renderMirror(m){
  const stop = m.last_status==='stopped';
  const fr = m.upstream_frozen ? pill('上游已冻结 '+ (m.frozen_reason||''),'bad')
             : pill('上游追加中','ok');
  const st = stop ? pill('已停止：'+(m.last_stop_reason||''),'bad')
           : m.last_status.startsWith('caught') ? pill(m.last_status,'ok')
           : pill(m.last_status||'never','warn');
  document.getElementById('mirror').innerHTML = `
    <dt>状态</dt><dd>${st}</dd>
    <dt>最后可信树高</dt><dd><b>${m.trusted_tree_size}</b></dd>
    <dt>上游观察高度</dt><dd>${m.upstream_tree_size}</dd>
    <dt>上游冻结</dt><dd>${fr}${m.frozen_tree_size!=null?' @'+m.frozen_tree_size:''}</dd>
    <dt>连续失败</dt><dd>${m.consecutive_failures}</dd>
    <dt>最后错误</dt><dd class="mono">${esc(m.last_error||'—')}</dd>
    <dt>上次成功</dt><dd>${iso(m.last_success_at)}</dd>
    <dt>上次尝试</dt><dd>${iso(m.last_attempt_at)}</dd>`;
}
function renderRejects(rc){
  const keys = Object.keys(rc||{});
  document.getElementById('rejects').innerHTML = keys.length
    ? keys.map(k=>`<span class="pill bad">${esc(k)} × ${rc[k]}</span>`).join(' ')
    : '<span class="muted">无拒绝</span>';
}
function renderTenants(ts){
  document.getElementById('tenantblocks').innerHTML = ts.map(t=>{
    const id = esc(t.tenant_id);
    const acts = t.active
      ? `<button class="danger" onclick="deact('${id}')">停用</button>
         <button class="ghost" onclick="shrink('${id}')">调整在途上限</button>`
      : '';
    const wins = (t.windows||[]).map(w=>{
      const tip = `#${w.seq} [${w.start_index},${w.end_index}) owner=${esc(w.lease_owner)} `
        + `epoch=${w.lease_epoch} retries=${w.retries}`
        + (w.lease_expired?' EXPIRED':'');
      const fe = (t.active && w.state==='leased')
        ? ` <a href="#" title="强制该窗口立即超时，供新 worker 接管" `
          + `onclick="forceExpire('${id}','${esc(w.delivery_id)}');return false;">⏱</a>` : '';
      return `<span class="win ${w.state}" title="${tip}">`
        + `[${w.start_index},${w.end_index}) ${w.state}`
        + ` <span class="own">${esc(w.lease_owner||'')}×${w.retries}</span>${fe}</span>`;
    }).join('');
    const holes = (t.holes||[]).map(h=>
      `<span class="hole" title="未被窗口覆盖的原始序号空洞">`
      + `空洞 [${h.from},${h.to})</span>`).join('');
    const block = t.blocking_window
      ? pill('阻塞窗口 #'+t.blocking_window.seq+' ('
        +esc(t.blocking_window.lease_owner)+')','bad')
      : (t.inflight===0 ? pill('无在途窗口','ok')
                        : pill('窗口全部完成待补洞','warn'));
    return `<div class="tblock">
      <div class="head">
        <b>${id}</b> <span class="muted">${esc(t.name)}</span>
        ${t.active?pill('active','ok'):pill('已停用','bad')}
        ${t.filter_locked?pill('规则已锁定','warn'):''}
        ${block}
        <span class="meta">提交屏障 <b>${t.commit_barrier}</b></span>
        <span class="meta">在途 ${t.inflight}/${t.max_inflight}</span>
        <span class="meta">发放前沿 ${t.frontier} · 镜像高 ${t.mirror_tree_size}</span>
        <span class="meta">原始积压 ${t.backlog} · 匹配积压 ${t.backlog_matching}</span>
        <span style="flex:1"></span>${acts}
      </div>
      <div class="winbar">${wins}${holes||
        '<span class="muted">暂无在途窗口（已越过屏障的窗口被回收出在途集合）</span>'}</div>
      <div class="meta mono">筛选 ${esc(JSON.stringify(t.filter))}</div>
    </div>`;
  }).join('') || '<span class="muted">尚无租户</span>';
}
async function shrink(id){
  const v = prompt('设置租户 '+id+' 的最大在途窗口数（收缩不会抢走有效持有者）','1');
  if(v===null) return;
  const n = parseInt(v,10);
  if(!(n>=1)){ msg('需要正整数',true); return; }
  try{
    const r = await api('/v1/admin/tenants/'+encodeURIComponent(id)+
      '/max-inflight', {method:'POST', body:JSON.stringify({max_inflight:n})});
    msg(r.shrink_pending
      ? ('已收缩但有 '+r.inflight+' 个窗口仍在途：不抢占，等其提交')
      : ('上限已设为 '+r.max_inflight));
    refresh();
  }catch(e){ msg(e.message,true); }
}
async function forceExpire(id, did){
  if(!confirm('强制窗口 '+did.slice(0,16)+' 立即到期以便新 worker 接管？')) return;
  try{
    await api('/v1/admin/tenants/'+encodeURIComponent(id)+'/deliveries/'+
      encodeURIComponent(did)+'/force-expire',
      {method:'POST', body:JSON.stringify({reason:'ops'})});
    msg('窗口已可被接管，旧持有者提交将被拒绝'); refresh();
  }catch(e){ msg(e.message,true); }
}
function renderEvents(ev){
  document.getElementById('events').innerHTML = (ev||[]).slice().reverse().map(e=>{
    const bad = e.kind==='reject'||e.kind==='sync_stopped';
    return `<div class="r" style="color:${bad?'var(--bad)':'inherit'}">
      ${iso(e.created_at)} <b>${esc(e.kind)}</b>
      ${e.reason?pill(esc(e.reason),'bad'):''}
      ${e.tenant_id?esc(e.tenant_id):''} ${e.delivery_id?esc(e.delivery_id.slice(0,18)):''}
      <div class="muted">${esc(JSON.stringify(e.detail))}</div></div>`;
  }).join('') || '<span class="muted">无事件</span>';
}
async function syncNow(){
  try { msg('同步中…'); const r = await api('/v1/admin/sync',
    {method:'POST'});
    msg(r.ok?('已同步到 '+r.trusted_tree_size)
           :('停止：'+r.reason+' @ '+r.trusted_tree_size), !r.ok);
    refresh();
  } catch(e){ msg(e.message, true); }
}
async function deact(id){
  const reason = prompt('停用原因（租户位点保留，拒绝一切投递/确认）','');
  if(reason===null) return;
  try { await api('/v1/admin/tenants/'+encodeURIComponent(id)+'/deactivate',
    {method:'POST', body:JSON.stringify({reason})}); refresh();
  } catch(e){ msg(e.message,true); }
}
async function createTenant(){
  let filter = {};
  const t = document.getElementById('nfilter').value.trim();
  if(t){ try{ filter=JSON.parse(t); }catch(e){ msg('筛选 JSON 非法',true); return; } }
  try{
    const n = parseInt(document.getElementById('ninf').value,10);
    const r = await api('/v1/admin/tenants', {method:'POST',
      body:JSON.stringify({tenant_id:document.getElementById('nid').value.trim(),
        name:document.getElementById('nname').value.trim(),
        max_inflight:(n>=1?n:8), filter})});
    document.getElementById('created').textContent =
      '租户令牌（仅显示一次）：\n'+r.token;
    refresh();
  }catch(e){ msg(e.message,true); }
}
document.getElementById('auto').onchange = (e)=>{
  if(e.target.checked){ refresh(); timer=setInterval(refresh,3000); }
  else clearInterval(timer);
};
refresh();
</script>
</body>
</html>
"""

UI_ASSETS = {"index.html": INDEX_HTML}
