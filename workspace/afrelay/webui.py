"""零依赖运维单页（/ui）。

展示镜像高度、上游观察高度/冻结、停止原因、各租户位点/积压/租约持有者/
重试次数、拒绝原因统计与最近事件；支持管理员触发立即同步、停用/创建租户。
纯原生 HTML/JS，单文件内嵌。
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
    <h2>审计租户：位点 / 积压 / 租约持有者 / 重试</h2>
    <table><thead><tr>
      <th>租户</th><th>状态</th><th class="num">位点末端</th>
      <th class="num">镜像高</th><th class="num">原始积压</th>
      <th class="num">匹配积压</th><th>当前租约</th><th class="num">重试</th>
      <th>筛选</th><th></th>
    </tr></thead><tbody id="tenants"></tbody></table>
  </section>
  <section class="card">
    <h2>新建租户</h2>
    <label>tenant_id</label><input id="nid" placeholder="auditor-a">
    <label>名称</label><input id="nname" placeholder="A 组审计员">
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
  document.getElementById('tenants').innerHTML = ts.map(t=>{
    const d = t.current_delivery;
    const lease = d ? `<div>${pill('leased to '+esc(d.lease_owner),'warn')}
        ${d.lease_expired?pill('已超时','bad'):''}
        <div class="muted mono">${esc(d.delivery_id)}<br>until ${iso(d.lease_expires_at)}</div></div>`
      : '<span class="muted">无在途包</span>';
    const f = JSON.stringify(t.filter);
    return `<tr>
      <td><b>${esc(t.tenant_id)}</b><br><span class="muted">${esc(t.name)}</span></td>
      <td>${t.active?pill('active','ok'):pill('已停用','bad')}
          ${t.filter_locked?pill('规则已锁定','warn'):''}</td>
      <td class="num">${t.cursor_end}</td>
      <td class="num">${t.mirror_tree_size}</td>
      <td class="num">${t.backlog}</td>
      <td class="num">${t.backlog_matching}</td>
      <td>${lease}</td>
      <td class="num">${d?d.retries:0}</td>
      <td class="mono" style="max-width:210px">${esc(f)}</td>
      <td>${t.active?`<button class="danger" onclick="deact('${esc(t.tenant_id)}')">停用</button>`:''}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" class="muted">尚无租户</td></tr>';
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
    const r = await api('/v1/admin/tenants', {method:'POST',
      body:JSON.stringify({tenant_id:document.getElementById('nid').value.trim(),
        name:document.getElementById('nname').value.trim(), filter})});
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
