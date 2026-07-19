/* ═══════════════════════════════════════════════
   OwelSec AI — Frontend Application Logic
   ═══════════════════════════════════════════════ */

const API_BASE = (() => {
    if (window.location.protocol === 'file:') return 'http://127.0.0.1:5000';
    const u = new URL(window.location.origin); u.port = '5000'; return u.origin;
})();

let activePoller = null;
let currentScanId = null;
const $ = id => document.getElementById(id);

/* ── Matrix Rain ── */
(function(){
    const canvas = document.getElementById('matrix-canvas');
    if(!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, cols, drops;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$@#%&<>{}[]ｦｧｨｩｪｫｬｭｮｯアイウエオ';
    function init(){
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
        cols = Math.floor(W / 18);
        drops = Array(cols).fill(1);
    }
    function draw(){
        ctx.fillStyle = 'rgba(10,14,31,0.05)';
        ctx.fillRect(0,0,W,H);
        ctx.font = '13px Share Tech Mono';
        for(let i=0;i<drops.length;i++){
            const ch = chars[Math.floor(Math.random()*chars.length)];
            ctx.fillStyle = (drops[i]%12===0) ? '#ff3333' : '#5588ff';
            ctx.fillText(ch, i*18, drops[i]*18);
            if(drops[i]*18>H && Math.random()>0.975) drops[i]=0;
            drops[i]++;
        }
    }
    init();
    setInterval(draw, 50);
    window.addEventListener('resize', init);
})();

/* ── Live Clock ── */
(function(){
    function tick(){
        const el = $('live-time');
        if(!el) return;
        const n = new Date();
        el.textContent = n.toTimeString().slice(0,8) + ' UTC' +
            (n.getTimezoneOffset()>0?'-':'+') +
            (Math.abs(n.getTimezoneOffset())/60).toString().padStart(2,'0');
    }
    tick(); setInterval(tick, 1000);
})();

/* ── Session ID ── */
(function(){
    const el = $('session-id');
    if(el) el.textContent = 'SESSION: ' + Math.random().toString(36).substr(2,8).toUpperCase();
})();

/* ── Auth ── */
function getToken(){ return localStorage.getItem('strix_token'); }
function setToken(t){ localStorage.setItem('strix_token', t); }
function clearToken(){ localStorage.removeItem('strix_token'); }

function authHeaders(){
    return { 'Content-Type':'application/json', 'Authorization':'Bearer '+getToken() };
}

async function authFetch(url, opts={}){
    opts.headers = { ...authHeaders(), ...(opts.headers||{}) };
    const res = await fetch(url, opts);
    if(res.status===401){ clearToken(); showLogin(); throw new Error('Session expired'); }
    return res;
}

function showLogin(){
    $('loginOverlay').style.display = 'flex';
    $('appLayout').style.display = 'none';
}
function showApp(){
    $('loginOverlay').style.display = 'none';
    $('appLayout').style.display = 'flex';
    loadHistory();
}

async function doLogin(){
    const user = $('loginUser').value.trim();
    const pass = $('loginPass').value;
    $('loginError').textContent = '';
    if(!user||!pass){ $('loginError').textContent = '⚠ ENTER CREDENTIALS'; return; }
    try {
        const res = await fetch(`${API_BASE}/login`, {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ username:user, password:pass }),
        });
        const data = await res.json();
        if(!res.ok){ $('loginError').textContent = '⚠ '+(data.error||'ACCESS DENIED').toUpperCase(); return; }
        setToken(data.token);
        showApp();
    } catch(e){ $('loginError').textContent = '⚠ CONNECTION FAILED'; }
}

function doLogout(){
    clearToken();
    if(activePoller){clearInterval(activePoller);activePoller=null;}
    showLogin();
}

/* ── Navigation ── */
function switchNav(name){
    document.querySelectorAll('.nav-item[data-tab]').forEach(n=>n.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(p=>p.classList.remove('active'));
    const navEl = document.querySelector(`.nav-item[data-tab="${name}"]`);
    if(navEl) navEl.classList.add('active');
    const tabEl = $('tab-'+name);
    if(tabEl) tabEl.classList.add('active');
    if(name==='history') loadHistory();
}

/* ── Progress ── */
function setProgress(v, s){
    const bar = $('progress-bar');
    const txt = $('progress-text');
    const wrap = $('progress-wrap');
    if(bar) bar.style.width = v+'%';
    if(txt) txt.textContent = (s||'PROCESSING...').toUpperCase();
    if(wrap && v>0) wrap.classList.add('active');
}

function setStatus(type, text){
    const el = $('statusMsg');
    if(!el) return;
    el.className = 'status-msg '+type;
    $('statusText').textContent = text.toUpperCase();
    const sp = $('statusSpinner');
    if(sp) sp.style.display = type==='running'?'block':'none';
}

/* ── Badges ── */
function sevBadge(s){
    s=(s||'info').toLowerCase();
    return `<span class="badge badge-${s}">${s}</span>`;
}
function statusBadge(s){
    s=(s||'unverified').toLowerCase();
    const l={confirmed:'CONFIRMED',false_positive:'FALSE POS',unverified:'UNVERIFIED'};
    return `<span class="badge badge-${s}">${l[s]||s}</span>`;
}

/* ── Render Findings ── */
function renderFindings(results){
    const list=$('findingsList'), empty=$('findingsEmpty');
    if(!results||!results.length){
        if(list) list.innerHTML='';
        if(empty){empty.style.display='block';empty.innerHTML='root@owelsec:~$ NO FINDINGS DETECTED <span class="cursor"></span>';}
        return;
    }
    if(empty) empty.style.display='none';
    const so={critical:0,high:1,medium:2,low:3,info:4,unknown:5};
    const sto={confirmed:0,unverified:1,false_positive:2};
    results.sort((a,b)=>(sto[a.status]||1)-(sto[b.status]||1)||(so[a.severity]||5)-(so[b.severity]||5));
    list.innerHTML=results.map(f=>{
        const sev = (f.severity||'info').toLowerCase();
        return `<div class="finding-card sev-${sev}">
            <div class="finding-header">
                <span class="finding-type">${esc(f.type)}</span>
                <div>${sevBadge(f.severity)} ${statusBadge(f.status)}</div>
            </div>
            <div class="finding-url">${esc(f.url)}</div>
            ${f.details?`<div class="finding-details">${esc(f.details)}</div>`:''}
            <div class="finding-confidence">CONFIDENCE: ${(f.confidence*100).toFixed(0)}%</div>
        </div>`;
    }).join('');
}

function renderAnalysis(text){
    const el=$('analysisContent');
    if(!el) return;
    if(!text){el.innerHTML='<div class="empty-state">root@owelsec:~$ AWAITING AI ANALYSIS <span class="cursor"></span></div>';return;}
    el.innerHTML='<div class="analysis-content">'+marked.parse(text)+'</div>';
}

/* ── History ── */
async function loadHistory(){
    const el=$('historyList');
    if(!el) return;
    try {
        const res = await authFetch(`${API_BASE}/scans?limit=30`);
        if(!res.ok) throw new Error('Failed');
        const scans = await res.json();
        if(!scans.length){el.innerHTML='<div class="empty-state">NO SCAN HISTORY <span class="cursor"></span></div>';return;}
        el.innerHTML = scans.map(s=>{
            const d = new Date(s.created_at);
            const time = d.toLocaleDateString()+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
            let stateColor = 'var(--muted)';
            if(s.state==='completed') stateColor='var(--blue-bright)';
            else if(s.state==='failed') stateColor='var(--red)';
            else stateColor='var(--amber)';
            return `<div class="history-item">
                <span class="history-target">${esc(s.target)}</span>
                <div class="history-right">
                    <span class="history-state" style="color:${stateColor}">${s.state}</span>
                    <span class="history-time">${time}</span>
                </div>
            </div>`;
        }).join('');
    } catch(e){el.innerHTML='<div class="empty-state">HISTORY UNAVAILABLE</div>';}
}

/* ── Poll Scan ── */
async function pollScan(scanId){
    try {
        const res = await authFetch(`${API_BASE}/scan/${scanId}`);
        const data = await res.json();
        if(!res.ok) throw new Error(data.error||'Error');
        setProgress(data.progress||0, data.stage||'Running');
        updateMeta(data);
        if(data.state==='completed'){
            clearInterval(activePoller);activePoller=null;
            $('scanBtn').disabled=false;
            $('scanBtn').classList.remove('scanning');
            $('scanBtn').textContent='EXECUTE';
            $('scan-line').classList.remove('active');
            setStatus('success','SCAN COMPLETE — '+new Date().toLocaleTimeString());
            renderFindings(data.strix_results||[]);
            renderAnalysis(data.analysis);
            $('reportButtons').style.display='flex';
            currentScanId=scanId;
            loadHistory();
            // Auto-switch to findings
            switchNav('dashboard');
            return;
        }
        if(data.state==='failed'){
            clearInterval(activePoller);activePoller=null;
            $('scanBtn').disabled=false;
            $('scanBtn').classList.remove('scanning');
            $('scanBtn').textContent='EXECUTE';
            $('scan-line').classList.remove('active');
            setStatus('error',data.error||'SCAN FAILED');
            renderFindings([]);renderAnalysis(null);
            $('reportButtons').style.display='none';
            loadHistory();
            return;
        }
        setStatus('running',data.stage||'SCAN IN PROGRESS…');
    } catch(e){
        clearInterval(activePoller);activePoller=null;
        $('scanBtn').disabled=false;
        $('scanBtn').classList.remove('scanning');
        $('scanBtn').textContent='EXECUTE';
        setStatus('error',e.toString());
    }
}

/* ── Start Scan ── */
async function startScan(){
    const target=$('target').value.trim();
    if(!target.startsWith('http://')&&!target.startsWith('https://')){
        setStatus('error','URL MUST START WITH http:// OR https://');return;
    }
    if(activePoller){clearInterval(activePoller);activePoller=null;}
    $('scanBtn').disabled=true;
    $('scanBtn').classList.add('scanning');
    $('scanBtn').textContent='SCANNING';
    $('scan-line').classList.add('active');
    setStatus('running','SUBMITTING SCAN…');
    setProgress(1,'QUEUED');
    renderFindings([]);renderAnalysis(null);
    $('reportButtons').style.display='none';
    try {
        const res = await authFetch(`${API_BASE}/scan`,{method:'POST',body:JSON.stringify({url:target})});
        const data = await res.json();
        if(!res.ok) throw new Error(data.error||'Scan failed');
        updateMeta(data);
        setStatus('running',data.stage||'QUEUED');
        setProgress(data.progress||1,data.stage||'QUEUED');
        currentScanId=data.scan_id;
        activePoller=setInterval(()=>pollScan(data.scan_id),2500);
        pollScan(data.scan_id);
    } catch(e){
        $('scanBtn').disabled=false;
        $('scanBtn').classList.remove('scanning');
        $('scanBtn').textContent='EXECUTE';
        $('scan-line').classList.remove('active');
        setStatus('error',e.toString());
        setProgress(0,'NO SCAN RUNNING');
    }
}

/* ── Download Reports ── */
async function downloadReport(type){
    if(!currentScanId) return;
    try {
        const res = await authFetch(`${API_BASE}/scan/${currentScanId}/report/${type}`);
        if(!res.ok){const d=await res.json();alert(d.error||'Download failed');return;}
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href=url;
        a.download=`owelsec_${currentScanId.slice(0,8)}.${type}`;
        a.click();
        URL.revokeObjectURL(url);
    } catch(e){alert('Download error: '+e);}
}

/* ── Helpers ── */
function updateMeta(d){
    $('metaBar').style.display='flex';
    $('metaTarget').textContent='TARGET: '+(d.target||'—');
    $('metaScanId').textContent='SCAN_ID: '+(d.scan_id||'—').slice(0,8);
    $('metaState').textContent='STATE: '+(d.state||'—').toUpperCase();
}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', ()=>{
    // Login enter keys
    const lp = $('loginPass');
    const lu = $('loginUser');
    const tg = $('target');
    if(lp) lp.addEventListener('keydown', e=>{if(e.key==='Enter') doLogin();});
    if(lu) lu.addEventListener('keydown', e=>{if(e.key==='Enter') $('loginPass').focus();});
    if(tg) tg.addEventListener('keydown', e=>{if(e.key==='Enter') startScan();});

    // Nav clicks
    document.querySelectorAll('.nav-item[data-tab]').forEach(el=>{
        el.addEventListener('click', ()=>switchNav(el.dataset.tab));
    });

    // Check token
    if(getToken()) showApp(); else showLogin();
});
