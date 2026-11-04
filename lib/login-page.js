/**
 * Self-contained login and admin pages. No external assets, no CDN — these
 * must render on a plain LAN/WG network. Korean first, English via
 * `Accept-Language: en`.
 */

const css = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;background:#0f1420;color:#e6e9f0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{width:min(420px,92vw);padding:32px;background:#171e2e;border:1px solid #2a3550;border-radius:14px}
h1{margin:0 0 4px;font-size:20px}p.sub{margin:0 0 22px;color:#8b96ad;font-size:13px}
label{display:block;margin:14px 0 4px;font-size:13px;color:#aeb8cd}
input{width:100%;padding:10px 12px;border:1px solid #34415f;border-radius:8px;background:#0d1220;color:inherit;font:inherit}
input:focus{outline:2px solid #4f7cff;border-color:transparent}
button{margin-top:20px;width:100%;padding:11px;border:0;border-radius:8px;background:#4f7cff;color:#fff;font:600 15px inherit;cursor:pointer}
button:hover{background:#6a92ff}
button.secondary{background:#26314a;margin-top:8px}
.err{margin-top:14px;padding:10px 12px;border-radius:8px;background:#43202a;color:#ffb4c0;font-size:13px;display:none}
.ok{background:#1c3a2c;color:#9fe6bd}
.muted{color:#8b96ad;font-size:12px;margin-top:16px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
td,th{padding:7px 6px;border-bottom:1px solid #232d44;text-align:left}
th{color:#8b96ad;font-weight:500}
.row{display:flex;gap:8px}.row button{width:auto;padding:7px 12px;margin:0;font-size:13px}
code{background:#0d1220;padding:2px 6px;border-radius:5px;font-size:12px}
img.qr{display:block;margin:14px auto;background:#fff;padding:8px;border-radius:8px}
a{color:#89a7ff}
`;

const strings = {
  ko: {
    title: "DeepSeek Homegate 로그인",
    sub: "이 기기에서 작업 계속 — 계정으로 인증",
    user: "사용자 이름", pass: "비밀번호", login: "로그인",
    mfaTitle: "2단계 인증", mfa: "인증 앱 6자리 코드 (또는 백업코드)", verify: "확인",
    bootTitle: "첫 관리자 계정 만들기", bootHint: "서버에 계정이 없습니다. 루프백(또는 지정한 바인드 주소)에서만 생성할 수 있습니다.", create: "관리자 생성",
    okRelogin: "성공 — 곧 다시 연결됩니다…",
    adminTitle: "Homegate 관리", accounts: "계정", devices: "페어링된 기기",
    newUser: "새 계정", addAccount: "계정 추가", role: "역할", remove: "삭제",
    invite: "새 기기 페어링", inviteHint: "QR을 폰으로 스캔하면 즉시 전체 GUI 세션이 시작됩니다 (5분 유효).",
    revoke: "철거", mfaCol: "MFA", back: "돌아가기", save: "저장",
    pwNew: "새 비밀번호", pwSet: "비밀번호 변경",
    errBad: "사용자 이름 또는 비밀번호가 올바르지 않습니다",
    errLimited: "시도 횟수를 초과했습니다. 잠시 후 다시 시도하세요",
    errMfa: "코드가 올바르지 않습니다",
    errWeak: "비밀번호는 6자 이상이어야 합니다",
    errBoot: "부트스트랩은 루프백/바인드 주소 요청만 허용됩니다",
    errAuth: "인증이 필요합니다",
  },
  en: {
    title: "DeepSeek Homegate sign in",
    sub: "Continue working on this device — authenticate with your account",
    user: "Username", pass: "Password", login: "Sign in",
    mfaTitle: "Two-factor", mfa: "Authenticator 6-digit code (or backup code)", verify: "Verify",
    bootTitle: "Create the first admin", bootHint: "No accounts on this server yet. Creation is restricted to loopback / bind-address requests.", create: "Create admin",
    okRelogin: "Success — reconnecting…",
    adminTitle: "Homegate admin", accounts: "Accounts", devices: "Paired devices",
    newUser: "New account", addAccount: "Add account", role: "Role", remove: "Remove",
    invite: "Pair a new device", inviteHint: "Scan the QR with your phone to start a full GUI session immediately (valid 5 min).",
    revoke: "Revoke", mfaCol: "MFA", back: "Back", save: "Save",
    pwNew: "New password", pwSet: "Set password",
    errBad: "Wrong username or password",
    errLimited: "Too many attempts — try again later",
    errMfa: "Invalid code",
    errWeak: "Password must be at least 6 characters",
    errBoot: "Bootstrap only accepts loopback / bind-address requests",
    errAuth: "Authentication required",
  },
};

function page(title, body, lang) {
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>${css}</style></head><body><main>${body}</main></body></html>`;
}

/** Login page (also renders the bootstrap form and the MFA step; the JS is a small state machine). */
export function renderLoginPage({ locale, bootstrap }) {
  const t = strings[locale] ?? strings.ko;
  const body = `
<h1 id="t1">${bootstrap ? t.bootTitle : t.title}</h1>
<p class="sub" id="t2">${bootstrap ? t.bootHint : t.sub}</p>
<div class="err" id="err"></div>
<form id="f" autocomplete="on">
  <label>${t.user}<input name="username" id="u" autocomplete="username" required></label>
  <div id="pwrow"><label>${t.pass}<input name="password" id="p" type="password" autocomplete="current-password" required></label></div>
  <div id="mfarow" style="display:none"><label>${t.mfa}<input id="c" name="code" autocomplete="one-time-code" inputmode="text"></label></div>
  <button id="go" type="submit">${bootstrap ? t.create : t.login}</button>
</form>
<script>
const S=${JSON.stringify(t)};let stage=${bootstrap ? '"bootstrap"' : '"login"'},mfaUser=null;
const $=id=>document.getElementById(id),err=$('err');
function show(m,ok){err.textContent=m;err.style.display='block';err.className=ok?'err ok':'err'}
$('f').addEventListener('submit',async e=>{e.preventDefault();err.style.display='none';
 const body={username:$('u').value.trim()};
 if(stage==='login'){body.password=$('p').value}
 else if(stage==='mfa'){body.code=$('c').value.trim()}
 else{body.password=$('p').value}
 const url=stage==='mfa'?'/auth/mfa/login':stage==='bootstrap'?'/auth/bootstrap':'/auth/login';
 let r;try{r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})}catch(x){return show(String(x))}
 const d=await r.json().catch(()=>({}));
 if(r.status===200&&d.mfaRequired){stage='mfa';mfaUser=body.username;$('t1').textContent=S.mfaTitle;$('t2').textContent='';$('pwrow').style.display='none';$('mfarow').style.display='';$('go').textContent=S.verify;$('u').disabled=true;$('c').focus();return}
 if(r.status===200&&d.ok){$('f').style.display='none';show(S.okRelogin,true);setTimeout(()=>location.href=d.next||'/',900);return}
 if(r.status===429)return show(S.errLimited);
 if(r.status===401&&stage==='mfa')return show(S.errMfa);
 if(r.status===400&&d.error==='weak-password')return show(S.errWeak);
 if(r.status===403&&d.error==='loopback-only')return show(S.errBoot);
 show(d.error||S.errBad);});
</script>`;
  return page(bootstrap ? t.bootTitle : t.title, body, locale);
}

/** Admin page: accounts, MFA self-service pointers, device roster + pairing QR. */
export function renderAdminPage({ locale }) {
  const t = strings[locale] ?? strings.ko;
  const body = `
<h1>${t.adminTitle}</h1>
<p class="sub"><a href="/">${t.back}</a></p>
<h3>${t.accounts}</h3><table id="acc"><tr><th>${t.user}</th><th>${t.role}</th><th>${t.mfaCol}</th><th></th></tr></table>
<form id="newacc" class="row" style="margin-top:14px;flex-wrap:wrap">
  <input id="nu" placeholder="${t.newUser}" style="flex:1"><input id="np" type="password" placeholder="${t.pass}" style="flex:1">
  <select id="nr"><option value="user">user</option><option value="admin">admin</option><option value="guest">guest</option></select>
  <button class="secondary" type="submit" style="margin:0">${t.addAccount}</button>
</form>
<h3 style="margin-top:26px">${t.devices}</h3><table id="dev"><tr><th>${t.user}</th><th></th></tr></table>
<button id="inv">${t.invite}</button><p class="sub">${t.inviteHint}</p><div id="qr"></div>
<h3 style="margin-top:26px">${t.pwNew}</h3>
<form id="pwf" class="row"><input id="pu" placeholder="${t.user}" style="flex:1"><input id="pp" type="password" placeholder="${t.pass}" style="flex:1"><button class="secondary" type="submit" style="margin:0">${t.pwSet}</button></form>
<script>
const t=${JSON.stringify(t)};
const $=id=>document.getElementById(id);
async function api(url,opts){const r=await fetch(url,Object.assign({headers:{'content-type':'application/json'}},opts||{}));if(r.status===401){location.href='/auth/login';throw 0}return r.json()}
async function refresh(){
 const a=await api('/auth/accounts');$('acc').innerHTML='<tr><th>'+t.user+'</th><th>'+t.role+'</th><th>'+t.mfaCol+'</th><th></th></tr>'+a.accounts.map(x=>'<tr><td>'+x.username+'</td><td>'+x.role+'</td><td>'+(x.mfa?'✓':'—')+'</td><td><button class=secondary onclick=rm("'+x.username+'")>'+'${t.remove}'+'</button></td></tr>').join('');
 const d=await api('/mini/devices');$('dev').innerHTML='<tr><th>id</th><th>name</th><th></th></tr>'+d.devices.map(x=>'<tr><td><code>'+x.id+'</code></td><td>'+x.name+'</td><td><button class=secondary onclick=revoke("'+x.id+'")>'+'${t.revoke}'+'</button></td></tr>').join('');
}
window.rm=async u=>{await api('/auth/accounts',{method:'POST',body:JSON.stringify({op:'remove',username:u})});refresh()};
window.revoke=async id=>{await api('/mini/devices',{method:'POST',body:JSON.stringify({op:'remove',id})});refresh()};
$('newacc').addEventListener('submit',async e=>{e.preventDefault();await api('/auth/accounts',{method:'POST',body:JSON.stringify({op:'create',username:$('nu').value,password:$('np').value,role:$('nr').value})});refresh()});
$('pwf').addEventListener('submit',async e=>{e.preventDefault();await api('/auth/accounts',{method:'POST',body:JSON.stringify({op:'password',username:$('pu').value,password:$('pp').value})});alert(t.save)});
$('inv').addEventListener('click',async()=>{const d=await api('/mini/invite',{method:'POST',body:'{}'});$('qr').innerHTML='<img class=qr src="'+d.qrDataUrl+'" width=220 height=220><p class=muted style=text-align:center><code>'+d.url+'</code></p>'});
refresh();
</script>`;
  return page(t.adminTitle, body, locale);
}
