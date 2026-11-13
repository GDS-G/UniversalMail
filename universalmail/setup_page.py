"""First-run local/server setup UI. Provider passwords and MFA remain provider-hosted."""
import secrets
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()
PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>UniversalMail · Setup</title>
<style nonce="__NONCE__">
:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;max-width:1000px;margin:32px auto;padding:20px;line-height:1.55}h1{margin-bottom:6px}h2{font-size:1.25rem}section{border:1px solid #8a949e;border-radius:10px;padding:22px;margin:22px 0}input,select,button{font:inherit;padding:10px;box-sizing:border-box}input:not([type=checkbox]),select{width:100%;margin:6px 0 14px}button{cursor:pointer;margin:6px 8px 6px 0}pre,code{overflow-wrap:anywhere;white-space:pre-wrap}small{display:block}label{display:block}.row{display:grid;grid-template-columns:1fr 1fr;gap:18px}.notice{border-left:4px solid #7893ad;padding-left:16px}.hide{display:none}@media(max-width:650px){.row{grid-template-columns:1fr}}a{color:inherit}#status{min-height:1.5em}li{margin-bottom:8px}
</style></head><body><h1>UniversalMail</h1><p>Set up this computer now. Use the same backend on your own server later.</p>
<section><h2>1 · Unlock configuration</h2><label>Administration key<input id="key" type="password" autocomplete="off" spellcheck="false"></label>
<small>This is the generated UNIVERSALMAIL_API_KEY in your private .env file—not your mailbox password. The Windows launcher can copy it to your clipboard with -CopyKey. It is not put in a URL or browser storage.</small>
<button id="unlock">Check setup</button><button id="lock">Clear key</button><pre id="status" role="status" aria-live="polite"></pre></section>
<section><h2>2 · Where should it run?</h2><label>Deployment option<select id="mode"><option value="local">This computer — Docker</option><option value="server">My backend server — Docker + HTTPS</option></select></label>
<p id="local-help">Local mode keeps the API on this computer's loopback interface. Keep Docker running. The setup page must be opened on this computer, not on a phone.</p>
<div id="server-help" class="hide"><p>On a compatible Linux server with Docker Engine and Compose v2, run the included server launcher. It configures the app, data volume, and Caddy HTTPS proxy. You supply the authorized server, DNS hostname and network access; this page does not SSH to hosts or buy a server.</p>
<code>bash ./start-universalmail.sh --mode server --domain mail.your-domain.com</code><p>DNS must point to the server and ports 80/443 must reach it. Existing deployments are not automatically moved or overwritten. Back up the data volume and master key together before migration.</p></div><p id="runtime"></p></section>
<section><h2>3 · Register the application once, then connect mailboxes</h2><p>You can finish this after the local service is running. Provider app registration is different from signing into a mailbox. Register a <strong>Web application</strong> for this backend—even when it runs in Docker on your computer.</p>
<div class="row"><div><h3>Google / Gmail</h3><ol><li>Open <a href="https://console.cloud.google.com/" target="_blank" rel="noopener noreferrer">Google Cloud Console</a>. Create or select a project and enable the Gmail API.</li><li>Configure Google Auth Platform branding, audience and data access. For an external app in Testing, add your mailbox as a test user.</li><li>Create an OAuth client of type <strong>Web application</strong>. Add this exact authorized redirect URI: <code id="gmail-callback">Unlock to see the configured URI.</code></li><li>Save the client ID and client secret below. Those are app credentials, not your Google password.</li></ol><p>Testing-mode grants can require reconnection. Calendar permissions will be added when calendar support exists.</p></div>
<div><h3>Microsoft / Outlook</h3><ol><li>Open <a href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">Microsoft Entra admin center</a> → App registrations → New registration. Registration requires access to an Entra tenant.</li><li>For both Outlook.com and organizational accounts, choose accounts in any organizational directory and personal Microsoft accounts.</li><li>Add a <strong>Web</strong> redirect URI: <code id="outlook-callback">Unlock to see the configured URI.</code></li><li>Add delegated Graph permissions User.Read, Mail.ReadWrite, Mail.Send and offline_access. Create a client secret and copy its <strong>Value</strong>, not its ID.</li><li>Save the Application (client) ID and secret below. Employer policies may require an administrator's approval.</li></ol></div></div>
<label>Provider<select id="provider"><option value="gmail">Google / Gmail</option><option value="outlook">Microsoft / Outlook</option></select></label>
<label>Application client ID<input id="client-id" autocomplete="off" spellcheck="false"></label>
<label>Application client secret<input id="client-secret" type="password" autocomplete="new-password" spellcheck="false"></label>
<label>Microsoft tenant (common supports work/school and personal accounts)<input id="tenant" value="common" autocomplete="off" spellcheck="false"></label>
<label><input type="checkbox" id="replace"> Replace an existing app configuration; I understand affected mailboxes may need reconnection.</label>
<button id="save">Save app configuration encrypted</button><pre id="provider-result" role="status"></pre>
<hr><label>Expected mailbox address (optional)<input id="email" type="email" autocomplete="email"></label>
<button id="gmail">Connect Gmail</button><button id="outlook">Connect Outlook</button><button id="accounts">Refresh connected accounts</button><pre id="account-list"></pre></section>
<section><h2>ChatGPT connection is a separate step</h2><p>Running this service or connecting a mailbox does not connect the installed ChatGPT plugin. Its authenticated MCP endpoint and bridge are not implemented yet. A local deployment will need a supported private tunnel or a locally running MCP client. Server mode will need a reachable authenticated MCP endpoint.</p><p>Calendar management, Outlook Safe Senders, phishing reporting, cross-account migration and autonomous processing remain unfinished. No test message is sent by this setup process.</p><p>Custom IMAP/SMTP account registration is currently available in the authenticated <a href="/docs">API interface</a>.</p></section>
<script nonce="__NONCE__">
const byId=id=>document.getElementById(id), key=byId('key'), status=byId('status');
async function call(path,method='GET',body){const r=await fetch(path,{method,credentials:'same-origin',redirect:'error',headers:{'X-API-Key':key.value,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const d=await r.json();if(!r.ok)throw Error(typeof d.detail==='string'?d.detail:'Check the entered values.');return d;}
async function check(){const d=await call('/setup/status');status.textContent='Server reachable. Google app: '+(d.providers.gmail.configured?'configured':'not configured')+'. Microsoft app: '+(d.providers.outlook.configured?'configured':'not configured')+'.';byId('runtime').textContent='Current running instance: '+d.mode+' at '+d.origin+'. Changing the selector displays setup instructions; it does not migrate this instance.';for(const k of ['gmail','outlook'])byId(k+'-callback').textContent=d.providers[k].redirect_uri;byId('account-list').textContent=d.accounts.length?d.accounts.map(a=>a.kind+' — '+a.email).join('\n'):'No mailboxes connected.';}
byId('unlock').onclick=()=>check().catch(e=>status.textContent=e.message);
byId('accounts').onclick=()=>check().catch(e=>status.textContent=e.message);
byId('lock').onclick=()=>{key.value='';byId('client-secret').value='';byId('account-list').textContent='';status.textContent='Key cleared from this page.';};
byId('mode').onchange=()=>{const server=byId('mode').value==='server';byId('local-help').classList.toggle('hide',server);byId('server-help').classList.toggle('hide',!server);};
byId('save').onclick=async()=>{const button=byId('save');button.disabled=true;try{const d=await call('/setup/providers/'+byId('provider').value,'POST',{client_id:byId('client-id').value.trim(),client_secret:byId('client-secret').value,tenant:byId('tenant').value.trim()||'common',replace_existing:byId('replace').checked});byId('provider-result').textContent='Saved encrypted. Credentials are not verified until sign-in succeeds. '+(d.reconnect_existing_accounts?'Reconnect existing mailboxes.':'');byId('client-secret').value='';await check();}catch(e){byId('provider-result').textContent=e.message;}finally{button.disabled=false;}};
for(const kind of ['gmail','outlook'])byId(kind).onclick=async()=>{document.querySelectorAll('button').forEach(b=>b.disabled=true);try{const email=byId('email').value.trim();const d=await call('/oauth/'+kind+'/start','POST',email?{expected_email:email}:{});key.value='';byId('client-secret').value='';window.location.assign(d.authorization_url);}catch(e){status.textContent=e.message;document.querySelectorAll('button').forEach(b=>b.disabled=false);}};
</script></body></html>'''


@router.get("/", include_in_schema=False)
def home():
    return RedirectResponse("/setup", status_code=307)


@router.get("/setup", response_class=HTMLResponse, include_in_schema=False)
def setup_page():
    nonce = secrets.token_urlsafe(24)
    return HTMLResponse(PAGE.replace("__NONCE__", nonce), headers={
        "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"})
