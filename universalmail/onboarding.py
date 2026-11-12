"""Minimal owner-only account connection page; no provider credentials enter the page."""
import secrets
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>UniversalMail · Connect</title>
<style nonce="__NONCE__">body{font:16px system-ui,sans-serif;max-width:680px;margin:70px auto;padding:24px;line-height:1.6;color:#182734;background:#f5f7f8}input,button{font:inherit;padding:12px;margin:6px 0;box-sizing:border-box}input{width:100%}button{cursor:pointer;margin-right:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{display:block;color:#526574}</style></head>
<body><h1>Connect a mailbox</h1><p>Authorize Gmail or Outlook on the provider's own sign-in page. This is the private administration interface for your UniversalMail server.</p>
<label>Server administration key<input id="key" type="password" autocomplete="off" spellcheck="false"></label>
<small>Use your UniversalMail API key, not your email password. It is not saved in this browser.</small>
<label>Expected mailbox (optional)<input id="email" type="email" autocomplete="email"></label>
<button id="check" type="button">Check configuration</button><button id="gmail" type="button">Connect Gmail</button><button id="outlook" type="button">Connect Outlook</button>
<pre id="status" role="status" aria-live="polite"></pre>
<p>Development build. Calendar, Outlook Safe Senders, phishing reporting, cross-account migration, and the live ChatGPT connection remain unfinished.</p>
<script nonce="__NONCE__">
const status = document.getElementById('status');
const key = document.getElementById('key');
async function call(path, method, body) {
  const response = await fetch(path, {method, credentials:'same-origin', redirect:'error',
    headers:{'X-API-Key':key.value, 'Content-Type':'application/json'},
    body:body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Check the entered values.');
  return data;
}
document.getElementById('check').onclick = async () => {
  try { status.textContent = JSON.stringify(await call('/oauth/status','GET'),null,2); }
  catch(e) { status.textContent = e.message; }
};
for (const kind of ['gmail','outlook']) document.getElementById(kind).onclick = async () => {
  document.querySelectorAll('button').forEach(b=>b.disabled=true);
  try {
    const email = document.getElementById('email').value.trim();
    const data = await call('/oauth/'+kind+'/start','POST',email ? {expected_email:email} : {});
    key.value = '';
    window.location.assign(data.authorization_url);
  } catch(e) { status.textContent = e.message; document.querySelectorAll('button').forEach(b=>b.disabled=false); }
};
</script></body></html>"""


@router.get("/connect", response_class=HTMLResponse, include_in_schema=False)
def connect_page():
    nonce = secrets.token_urlsafe(24)
    return HTMLResponse(PAGE.replace("__NONCE__", nonce), headers={
        "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"})
