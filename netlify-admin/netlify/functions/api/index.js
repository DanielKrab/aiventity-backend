/**
 * Aiventity CMS — Netlify Function (Node.js stdlib only)
 * Full CMS backend: content, media, theme, SEO, activity log, publish
 */
const crypto = require("crypto");
const https  = require("https");
const fs     = require("fs");
const path   = require("path");

// ── Config ──────────────────────────────────────────────────────────────────
const SECRET_KEY     = process.env.SECRET_KEY     || "changeme";
const ADMIN_HASH     = process.env.ADMIN_HASH     || "";
const GITHUB_TOKEN   = process.env.GITHUB_TOKEN   || "";
const GITHUB_OWNER   = process.env.GITHUB_OWNER   || "DanielKrab";
const GITHUB_REPO    = process.env.GITHUB_REPO    || "aiventity-backend";
const GITHUB_BRANCH  = process.env.GITHUB_BRANCH  || "data";
const NETLIFY_TOKEN  = process.env.NETLIFY_TOKEN  || "";
const PUBLIC_SITE_ID = process.env.PUBLIC_SITE_ID || "5559f234-9246-4edf-a2c5-778983c63285";
const TOKEN_TTL      = 7 * 24 * 3600;

const CORS = {
  "Access-Control-Allow-Origin" : "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
};

// ══════════════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════════════
function sign(p) { return crypto.createHmac("sha256",SECRET_KEY).update(p).digest("hex"); }
function makeToken() { const e=String(Math.floor(Date.now()/1000)+TOKEN_TTL); return `${e}.${sign(e)}`; }
function verifyToken(t) {
  if(!t) return false;
  const d=t.lastIndexOf("."); if(d<0) return false;
  const exp=t.slice(0,d),sig=t.slice(d+1);
  try{ if(!crypto.timingSafeEqual(Buffer.from(sign(exp)),Buffer.from(sig))) return false; }catch{ return false; }
  return parseInt(exp,10)>Math.floor(Date.now()/1000);
}
function bearer(ev) { const a=(ev.headers||{}).authorization||(ev.headers||{}).Authorization||""; return a.startsWith("Bearer ")?a.slice(7):""; }
function isAuth(ev) { return verifyToken(bearer(ev)); }
function checkPw(pw) {
  if(!ADMIN_HASH||!ADMIN_HASH.startsWith("pbkdf2:")) return false;
  const [,salt,stored]=ADMIN_HASH.split(":");
  const d=crypto.pbkdf2Sync(pw,salt,260000,32,"sha256").toString("hex");
  try{ return crypto.timingSafeEqual(Buffer.from(d),Buffer.from(stored)); }catch{ return false; }
}

// ══════════════════════════════════════════════════════════════════════════
// HTTP helper
// ══════════════════════════════════════════════════════════════════════════
function httpRequest(url,opts={},body=null,binary=false) {
  return new Promise((res,rej)=>{
    const u=new URL(url);
    const o={hostname:u.hostname,path:u.pathname+u.search,method:opts.method||"GET",headers:opts.headers||{}};
    const req=https.request(o,r=>{
      const c=[]; r.on("data",x=>c.push(x)); r.on("end",()=>{
        const buf=Buffer.concat(c);
        if(r.statusCode>=400) rej(new Error(`HTTP ${r.statusCode}: ${buf.toString("utf-8").slice(0,300)}`));
        else res(binary?buf:buf.toString("utf-8"));
      });
    });
    req.on("error",rej);
    if(body) req.write(Buffer.isBuffer(body)?body:typeof body==="string"?body:JSON.stringify(body));
    req.end();
  });
}

// ══════════════════════════════════════════════════════════════════════════
// GitHub storage
// ══════════════════════════════════════════════════════════════════════════
const GH = { Authorization:`token ${GITHUB_TOKEN}`, Accept:"application/vnd.github.v3+json",
              "Content-Type":"application/json", "User-Agent":"AiventityCMS/2.0" };

async function ghGet(p) {
  try {
    const t=await httpRequest(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${p}?ref=${GITHUB_BRANCH}`,{headers:GH});
    const i=JSON.parse(t);
    if(Array.isArray(i)) return {data:i,sha:null}; // directory listing
    const data=JSON.parse(Buffer.from(i.content,"base64").toString("utf-8"));
    return {data,sha:i.sha};
  } catch(e) { return {data:{},sha:null}; }
}
async function ghGetRaw(p) { // for non-JSON (media)
  try {
    const t=await httpRequest(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${p}?ref=${GITHUB_BRANCH}`,{headers:GH});
    const i=JSON.parse(t);
    return {content:i.content,sha:i.sha,encoding:i.encoding,size:i.size,name:i.name};
  } catch { return null; }
}
async function ghPut(p,data,sha,msg="CMS update") {
  const body={message:msg,content:Buffer.from(JSON.stringify(data,null,2)).toString("base64"),branch:GITHUB_BRANCH};
  if(sha) body.sha=sha;
  return httpRequest(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${p}`,{method:"PUT",headers:GH},body);
}
async function ghPutBinary(p,base64Content,sha,msg="CMS: upload media") {
  const body={message:msg,content:base64Content,branch:GITHUB_BRANCH};
  if(sha) body.sha=sha;
  return httpRequest(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${p}`,{method:"PUT",headers:GH},body);
}
async function ghDelete(p,sha,msg="CMS: delete") {
  const body=JSON.stringify({message:msg,sha,branch:GITHUB_BRANCH});
  return httpRequest(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${p}`,{method:"DELETE",headers:GH},body);
}

// ══════════════════════════════════════════════════════════════════════════
// Activity logging
// ══════════════════════════════════════════════════════════════════════════
async function logActivity(action,detail="") {
  try {
    const {data:log,sha}=await ghGet("activity_log.json");
    const arr=Array.isArray(log)?log:[];
    arr.push({ts:new Date().toISOString(),action,detail});
    const trimmed=arr.slice(-200); // keep last 200
    await ghPut("activity_log.json",trimmed,sha,"CMS: activity log");
  } catch{}
}

// ══════════════════════════════════════════════════════════════════════════
// Response helpers
// ══════════════════════════════════════════════════════════════════════════
function resp(s,b,x={}) { return {statusCode:s,headers:{...CORS,"Content-Type":"application/json",...x},body:JSON.stringify(b)}; }
function unauth()     { return resp(401,{error:"Niet ingelogd"}); }
function bad(m="Ongeldig verzoek") { return resp(400,{error:m}); }

// ══════════════════════════════════════════════════════════════════════════
// Render / Publish
// ══════════════════════════════════════════════════════════════════════════
const LOGO_URL=`https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/main/static/logo.png`;

function evalJinja(expr,ctx) {
  if(expr.includes("~")) return expr.split("~").map(p=>evalJinja(p.trim(),ctx)).join("");
  const m=expr.match(/^(\w+)\.get\(['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?\)$/);
  if(m){ const o=ctx[m[1]]||{}; return o[m[2]]!==undefined?String(o[m[2]]):m[3]||""; }
  const s=expr.match(/^['"]([^'"]*)['"]\s*$/); if(s) return s[1];
  if(/^\w+$/.test(expr)&&expr in ctx) return String(ctx[expr]||"");
  return "";
}

function buildThemeCSS(theme={}) {
  const p=theme.primary_color||"#007AFF";
  const a=theme.accent_color||"#10b981";
  const bg=theme.bg_color||"#050505";
  const tc=theme.text_color||"#ffffff";
  const hf=theme.heading_font||"Space Grotesk";
  const bf=theme.body_font||"Inter";
  return `
:root{--p:${p};--a:${a};--bg:${bg};--tc:${tc};}
body{background-color:var(--bg)!important;color:var(--tc)!important;font-family:'${bf}',sans-serif!important;}
h1,h2,h3,h4,h5,.font-heading,[class*="font-heading"]{font-family:'${hf}',sans-serif!important;}
.btn-primary{background:var(--p)!important;border-color:var(--p)!important;}
.btn-primary:hover{filter:brightness(1.15)!important;}
.text-ai-blue,.text-ai-blue *{color:var(--p)!important;}
h1 span:nth-child(2){color:var(--p)!important;}
.gradient-text{background:linear-gradient(135deg,var(--tc) 30%,var(--p) 100%)!important;-webkit-background-clip:text!important;background-clip:text!important;-webkit-text-fill-color:transparent!important;}
.glass-blue{border-color:color-mix(in srgb,var(--p) 30%,transparent)!important;}
.lbtn-on{background:var(--p)!important;}
.ping-dot{background:var(--a)!important;}
.tag-ok{color:var(--a)!important;}
.feature-card:hover{border-color:color-mix(in srgb,var(--p) 40%,transparent)!important;box-shadow:0 20px 60px color-mix(in srgb,var(--p) 12%,transparent)!important;}
`.trim();
}

function renderWebsite(content,cfg={},themeOverride=null) {
  const sections={h:content.hero||{},cr:content.creativity||{},ig:content.integration||{},
                  ex:content.execution||{},ap:content.apply||{},ft:content.footer||{}};
  const tmplPath=path.join(__dirname,"templates","website.html");
  let html;
  try { html=fs.readFileSync(tmplPath,"utf-8"); } catch { return buildFallback(sections); }
  // Strip Jinja control flow, evaluate expressions
  html=html.replace(/\{%.*?%\}/gs,"");
  html=html.replace(/\{\{\s*(.+?)\s*\}\}/g,(_,e)=>{ try{return evalJinja(e.trim(),sections);}catch{return "";} });
  // Fix logo URL — replace relative /logo.png with absolute CDN URL
  html=html.replace(/src="\/logo\.png"/g,`src="${LOGO_URL}"`);
  // Inject theme CSS
  const theme=themeOverride||(cfg&&cfg.theme)||{};
  if(Object.keys(theme).length>0) {
    const css=buildThemeCSS(theme);
    html=html.replace("</head>",`<style id="cms-theme">${css}</style></head>`);
    // Also inject Google Fonts for custom fonts if needed
    const hf=(theme.heading_font||"").replace(/\s/g,"+");
    const bf=(theme.body_font||"").replace(/\s/g,"+");
    if(hf||bf) {
      const fonts=[hf,bf].filter(Boolean).map(f=>`family=${f}:wght@400;500;600;700`).join("&");
      html=html.replace("</head>",`<link href="https://fonts.googleapis.com/css2?${fonts}&display=swap" rel="stylesheet"></head>`);
    }
  }
  return html;
}
function buildFallback(s) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Aiventity</title></head><body style="background:#050505;color:#fff;font-family:sans-serif;padding:40px"><h1>${s.h.h1_en||"Imagine."} ${s.h.h2_en||"Automate."} ${s.h.h3_en||"Execute."}</h1><p>${s.h.subheadline_en||""}</p></body></html>`;
}

async function doPublish(body={}) {
  const {data:content}=await ghGet("content.json");
  const {data:cfg,sha:cfgSha}=await ghGet("config.json");
  const token=body.netlify_token||cfg.netlify_token||NETLIFY_TOKEN;
  const siteId=body.netlify_site_id||cfg.netlify_site_id||PUBLIC_SITE_ID;
  if(!token||!siteId) throw new Error("Netlify token of site ID ontbreekt");
  const html=renderWebsite(content,cfg);
  const htmlBuf=Buffer.from(html,"utf-8");
  const htmlSha1=crypto.createHash("sha1").update(htmlBuf).digest("hex");
  const hdrsBuf=Buffer.from("/*\n  Content-Type: text/html; charset=utf-8\n  Cache-Control: public, max-age=0, must-revalidate\n  X-Frame-Options: SAMEORIGIN\n");
  const hdrsSha1=crypto.createHash("sha1").update(hdrsBuf).digest("hex");

  // Fetch logo to include in deploy
  let logoBuf=null; let logoSha1=null;
  try {
    logoBuf=await httpRequest(LOGO_URL,{headers:{"User-Agent":"AiventityCMS/2.0"}},null,true);
    logoSha1=crypto.createHash("sha1").update(logoBuf).digest("hex");
  } catch{}

  const files={"/index.html":htmlSha1,"/_headers":hdrsSha1};
  if(logoSha1) files["/logo.png"]=logoSha1;
  const manifest=JSON.stringify({files});
  const nlH={Authorization:`Bearer ${token}`,"Content-Type":"application/json"};
  const dep=JSON.parse(await httpRequest(`https://api.netlify.com/api/v1/sites/${siteId}/deploys`,{method:"POST",headers:nlH},manifest));
  const did=dep.id; const required=dep.required||[];
  const fm={
    [htmlSha1]:{n:"index.html",b:htmlBuf,ct:"text/html; charset=utf-8"},
    [hdrsSha1]:{n:"_headers",b:hdrsBuf,ct:"text/plain"},
  };
  if(logoSha1&&logoBuf) fm[logoSha1]={n:"logo.png",b:logoBuf,ct:"image/png"};
  for(const sha of required){ if(fm[sha]){ const {n,b,ct}=fm[sha]; await httpRequest(`https://api.netlify.com/api/v1/deploys/${did}/files/${n}`,{method:"PUT",headers:{Authorization:`Bearer ${token}`,"Content-Type":ct}},b); } }
  cfg.last_published=new Date().toLocaleString("nl-NL",{timeZone:"Europe/Amsterdam"});
  await ghPut("config.json",cfg,cfgSha,"CMS: publish timestamp");
  await logActivity("publish","Website gepubliceerd op Netlify");
  return cfg.last_published;
}

// ══════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ══════════════════════════════════════════════════════════════════════════
exports.handler = async (event) => {
  const method=(event.httpMethod||"GET").toUpperCase();
  const rawPath=event.path||"/";
  const p=rawPath.replace(/^\/?\.netlify\/functions\/api/,"").replace(/\/$/,"")||"/";

  if(method==="OPTIONS") return {statusCode:204,headers:CORS,body:""};

  // ── Public ──────────────────────────────────────────────────────────────
  if(p==="/api/login"&&method==="POST") {
    let b; try{b=JSON.parse(event.body||"{}");}catch{return bad();}
    if(!ADMIN_HASH) return resp(500,{error:"ADMIN_HASH not set"});
    if(checkPw(b.password||"")) return resp(200,{ok:true,token:makeToken()});
    return resp(401,{error:"Ongeldig wachtwoord"});
  }

  // ── Contact form (public) ─────────────────────────────────────────────────
  if(p==="/api/contact"&&method==="POST") {
    let b; try{b=JSON.parse(event.body||"{}");}catch{return bad();}
    const email=b.email||b.mail||""; const message=b.message||b.bericht||b.msg||"";
    if(!email) return bad("E-mailadres is verplicht");
    const {data:inbox,sha:iSha}=await ghGet("inbox.json");
    const arr=Array.isArray(inbox)?inbox:[];
    const id=Date.now().toString(36)+Math.random().toString(36).slice(2,6);
    const entry={id,name:b.name||b.naam||"",email,phone:b.phone||"",
                 subject:b.subject||b.onderwerp||"Aanmelding/vraag",
                 message:message||"(geen bericht)",
                 ts:new Date().toISOString(),read:false};
    arr.unshift(entry);
    await ghPut("inbox.json",arr.slice(0,500),iSha,"CMS: new submission");
    // Optional email via Resend
    const RESEND=process.env.RESEND_API_KEY||"";
    const NOTIFY=process.env.NOTIFY_EMAIL||"danielcloud@hotmail.nl";
    if(RESEND) {
      try {
        await httpRequest("https://api.resend.com/emails",{method:"POST",
          headers:{"Authorization":`Bearer ${RESEND}`,"Content-Type":"application/json"}},
          {from:"noreply@aiventity.com",to:[NOTIFY],
           subject:`[Aiventity] Nieuw bericht van ${entry.name||email}`,
           html:`<p><b>Van:</b> ${entry.name||""} &lt;${email}&gt;</p><p><b>Onderwerp:</b> ${entry.subject}</p><hr><p>${entry.message.replace(/\n/g,'<br>')}</p><p><small>Ontvangen: ${new Date().toLocaleString('nl-NL')}</small></p>`});
      } catch{}
    }
    return resp(200,{ok:true,message:"Bericht ontvangen! We nemen snel contact op."});
  }

  if(!isAuth(event)) return unauth();

  let body={}; try{body=JSON.parse(event.body||"{}");}catch{}

  // ── Preview (returns HTML) ────────────────────────────────────────────────
  if(p==="/api/preview") {
    if(method==="GET") {
      // Full preview: load saved content+theme from GitHub
      const {data:content}=await ghGet("content.json");
      const {data:cfg}=await ghGet("config.json");
      const html=renderWebsite(content,cfg);
      return {statusCode:200,headers:{...CORS,"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"},body:html};
    }
    if(method==="POST") {
      // Live preview: render with provided data (no GitHub writes — fast!)
      const content=body.content||{};
      const themeOverride=body.theme||null;
      const html=renderWebsite(content,{},themeOverride);
      return {statusCode:200,headers:{...CORS,"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"},body:html};
    }
  }

  // ── Inbox ─────────────────────────────────────────────────────────────────
  if(p==="/api/inbox") {
    if(method==="GET"){ const {data}=await ghGet("inbox.json"); return resp(200,Array.isArray(data)?data:[]); }
  }
  if(p.match(/^\/api\/inbox\/[^/]+\/(read|delete)$/)&&method==="POST") {
    const parts=p.split("/"); const id=parts[3]; const action=parts[4];
    const {data:inbox,sha:iSha}=await ghGet("inbox.json");
    let arr=Array.isArray(inbox)?inbox:[];
    if(action==="read") arr=arr.map(m=>m.id===id?{...m,read:true}:m);
    else if(action==="delete") arr=arr.filter(m=>m.id!==id);
    await ghPut("inbox.json",arr,iSha,`CMS: inbox ${action}`);
    if(action==="delete") await logActivity("inbox_delete",`Bericht verwijderd: ${id}`);
    return resp(200,{ok:true});
  }

  // ── Content ─────────────────────────────────────────────────────────────
  if(p==="/api/content") {
    if(method==="GET"){ const {data}=await ghGet("content.json"); return resp(200,data); }
    if(method==="POST"){
      const {data:c,sha}=await ghGet("content.json");
      for(const [s,f] of Object.entries(body)) { const sec=Object.keys(body)[0]; c[s]={...(c[s]||{}),...f}; }
      await ghPut("content.json",c,sha,"CMS: save content");
      // Save history snapshot if requested
      if(body._snapshot) {
        const {data:h,sha:hSha}=await ghGet("content_history.json");
        const arr=Array.isArray(h)?h:[];
        arr.push({label:`Opgeslagen: ${Object.keys(body).filter(k=>k!=='_snapshot').join(', ')}`,
                  timestamp:new Date().toISOString(),data:c});
        await ghPut("content_history.json",arr.slice(-30),hSha,"CMS: save snapshot");
      }
      await logActivity("content_save",`Sectie opgeslagen: ${Object.keys(body).filter(k=>k!=='_snapshot').join(", ")}`);
      return resp(200,{ok:true});
    }
  }

  // ── Config ──────────────────────────────────────────────────────────────
  if(p==="/api/config") {
    if(method==="GET"){ const {data:cfg}=await ghGet("config.json"); delete cfg.admin_password_hash; delete cfg.secret_key; return resp(200,cfg); }
    if(method==="POST"){
      const {data:cfg,sha}=await ghGet("config.json");
      const ok=["site_name","site_tagline","twitter_url","linkedin_url","instagram_url","github_url",
        "google_analytics_id","contact_email","favicon_url","netlify_token","netlify_site_id",
        "company_name","company_address","company_phone","kvk_number","vat_number"];
      for(const k of ok) if(body[k]!==undefined&&body[k]!=="") cfg[k]=body[k];
      await ghPut("config.json",cfg,sha,"CMS: save config");
      await logActivity("settings_save","Website instellingen opgeslagen");
      return resp(200,{ok:true});
    }
  }

  // ── Theme ────────────────────────────────────────────────────────────────
  if(p==="/api/theme") {
    if(method==="GET"){ const {data:cfg}=await ghGet("config.json"); return resp(200,cfg.theme||{}); }
    if(method==="POST"){
      const {data:cfg,sha}=await ghGet("config.json");
      cfg.theme={...(cfg.theme||{}),...body};
      await ghPut("config.json",cfg,sha,"CMS: save theme");
      await logActivity("theme_save","Thema-instellingen opgeslagen");
      return resp(200,{ok:true});
    }
  }

  // ── Media list ──────────────────────────────────────────────────────────
  if(p==="/api/media"&&method==="GET") {
    const {data}=await ghGet("media.json");
    return resp(200,Array.isArray(data)?data:[]);
  }

  // ── Media upload ────────────────────────────────────────────────────────
  if(p==="/api/media/upload"&&method==="POST") {
    const {name,base64,type,size}=body;
    if(!name||!base64) return bad("Naam en base64 data vereist");
    // Store file in GitHub data branch
    const safeName=name.replace(/[^a-zA-Z0-9._-]/g,"_");
    const filePath=`media/${safeName}`;
    const existing=await ghGetRaw(filePath);
    const b64=base64.includes(",")? base64.split(",")[1]:base64;
    await ghPutBinary(filePath,b64,existing?.sha||null,`CMS: upload ${safeName}`);
    // Update media index
    const {data:mediaList,sha:mSha}=await ghGet("media.json");
    const arr=Array.isArray(mediaList)?mediaList:[];
    const rawUrl=`https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/${GITHUB_BRANCH}/media/${safeName}`;
    const entry={name:safeName,url:rawUrl,type:type||"image",size:size||0,uploaded:new Date().toISOString()};
    const idx=arr.findIndex(m=>m.name===safeName);
    if(idx>=0) arr[idx]=entry; else arr.push(entry);
    await ghPut("media.json",arr,mSha,"CMS: update media index");
    await logActivity("media_upload",`Bestand geüpload: ${safeName}`);
    return resp(200,{ok:true,url:rawUrl,entry});
  }

  // ── Media delete ────────────────────────────────────────────────────────
  if(p.startsWith("/api/media/delete/")&&method==="POST") {
    const name=decodeURIComponent(p.replace("/api/media/delete/",""));
    const safeName=name.replace(/[^a-zA-Z0-9._-]/g,"_");
    const filePath=`media/${safeName}`;
    const existing=await ghGetRaw(filePath);
    if(existing?.sha) await ghDelete(filePath,existing.sha,`CMS: delete ${safeName}`);
    const {data:mediaList,sha:mSha}=await ghGet("media.json");
    const arr=(Array.isArray(mediaList)?mediaList:[]).filter(m=>m.name!==safeName);
    await ghPut("media.json",arr,mSha,"CMS: remove from media index");
    await logActivity("media_delete",`Bestand verwijderd: ${safeName}`);
    return resp(200,{ok:true});
  }

  // ── Publish ─────────────────────────────────────────────────────────────
  if(p==="/api/publish"&&method==="POST") {
    try { const ts=await doPublish(body); return resp(200,{ok:true,message:"✅ Website gepubliceerd!",last_published:ts}); }
    catch(e) { return resp(500,{error:`Publiceren mislukt: ${e.message}`}); }
  }
  if(p==="/api/publish-status"&&method==="GET") {
    const {data:cfg}=await ghGet("config.json");
    return resp(200,{last_published:cfg.last_published||null});
  }

  // ── History ─────────────────────────────────────────────────────────────
  if(p==="/api/history"&&method==="GET") {
    const {data}=await ghGet("content_history.json");
    return resp(200,Array.isArray(data)?data.slice(-30):[]);
  }
  if(p.match(/^\/api\/restore\/\d+$/)&&method==="POST") {
    const idx=parseInt(p.split("/").pop(),10);
    const {data:h,sha:hSha}=await ghGet("content_history.json");
    if(!Array.isArray(h)||idx>=h.length) return bad("Snapshot niet gevonden");
    const {data:content,sha:cSha}=await ghGet("content.json");
    const backup={label:"Auto-backup voor herstel",timestamp:new Date().toISOString(),data:content};
    await ghPut("content.json",h[idx].data,cSha,"CMS: restore snapshot");
    const newH=[...h,backup].slice(-30);
    await ghPut("content_history.json",newH,hSha,"CMS: history after restore");
    await logActivity("restore",`Snapshot hersteld: index ${idx}`);
    return resp(200,{ok:true});
  }

  // ── Activity log ─────────────────────────────────────────────────────────
  if(p==="/api/activity"&&method==="GET") {
    const {data}=await ghGet("activity_log.json");
    return resp(200,Array.isArray(data)?data.slice(-100).reverse():[]);
  }
  if(p==="/api/activity"&&method==="POST") {
    const {action,detail}=body;
    if(action) await logActivity(action,detail||"");
    return resp(200,{ok:true});
  }

  return resp(404,{error:"Route niet gevonden",path:p});
};
