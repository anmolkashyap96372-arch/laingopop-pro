const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto'),https=require('https'),http=require('http');
const app=express();app.use(express.json());app.set('trust proxy',true);

const ADMIN_KEY=process.env.ADMIN_KEY||'change-me';
const FILE=process.env.DATA_FILE||path.join(__dirname,'data.json');
const VAPID_PUBLIC=process.env.VAPID_PUBLIC||'';
const VAPID_PRIVATE=process.env.VAPID_PRIVATE||'';
const VAPID_SUBJECT=process.env.VAPID_SUBJECT||'mailto:admin@laingopop.com';
const DAYS={yearly:365,monthly:30,week:7};

let db={grants:[],subs:[]};
try{db=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){}
if(!db.grants)db.grants=[];if(!db.subs)db.subs=[];
const save=()=>{try{fs.writeFileSync(FILE,JSON.stringify(db))}catch(e){}};
const ipOf=r=>(r.headers['x-nf-client-connection-ip']||r.headers['cf-connecting-ip']||(r.headers['x-forwarded-for']||'').split(',')[0]||r.ip||'').trim();
const norm=s=>String(s||'').trim().toUpperCase();
const live=g=>g.expiresAt>Date.now();
const adminOnly=(q,s,n)=>q.headers['x-admin-key']===ADMIN_KEY?n():s.status(401).json({error:'bad key'});
const b64url=b=>Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');

// ── VAPID helpers (no npm dep) ────────────────────────────────────────────────
function vapidJwt(audience){
  const header=b64url(JSON.stringify({typ:'JWT',alg:'ES256'}));
  const payload=b64url(JSON.stringify({aud:audience,exp:Math.floor(Date.now()/1000)+3600,sub:VAPID_SUBJECT}));
  const unsigned=`${header}.${payload}`;
  const privDer=Buffer.from(VAPID_PRIVATE,'base64');
  let privKey;
  try{
    // raw 32-byte key -> pkcs8 der
    const pkcs8=Buffer.concat([Buffer.from('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042','hex'),privDer,Buffer.from('a144034200','hex'),Buffer.from(VAPID_PUBLIC,'base64')]);
    privKey=crypto.createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});
  }catch(e){privKey=crypto.createPrivateKey({key:Buffer.from(VAPID_PRIVATE,'base64'),format:'der',type:'pkcs8'})}
  const sig=crypto.sign('sha256',Buffer.from(unsigned),{key:privKey,dsaEncoding:'ieee-p1363'});
  return `${unsigned}.${b64url(sig)}`;
}
function sendPush(sub,payload){
  return new Promise((ok,fail)=>{
    if(!VAPID_PUBLIC||!VAPID_PRIVATE)return fail(new Error('No VAPID keys'));
    const ep=new URL(sub.endpoint);
    const audience=`${ep.protocol}//${ep.host}`;
    const jwt=vapidJwt(audience);
    const auth=`vapid t=${jwt},k=${VAPID_PUBLIC}`;
    const body=Buffer.from(typeof payload==='string'?payload:JSON.stringify(payload));
    const opts={hostname:ep.hostname,port:ep.port||443,path:ep.pathname+ep.search,method:'POST',headers:{'Content-Type':'application/octet-stream','Content-Length':body.length,'Authorization':auth,'TTL':'86400'}};
    const req=(ep.protocol==='https:'?https:http).request(opts,r=>{r.resume();ok(r.statusCode)});
    req.on('error',fail);req.write(body);req.end();
  });
}

// ── Status (app calls on open) ────────────────────────────────────────────────
app.get('/api/status',(q,s)=>{
  const ref=norm(q.query.ref),ip=ipOf(q);
