const express=require('express'),fs=require('fs'),path=require('path');
const app=express();app.use(express.json());app.set('trust proxy',true);
const ADMIN_KEY=process.env.ADMIN_KEY||'change-me';
const FILE=process.env.DATA_FILE||path.join(__dirname,'data.json');
const DAYS={yearly:365,monthly:30,week:7};
let grants=[];try{grants=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){}
const save=()=>{try{fs.writeFileSync(FILE,JSON.stringify(grants))}catch(e){}};
const ipOf=r=>(r.headers['x-nf-client-connection-ip']||r.headers['cf-connecting-ip']||(r.headers['x-forwarded-for']||'').split(',')[0]||r.ip||'').trim();
const norm=s=>String(s||'').trim().toUpperCase();
const live=g=>g.expiresAt>Date.now();
const adminOnly=(q,s,n)=>q.headers['x-admin-key']===ADMIN_KEY?n():s.status(401).json({error:'bad key'});

// App calls this on open/refresh
app.get('/api/status',(q,s)=>{
  const ref=norm(q.query.ref),ip=ipOf(q);
  const g=grants.filter(live).filter(x=>(x.ref&&x.ref===ref)||(x.ip&&x.ip===ip)).sort((a,b)=>b.expiresAt-a.expiresAt)[0];
  s.set('Cache-Control','no-store');
  s.json(g?{pro:true,plan:g.plan,expiresAt:g.expiresAt}:{pro:false});
});
// Panel
app.get('/admin',(q,s)=>s.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/api/admin/list',adminOnly,(q,s)=>s.json(grants.slice().reverse()));
app.get('/api/admin/myip',adminOnly,(q,s)=>s.json({ip:ipOf(q)}));
app.post('/api/admin/grant',adminOnly,(q,s)=>{
  const {plan,note}=q.body,ref=norm(q.body.ref),ip=String(q.body.ip||'').trim();
  const days=Number(q.body.days)||DAYS[plan];
  if(!days||!DAYS[plan]||(!ref&&!ip))return s.status(400).json({error:'plan + (ref or ip) required'});
  const old=grants.filter(live).find(x=>(ref&&x.ref===ref)||(ip&&x.ip===ip));
  const start=old?old.expiresAt:Date.now(); // renew = extend
  const g={id:Date.now().toString(36),ref,ip,plan,note:note||'',createdAt:Date.now(),expiresAt:start+days*864e5};
  if(old){old.expiresAt=g.expiresAt;old.plan=plan;if(ref)old.ref=ref;if(ip)old.ip=ip;save();return s.json(old)}
  grants.push(g);save();s.json(g);
});
app.post('/api/admin/revoke',adminOnly,(q,s)=>{const g=grants.find(x=>x.id===q.body.id);if(g)g.expiresAt=0;save();s.json({ok:true})});
app.listen(process.env.PORT||3000);
