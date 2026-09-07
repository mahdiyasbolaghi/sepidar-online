require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' && process.env.DATABASE_URL?.includes('localhost') === false
    ? { rejectUnauthorized: false }
    : false
});
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const q = (text, params=[]) => pool.query(text, params);
const n = v => Number(v || 0);

async function initDb(){
  await q(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'operator' CHECK(role IN ('admin','operator','viewer')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS marketers(
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      card TEXT DEFAULT '',
      balance NUMERIC(18,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS services(
      id BIGSERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      price NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK(price>=0),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS marketer_rates(
      marketer_id BIGINT NOT NULL REFERENCES marketers(id) ON DELETE CASCADE,
      service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      rate NUMERIC(6,3) NOT NULL DEFAULT 0 CHECK(rate>=0 AND rate<=100),
      PRIMARY KEY(marketer_id, service_id)
    );
    CREATE TABLE IF NOT EXISTS plans(
      id BIGSERIAL PRIMARY KEY,
      plan_no TEXT UNIQUE NOT NULL,
      paid_amount NUMERIC(18,2) NOT NULL DEFAULT 0,
      final_credit NUMERIC(18,2) NOT NULL DEFAULT 0,
      weeks INTEGER NOT NULL DEFAULT 1 CHECK(weeks>0),
      weekly_cap NUMERIC(18,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS customers(
      id BIGSERIAL PRIMARY KEY,
      customer_code TEXT UNIQUE NOT NULL,
      card_uid TEXT UNIQUE,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      national_code TEXT DEFAULT '',
      marketer_id BIGINT REFERENCES marketers(id) ON DELETE SET NULL,
      balance NUMERIC(18,2) NOT NULL DEFAULT 0,
      points BIGINT NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS customer_plans(
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      plan_id BIGINT NOT NULL REFERENCES plans(id),
      start_at TIMESTAMPTZ NOT NULL,
      end_at TIMESTAMPTZ NOT NULL,
      paid_amount NUMERIC(18,2) NOT NULL,
      final_credit NUMERIC(18,2) NOT NULL,
      weekly_cap NUMERIC(18,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS transactions(
      id BIGSERIAL PRIMARY KEY,
      invoice_no TEXT,
      customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL,
      kind TEXT NOT NULL,
      amount NUMERIC(18,2) NOT NULL,
      balance_before NUMERIC(18,2),
      balance_after NUMERIC(18,2),
      description TEXT DEFAULT '',
      plan_no TEXT DEFAULT '',
      created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS transaction_items(
      id BIGSERIAL PRIMARY KEY,
      transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
      service_id BIGINT REFERENCES services(id) ON DELETE SET NULL,
      service_name TEXT NOT NULL,
      qty NUMERIC(12,3) NOT NULL DEFAULT 1,
      unit_price NUMERIC(18,2) NOT NULL DEFAULT 0,
      total NUMERIC(18,2) NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS marketer_ledger(
      id BIGSERIAL PRIMARY KEY,
      marketer_id BIGINT NOT NULL REFERENCES marketers(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK(type IN ('commission','withdrawal','adjustment')),
      amount NUMERIC(18,2) NOT NULL,
      transaction_id BIGINT REFERENCES transactions(id) ON DELETE SET NULL,
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS accounting_entries(
      id BIGSERIAL PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('income','expense')),
      amount NUMERIC(18,2) NOT NULL CHECK(amount>=0),
      category TEXT DEFAULT '',
      description TEXT DEFAULT '',
      created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_tx_customer_created ON transactions(customer_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_cp_customer_dates ON customer_plans(customer_id,start_at,end_at);
    CREATE INDEX IF NOT EXISTS idx_marketer_ledger_mid ON marketer_ledger(marketer_id,created_at DESC);
  `);

  const u = await q('SELECT id FROM users LIMIT 1');
  if(!u.rowCount){
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
    await q('INSERT INTO users(username,password_hash,role) VALUES($1,$2,$3)', [username, bcrypt.hashSync(password, 12), 'admin']);
    console.log(`Default admin created: ${username}`);
  }
  await q(`INSERT INTO settings(key,value) VALUES
    ('business', '{"name":"سپیدار","currency":"تومان"}'::jsonb)
    ON CONFLICT(key) DO NOTHING`);
}

function tokenFor(user){
  return jwt.sign({ id:user.id, username:user.username, role:user.role }, JWT_SECRET, { expiresIn:'12h' });
}
function auth(req,res,next){
  try{
    const token=req.cookies.sepidar_token;
    if(!token) return res.status(401).json({error:'ورود لازم است'});
    req.user=jwt.verify(token,JWT_SECRET); next();
  }catch(e){ return res.status(401).json({error:'نشست معتبر نیست'}); }
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'دسترسی مدیر لازم است'}); next(); }

app.post('/api/auth/login', async(req,res)=>{
  const {username='',password=''}=req.body;
  const r=await q('SELECT * FROM users WHERE username=$1',[username]);
  const u=r.rows[0];
  if(!u || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است'});
  res.cookie('sepidar_token', tokenFor(u), {httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:12*3600*1000});
  res.json({id:u.id,username:u.username,role:u.role});
});
app.post('/api/auth/logout',(req,res)=>{res.clearCookie('sepidar_token');res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json(req.user));

app.get('/api/bootstrap',auth,async(req,res)=>{
  const [business,customers,plans,services,marketers]=await Promise.all([
    q("SELECT value FROM settings WHERE key='business'"),
    q(`SELECT c.*,m.name marketer_name FROM customers c LEFT JOIN marketers m ON m.id=c.marketer_id ORDER BY c.id DESC`),
    q('SELECT * FROM plans ORDER BY id DESC'),
    q('SELECT * FROM services WHERE active=true ORDER BY id DESC'),
    q(`SELECT m.*,COALESCE(json_agg(json_build_object('service_id',mr.service_id,'rate',mr.rate)) FILTER (WHERE mr.service_id IS NOT NULL),'[]') rates FROM marketers m LEFT JOIN marketer_rates mr ON mr.marketer_id=m.id GROUP BY m.id ORDER BY m.id DESC`)
  ]);
  res.json({business:business.rows[0]?.value||{name:'سپیدار',currency:'تومان'},customers:customers.rows,plans:plans.rows,services:services.rows,marketers:marketers.rows});
});

app.get('/api/dashboard',auth,async(req,res)=>{
  const r=await q(`SELECT
    (SELECT count(*) FROM customers WHERE active=true)::int customers,
    (SELECT COALESCE(sum(balance),0) FROM customers WHERE active=true) total_balance,
    (SELECT COALESCE(sum(abs(amount)),0) FROM transactions WHERE kind='sale') total_sales,
    (SELECT COALESCE(sum(amount),0) FROM transactions WHERE kind='topup') total_topups,
    (SELECT count(*) FROM transactions WHERE created_at::date=current_date)::int today_transactions`);
  res.json(r.rows[0]);
});

app.get('/api/customers',auth,async(req,res)=>{
  const term=(req.query.q||'').trim();
  const params=[]; let where='';
  if(term){params.push('%'+term+'%');where=`WHERE c.name ILIKE $1 OR c.phone ILIKE $1 OR c.customer_code ILIKE $1 OR COALESCE(c.card_uid,'') ILIKE $1`;}
  const r=await q(`SELECT c.*,m.name marketer_name,
    (SELECT json_build_object('id',cp.id,'plan_id',cp.plan_id,'plan_no',p.plan_no,'start_at',cp.start_at,'end_at',cp.end_at,'weekly_cap',cp.weekly_cap,'final_credit',cp.final_credit)
     FROM customer_plans cp JOIN plans p ON p.id=cp.plan_id WHERE cp.customer_id=c.id AND now() BETWEEN cp.start_at AND cp.end_at ORDER BY cp.id DESC LIMIT 1) active_plan
    FROM customers c LEFT JOIN marketers m ON m.id=c.marketer_id ${where} ORDER BY c.id DESC LIMIT 500`,params);
  res.json(r.rows);
});
app.post('/api/customers',auth,async(req,res)=>{
  const {customer_code,card_uid,name,phone='',national_code='',marketer_id=null}=req.body;
  if(!customer_code||!name) return res.status(400).json({error:'کد مشتری و نام الزامی است'});
  try{const r=await q(`INSERT INTO customers(customer_code,card_uid,name,phone,national_code,marketer_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[customer_code,card_uid||null,name,phone,national_code,marketer_id||null]);res.json(r.rows[0]);}
  catch(e){res.status(400).json({error:e.code==='23505'?'کد مشتری یا UID کارت تکراری است':'ثبت مشتری انجام نشد'});}
});
app.put('/api/customers/:id',auth,async(req,res)=>{
  const {customer_code,card_uid,name,phone='',national_code='',marketer_id=null,active=true}=req.body;
  try{const r=await q(`UPDATE customers SET customer_code=$1,card_uid=$2,name=$3,phone=$4,national_code=$5,marketer_id=$6,active=$7 WHERE id=$8 RETURNING *`,[customer_code,card_uid||null,name,phone,national_code,marketer_id||null,!!active,req.params.id]);res.json(r.rows[0]);}
  catch(e){res.status(400).json({error:'ویرایش مشتری انجام نشد'});}
});

app.get('/api/plans',auth,async(req,res)=>res.json((await q('SELECT * FROM plans ORDER BY id DESC')).rows));
app.post('/api/plans',auth,async(req,res)=>{
  const {plan_no,paid_amount=0,final_credit=0,weeks=1,weekly_cap=0}=req.body;
  try{const r=await q(`INSERT INTO plans(plan_no,paid_amount,final_credit,weeks,weekly_cap) VALUES($1,$2,$3,$4,$5) RETURNING *`,[plan_no,n(paid_amount),n(final_credit),Math.max(1,parseInt(weeks||1)),n(weekly_cap)]);res.json(r.rows[0]);}
  catch(e){res.status(400).json({error:'شماره طرح تکراری یا اطلاعات نامعتبر است'});}
});
app.put('/api/plans/:id',auth,async(req,res)=>{
  const {plan_no,paid_amount,final_credit,weeks,weekly_cap,active=true}=req.body;
  const r=await q(`UPDATE plans SET plan_no=$1,paid_amount=$2,final_credit=$3,weeks=$4,weekly_cap=$5,active=$6 WHERE id=$7 RETURNING *`,[plan_no,n(paid_amount),n(final_credit),Math.max(1,parseInt(weeks||1)),n(weekly_cap),!!active,req.params.id]);res.json(r.rows[0]);
});

app.get('/api/services',auth,async(req,res)=>res.json((await q('SELECT * FROM services WHERE active=true ORDER BY id DESC')).rows));
app.post('/api/services',auth,async(req,res)=>{
  try{const r=await q('INSERT INTO services(name,price) VALUES($1,$2) RETURNING *',[req.body.name,n(req.body.price)]);res.json(r.rows[0]);}
  catch(e){res.status(400).json({error:'نام خدمت تکراری یا قیمت نامعتبر است'});}
});
app.put('/api/services/:id',auth,async(req,res)=>{const r=await q('UPDATE services SET name=$1,price=$2,active=$3 WHERE id=$4 RETURNING *',[req.body.name,n(req.body.price),req.body.active!==false,req.params.id]);res.json(r.rows[0]);});

app.get('/api/marketers',auth,async(req,res)=>{
  const r=await q(`SELECT m.*,COALESCE(json_agg(json_build_object('service_id',mr.service_id,'rate',mr.rate)) FILTER (WHERE mr.service_id IS NOT NULL),'[]') rates FROM marketers m LEFT JOIN marketer_rates mr ON mr.marketer_id=m.id GROUP BY m.id ORDER BY m.id DESC`);res.json(r.rows);
});
app.post('/api/marketers',auth,async(req,res)=>{const r=await q('INSERT INTO marketers(name,phone,card) VALUES($1,$2,$3) RETURNING *',[req.body.name,req.body.phone||'',req.body.card||'']);res.json(r.rows[0]);});
app.put('/api/marketers/:id',auth,async(req,res)=>{
  const client=await pool.connect();
  try{await client.query('BEGIN');await client.query('UPDATE marketers SET name=$1,phone=$2,card=$3,active=$4 WHERE id=$5',[req.body.name,req.body.phone||'',req.body.card||'',req.body.active!==false,req.params.id]);
    if(Array.isArray(req.body.rates)) for(const x of req.body.rates){await client.query(`INSERT INTO marketer_rates(marketer_id,service_id,rate) VALUES($1,$2,$3) ON CONFLICT(marketer_id,service_id) DO UPDATE SET rate=EXCLUDED.rate`,[req.params.id,x.service_id,n(x.rate)]);}
    await client.query('COMMIT');res.json({ok:true});
  }catch(e){await client.query('ROLLBACK');res.status(400).json({error:'ویرایش بازاریاب انجام نشد'});}finally{client.release();}
});
app.post('/api/marketers/:id/withdraw',auth,async(req,res)=>{
  const amount=n(req.body.amount); if(amount<=0)return res.status(400).json({error:'مبلغ نامعتبر است'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const m=(await client.query('SELECT * FROM marketers WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!m)throw new Error('NOTFOUND');if(n(m.balance)<amount)throw new Error('BALANCE');await client.query('UPDATE marketers SET balance=balance-$1 WHERE id=$2',[amount,req.params.id]);await client.query(`INSERT INTO marketer_ledger(marketer_id,type,amount,description) VALUES($1,'withdrawal',$2,$3)`,[req.params.id,-amount,req.body.description||'برداشت از حساب بازاریاب']);await client.query('COMMIT');res.json({ok:true});}
  catch(e){await client.query('ROLLBACK');res.status(400).json({error:e.message==='BALANCE'?'موجودی بازاریاب کافی نیست':'برداشت انجام نشد'});}finally{client.release();}
});
app.get('/api/marketers/:id/ledger',auth,async(req,res)=>res.json((await q('SELECT * FROM marketer_ledger WHERE marketer_id=$1 ORDER BY id DESC LIMIT 500',[req.params.id])).rows));

app.post('/api/topups',auth,async(req,res)=>{
  const {customer_id,amount,description='شارژ حساب'}=req.body; const a=n(amount);if(a<=0)return res.status(400).json({error:'مبلغ نامعتبر است'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const c=(await client.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE',[customer_id])).rows[0];if(!c)throw new Error('NOTFOUND');const before=n(c.balance),after=before+a;await client.query('UPDATE customers SET balance=$1 WHERE id=$2',[after,customer_id]);const t=(await client.query(`INSERT INTO transactions(customer_id,kind,amount,balance_before,balance_after,description,created_by) VALUES($1,'topup',$2,$3,$4,$5,$6) RETURNING *`,[customer_id,a,before,after,description,req.user.id])).rows[0];await client.query('COMMIT');res.json(t);}catch(e){await client.query('ROLLBACK');res.status(400).json({error:'شارژ انجام نشد'});}finally{client.release();}
});

app.post('/api/assign-plan',auth,async(req,res)=>{
  const {customer_id,plan_id}=req.body; const client=await pool.connect();
  try{await client.query('BEGIN');const c=(await client.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE',[customer_id])).rows[0];const p=(await client.query('SELECT * FROM plans WHERE id=$1 AND active=true',[plan_id])).rows[0];if(!c||!p)throw new Error('NOTFOUND');
    const start=new Date(),end=new Date(start.getTime()+n(p.weeks)*7*86400000);const before=n(c.balance),after=before+n(p.final_credit);await client.query(`INSERT INTO customer_plans(customer_id,plan_id,start_at,end_at,paid_amount,final_credit,weekly_cap) VALUES($1,$2,$3,$4,$5,$6,$7)`,[customer_id,plan_id,start,end,p.paid_amount,p.final_credit,p.weekly_cap]);await client.query('UPDATE customers SET balance=$1 WHERE id=$2',[after,customer_id]);await client.query(`INSERT INTO transactions(customer_id,kind,amount,balance_before,balance_after,description,plan_no,created_by) VALUES($1,'plan_credit',$2,$3,$4,$5,$6,$7)`,[customer_id,n(p.final_credit),before,after,`فعال‌سازی طرح ${p.plan_no}`,p.plan_no,req.user.id]);await client.query('COMMIT');res.json({ok:true});}
  catch(e){await client.query('ROLLBACK');res.status(400).json({error:'فعال‌سازی طرح انجام نشد'});}finally{client.release();}
});

app.post('/api/sales',auth,async(req,res)=>{
  const {customer_id,items=[]}=req.body;if(!customer_id||!Array.isArray(items)||!items.length)return res.status(400).json({error:'اطلاعات فروش ناقص است'});
  const client=await pool.connect();
  try{await client.query('BEGIN');const c=(await client.query('SELECT * FROM customers WHERE id=$1 FOR UPDATE',[customer_id])).rows[0];if(!c)throw new Error('CUSTOMER');
    const ids=items.map(x=>Number(x.service_id)).filter(Boolean);const sr=(await client.query('SELECT * FROM services WHERE id=ANY($1::bigint[]) AND active=true',[ids])).rows;const map=new Map(sr.map(s=>[String(s.id),s]));
    const rows=items.map(x=>{const s=map.get(String(x.service_id));if(!s)throw new Error('SERVICE');const qty=Math.max(0.001,n(x.qty||1));const unit=n(s.price);return {service_id:s.id,name:s.name,qty,unit,total:qty*unit};});
    const total=rows.reduce((a,x)=>a+x.total,0);if(total<=0)throw new Error('TOTAL');if(n(c.balance)<total)throw new Error('BALANCE');
    const cp=(await client.query(`SELECT cp.*,p.plan_no FROM customer_plans cp JOIN plans p ON p.id=cp.plan_id WHERE cp.customer_id=$1 AND now() BETWEEN cp.start_at AND cp.end_at ORDER BY cp.id DESC LIMIT 1`,[customer_id])).rows[0];
    if(cp){const elapsed=Math.max(0,Date.now()-new Date(cp.start_at).getTime());const week=Math.floor(elapsed/(7*86400000));const ws=new Date(new Date(cp.start_at).getTime()+week*7*86400000);const we=new Date(ws.getTime()+7*86400000);const spent=n((await client.query(`SELECT COALESCE(sum(abs(amount)),0) v FROM transactions WHERE customer_id=$1 AND kind='sale' AND created_at >= $2 AND created_at < $3`,[customer_id,ws,we])).rows[0].v);if(spent+total>n(cp.weekly_cap))throw new Error('WEEKLY');}
    const before=n(c.balance),after=before-total,invoice='INV-'+Date.now();await client.query('UPDATE customers SET balance=$1,points=points+$2 WHERE id=$3',[after,Math.floor(total/100000),customer_id]);const t=(await client.query(`INSERT INTO transactions(invoice_no,customer_id,kind,amount,balance_before,balance_after,description,plan_no,created_by) VALUES($1,$2,'sale',$3,$4,$5,$6,$7,$8) RETURNING *`,[invoice,customer_id,-total,before,after,rows.map(x=>x.name).join('، '),cp?.plan_no||'',req.user.id])).rows[0];
    for(const x of rows) await client.query(`INSERT INTO transaction_items(transaction_id,service_id,service_name,qty,unit_price,total) VALUES($1,$2,$3,$4,$5,$6)`,[t.id,x.service_id,x.name,x.qty,x.unit,x.total]);
    if(c.marketer_id){const rates=(await client.query('SELECT service_id,rate FROM marketer_rates WHERE marketer_id=$1',[c.marketer_id])).rows;const rm=new Map(rates.map(x=>[String(x.service_id),n(x.rate)]));const commission=rows.reduce((a,x)=>a+x.total*(rm.get(String(x.service_id))||0)/100,0);if(commission>0){await client.query('UPDATE marketers SET balance=balance+$1 WHERE id=$2',[commission,c.marketer_id]);await client.query(`INSERT INTO marketer_ledger(marketer_id,type,amount,transaction_id,description) VALUES($1,'commission',$2,$3,$4)`,[c.marketer_id,commission,t.id,`پورسانت فاکتور ${invoice}`]);}}
    await client.query('COMMIT');res.json({ok:true,invoice_no:invoice,total,balance_after:after});
  }catch(e){await client.query('ROLLBACK');const msg={BALANCE:'اعتبار مشتری کافی نیست',WEEKLY:'سقف مجاز هفتگی طرح کافی نیست',SERVICE:'خدمت نامعتبر است',CUSTOMER:'مشتری پیدا نشد'}[e.message]||'ثبت فروش انجام نشد';res.status(400).json({error:msg});}finally{client.release();}
});

app.get('/api/transactions',auth,async(req,res)=>{
  const params=[];const where=[];if(req.query.customer_id){params.push(req.query.customer_id);where.push(`t.customer_id=$${params.length}`);}if(req.query.kind){params.push(req.query.kind);where.push(`t.kind=$${params.length}`);}if(req.query.from){params.push(req.query.from);where.push(`t.created_at >= $${params.length}::date`);}if(req.query.to){params.push(req.query.to);where.push(`t.created_at < ($${params.length}::date + interval '1 day')`);}
  const r=await q(`SELECT t.*,c.name customer_name,c.customer_code,COALESCE(json_agg(json_build_object('service_name',ti.service_name,'qty',ti.qty,'unit_price',ti.unit_price,'total',ti.total)) FILTER (WHERE ti.id IS NOT NULL),'[]') items FROM transactions t LEFT JOIN customers c ON c.id=t.customer_id LEFT JOIN transaction_items ti ON ti.transaction_id=t.id ${where.length?'WHERE '+where.join(' AND '):''} GROUP BY t.id,c.name,c.customer_code ORDER BY t.id DESC LIMIT 1000`,params);res.json(r.rows);
});

app.get('/api/report/detail',auth,async(req,res)=>{
  const p=[];const w=["t.kind='sale'"];if(req.query.customer){p.push('%'+req.query.customer+'%');w.push(`(c.name ILIKE $${p.length} OR c.customer_code ILIKE $${p.length})`);}if(req.query.service_id){p.push(req.query.service_id);w.push(`ti.service_id=$${p.length}`);}if(req.query.plan_no){p.push(req.query.plan_no);w.push(`t.plan_no=$${p.length}`);}if(req.query.from){p.push(req.query.from);w.push(`t.created_at >= $${p.length}::date`);}if(req.query.to){p.push(req.query.to);w.push(`t.created_at < ($${p.length}::date + interval '1 day')`);}
  const r=await q(`SELECT c.name customer_name,c.customer_code,c.card_uid,t.created_at,t.invoice_no,t.plan_no,ti.service_name,ti.qty,ti.unit_price,ti.total FROM transactions t JOIN customers c ON c.id=t.customer_id JOIN transaction_items ti ON ti.transaction_id=t.id WHERE ${w.join(' AND ')} ORDER BY t.id DESC,ti.id`,p);res.json(r.rows);
});

app.get('/api/accounting',auth,async(req,res)=>{const r=await q('SELECT * FROM accounting_entries ORDER BY id DESC LIMIT 1000');res.json(r.rows);});
app.post('/api/accounting',auth,async(req,res)=>{const {type,amount,category='',description=''}=req.body;if(!['income','expense'].includes(type)||n(amount)<0)return res.status(400).json({error:'اطلاعات نامعتبر است'});const r=await q('INSERT INTO accounting_entries(type,amount,category,description,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *',[type,n(amount),category,description,req.user.id]);res.json(r.rows[0]);});

app.get('/api/settings',auth,async(req,res)=>res.json((await q("SELECT value FROM settings WHERE key='business'")).rows[0]?.value||{}));
app.put('/api/settings',auth,admin,async(req,res)=>{await q(`INSERT INTO settings(key,value) VALUES('business',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,[JSON.stringify(req.body)]);res.json({ok:true});});

app.get('/api/users',auth,admin,async(req,res)=>res.json((await q('SELECT id,username,role,created_at FROM users ORDER BY id')).rows));
app.post('/api/users',auth,admin,async(req,res)=>{const {username,password,role='operator'}=req.body;if(!username||!password)return res.status(400).json({error:'نام کاربری و رمز لازم است'});try{const r=await q('INSERT INTO users(username,password_hash,role) VALUES($1,$2,$3) RETURNING id,username,role',[username,bcrypt.hashSync(password,12),role]);res.json(r.rows[0]);}catch(e){res.status(400).json({error:'نام کاربری تکراری یا نقش نامعتبر است'});}});

app.get('/api/health',async(req,res)=>{try{await q('SELECT 1');res.json({ok:true,db:true});}catch(e){res.status(500).json({ok:false,db:false});}});

app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

initDb().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`SePIDAR Online running on port ${PORT}`))).catch(err=>{console.error('Database initialization failed:',err);process.exit(1)});
