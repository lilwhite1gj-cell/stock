import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import nodePath from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { getDb } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = nodePath.dirname(__filename);

dotenv.config();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, nodePath.join(__dirname, '../public/uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + nodePath.extname(file.originalname))
});
const upload = multer({ storage });

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(nodePath.join(__dirname, '../public/uploads')));

app.set('view engine', 'ejs');
app.set('views', nodePath.join(__dirname, '../views'));
app.get('/', (req, res) => res.render('index'));

const SECRET = process.env.JWT_SECRET || 'mouth-nasal-tape-secret';

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// --- Auth 系统 ---
app.post('/api/register', async (req, res) => {
  const { username, password, phone, question, answer } = req.body;
  const db = await getDb();
  if (db.data.users.find(u => u.username === username)) return res.status(400).json({ message: '用户名已占用' });
  const hashedPassword = await bcrypt.hash(password, 10);
  db.data.users.push({ id: Date.now().toString(), username, password: hashedPassword, role: 'staff', phone: phone || '', securityQuestion: question || '', securityAnswer: answer || '' });
  await db.write();
  res.status(201).json({ message: 'Success' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: '凭据错误' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/update-profile', authenticate, async (req, res) => {
  const { newUsername, oldPassword, newPassword } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (newPassword) {
    if (!oldPassword || !(await bcrypt.compare(oldPassword, user.password))) return res.status(401).json({ message: '旧密码错误' });
    user.password = await bcrypt.hash(newPassword, 10);
  }
  if (newUsername) {
    if (db.data.users.find(u => u.username === newUsername && u.id !== user.id)) return res.status(400).json({ message: '用户名已存在' });
    db.data.transactions.forEach(t => { if (t.userId === user.id) t.username = newUsername; });
    db.data.products.forEach(p => { if (p.createdBy === user.id) p.creatorName = newUsername; });
    user.username = newUsername;
  }
  await db.write();
  res.json({ message: 'OK', user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/reset-password-now', async (req, res) => {
  const { username, phone, answer, newPassword } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username && u.phone === phone && u.securityAnswer === answer);
  if (!user) return res.status(401).json({ message: '验证失败' });
  user.password = await bcrypt.hash(newPassword, 10);
  await db.write();
  res.json({ message: 'OK' });
});

app.get('/api/forgot-password-verify', async (req, res) => {
  const { username } = req.query;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: 'No user' });
  res.json({ question: user.securityQuestion });
});

// --- 管理员分级接口 ---
app.get('/api/admin/users', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  res.json(db.data.users.map(({ password, ...u }) => u));
});

app.post('/api/admin/change-role', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: '仅最高管理员' });
  const db = await getDb();
  const user = db.data.users.find(u => u.id === req.body.userId);
  if (user && user.role !== 'admin') { user.role = req.body.newRole; await db.write(); res.json({ message: 'OK' }); }
  else res.status(400).json({ message: '操作失败' });
});

app.post('/api/admin/reset-user-password', authenticate, async (req, res) => {
  const myRole = req.user.role;
  const db = await getDb();
  const targetUser = db.data.users.find(u => u.id === req.body.userId);
  if (!targetUser || (myRole === 'manager' && (targetUser.role === 'admin' || targetUser.role === 'manager'))) return res.status(403).json({ message: '权限拦截' });
  targetUser.password = await bcrypt.hash(req.body.newPassword, 10);
  await db.write();
  res.json({ message: 'OK' });
});

app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  const targetUser = db.data.users.find(u => u.id === req.params.id);
  if (targetUser && targetUser.role !== 'admin' && req.params.id !== req.user.id) {
    db.data.users = db.data.users.filter(u => u.id !== req.params.id);
    await db.write();
    res.json({ message: 'OK' });
  } else res.status(400).json({ message: '不可删除' });
});

// --- 业务数据接口 ---
app.get('/api/products', authenticate, async (req, res) => { const db = await getDb(); res.json(db.data.products); });
app.post('/api/products', authenticate, upload.single('image'), async (req, res) => {
  const db = await getDb();
  const product = { ...req.body, id: Date.now().toString(), unitPrice: parseFloat(req.body.unitPrice) || 0, currency: req.body.currency || 'CNY', image: req.file ? `/uploads/${req.file.filename}` : null, createdBy: req.user.id, creatorName: req.user.username };
  db.data.products.push(product); await db.write();
  res.status(201).json(product);
});

app.put('/api/products/:id', authenticate, upload.single('image'), async (req, res) => {
  if (req.user.role === 'staff') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  const p = db.data.products.find(x => x.id === req.params.id);
  if (p) {
    Object.assign(p, req.body);
    if (req.body.unitPrice) p.unitPrice = parseFloat(req.body.unitPrice);
    if (req.file) p.image = `/uploads/${req.file.filename}`;
    await db.write(); res.json({ message: 'OK' });
  } else res.status(404).json({ message: 'Not found' });
});

app.get('/api/inventory', authenticate, async (req, res) => {
  const db = await getDb();
  const role = (req.user.role || 'staff').toLowerCase();
  res.json(db.data.products.map(p => {
    const pTrans = db.data.transactions.filter(t => t.productId === p.id);
    const isS = p.category && p.category.includes('样品');
    const rel = (role !== 'staff' || isS) ? pTrans : pTrans.filter(t => t.userId === req.user.id);
    return { ...p, balance: rel.reduce((a, t) => t.type === 'in' ? a + t.quantity : a - t.quantity, 0) };
  }));
});

app.get('/api/transactions', authenticate, async (req, res) => {
  const db = await getDb();
  const role = (req.user.role || 'staff').toLowerCase();
  const sampleIds = db.data.products.filter(p => p.category?.includes('样品')).map(p => p.id);
  res.json(db.data.transactions.filter(t => role !== 'staff' || t.userId === req.user.id || sampleIds.includes(t.productId)));
});
app.delete('/api/transactions/:id', authenticate, async (req, res) => {
  try {
    const role = (req.user.role || 'staff').toLowerCase();
    if (role !== 'admin' && role !== 'manager') {
      return res.status(403).json({ message: '权限不足：仅限管理员撤销流水' });
    }
    const db = await getDb();
    const tid = String(req.params.id);
    const exists = db.data.transactions.find(t => String(t.id) === tid);
    if (!exists) return res.status(404).json({ message: '未找到该条流水记录' });

    db.data.transactions = db.data.transactions.filter(t => String(t.id) !== tid);
    await db.write();
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete trans error:', err);
    res.status(500).json({ message: '服务器内部错误，请检查数据库' });
  }
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'Only admins can delete products' });
  const db = await getDb();
  const hasTrans = db.data.transactions.some(t => t.productId === req.params.id);
  if (hasTrans) return res.status(400).json({ message: 'Cannot delete product with existing transactions' });
  db.data.products = db.data.products.filter(p => p.id !== req.params.id);
  await db.write(); res.json({ message: 'Deleted' });
});

app.post('/api/transactions', authenticate, upload.single('transImage'), async (req, res) => {
  const db = await getDb();
  const t = { ...req.body, id: Date.now().toString(), quantity: parseInt(req.body.quantity), userId: req.user.id, username: req.user.username, date: new Date().toISOString(), image: req.file ? `/uploads/${req.file.filename}` : null };
  db.data.transactions.push(t);
  const prod = db.data.products.find(p => p.id === req.body.productId);
  if (prod && req.body.notes) prod.notes = req.body.notes;
  await db.write(); res.status(201).json(t);
});

// --- 汇率同步逻辑 ---
let cachedRate = 7.25;
let lastRateFetch = 0;
app.get('/api/exchange-rate', async (req, res) => {
  // 如果缓存超过 10 分钟，或者强制刷新请求，则尝试更新
  if (Date.now() - lastRateFetch > 600000 || req.query.force === 'true') {
    try {
      // 切换到更稳定的 API 源，并增加超时处理
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch('https://open.er-api.com/v6/latest/USD', { signal: controller.signal });
      const data = await response.json();
      
      if (data && data.rates && data.rates.CNY) {
        cachedRate = parseFloat(data.rates.CNY.toFixed(4));
        lastRateFetch = Date.now();
        console.log(`[ExchangeRate] Updated: 1 USD = ${cachedRate} CNY`);
      }
      clearTimeout(timeoutId);
    } catch (e) {
      console.error('[ExchangeRate] Fetch failed, using cache:', e.message);
    }
  }
  res.json({ rate: cachedRate, lastUpdate: lastRateFetch });
});

// --- 统计与档案辅助 ---
app.get('/api/dashboard-stats', authenticate, async (req, res) => {
  const db = await getDb();
  const role = req.user.role;
  const sampleIds = db.data.products.filter(p => p.category?.includes('样品')).map(p => p.id);
  const trans = role !== 'staff' ? db.data.transactions : db.data.transactions.filter(t => t.userId === req.user.id || sampleIds.includes(t.productId));
  const productMix = db.data.products.map(p => {
    const pt = db.data.transactions.filter(t => t.productId === p.id);
    const rt = (role !== 'staff' || p.category?.includes('样品')) ? pt : pt.filter(t => t.userId === req.user.id);
    return { name: p.name, balance: Math.max(0, rt.reduce((a, b) => b.type === 'in' ? a + b.quantity : a - b.quantity, 0)), category: p.category };
  }).filter(p => p.balance > 0);
  let lb = [];
  if (role !== 'staff') {
    lb = db.data.users.map(u => {
      const amt = db.data.transactions.filter(t => t.userId === u.id && t.type === 'out').reduce((sum, t) => {
        const prod = db.data.products.find(p => p.id === t.productId);
        return sum + (t.quantity * (prod?.unitPrice || 0));
      }, 0);
      return { username: u.username, totalAmount: amt };
    }).sort((a,b) => b.totalAmount - a.totalAmount).slice(0, 5);
  }
  res.json({ performance: { totalOut: trans.filter(t=>t.type==='out').reduce((a,b)=>a+b.quantity,0), totalIn: trans.filter(t=>t.type==='in').reduce((a,b)=>a+b.quantity,0), transCount: trans.length, activeSkus: productMix.length }, productMix, leaderboard: lb });
});

app.get('/api/customers', authenticate, async (req, res) => { 
  const db = await getDb(); 
  res.json(db.data.customers || []); 
});
app.delete('/api/customers/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  db.data.customers = db.data.customers.filter(c => c.id !== req.params.id);
  await db.write(); res.json({ message: 'Deleted' });
});
app.post('/api/customers', authenticate, async (req, res) => {
  const db = await getDb(); 
  const c = { ...req.body, id: Date.now().toString(), createdBy: req.user.id };
  db.data.customers.push(c); await db.write(); res.json(c);
});

app.get('/api/factories', authenticate, async (req, res) => { const db = await getDb(); res.json(db.data.factories || []); });
app.delete('/api/factories/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  db.data.factories = db.data.factories.filter(f => f.id !== req.params.id);
  await db.write(); res.json({ message: 'Deleted' });
});
app.post('/api/factories', authenticate, async (req, res) => {
  if (req.user.role === 'staff') return res.status(403).json({ message: 'No' });
  const db = await getDb(); const f = { ...req.body, id: Date.now().toString(), color: '#6366f1' };
  db.data.factories.push(f); await db.write(); res.json(f);
});

app.get('/api/categories', authenticate, async (req, res) => { const db = await getDb(); res.json(db.data.categories || ['嘴贴', '鼻贴', '样品']); });
app.post('/api/categories', authenticate, async (req, res) => {
  if (req.user.role === 'staff') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb(); db.data.categories = db.data.categories || [];
  if(!db.data.categories.includes(req.body.name)) db.data.categories.push(req.body.name);
  await db.write(); res.json(db.data.categories);
});
app.delete('/api/categories/:name', authenticate, async (req, res) => {
  if (req.user.role === 'staff') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  db.data.categories = (db.data.categories || []).filter(c => c !== req.params.name);
  await db.write();
  res.json(db.data.categories);
});

app.listen(5000, '0.0.0.0', () => console.log(`Server fully restored on port 5000`));
