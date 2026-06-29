import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { getDb } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '../public/uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, '../public/uploads')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.get('/', (req, res) => res.render('index'));

const SECRET = process.env.JWT_SECRET || 'mouth-nasal-tape-secret';

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Token invalid' });
    req.user = decoded;
    next();
  });
};

// --- Auth ---
app.post('/api/register', async (req, res) => {
  const { username, password, phone, question, answer } = req.body;
  const db = await getDb();
  if (db.data.users.find(u => u.username === username)) return res.status(400).json({ message: '用户名已占用' });
  const hashedPassword = await bcrypt.hash(password, 10);
  db.data.users.push({ 
    id: Date.now().toString(), 
    username, 
    password: hashedPassword, 
    role: 'staff',
    phone: phone || '',
    securityQuestion: question || '',
    securityAnswer: answer || '' // 实际项目中建议也进行哈希，此处为方便找回直接存储
  });
  await db.write();
  res.status(201).json({ message: 'Success' });
});

app.post('/api/forgot-password-verify', async (req, res) => {
  const { username } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  if (!user.securityQuestion) return res.status(400).json({ message: '该用户未设置密保信息，请联系管理员' });
  res.json({ question: user.securityQuestion });
});

app.post('/api/reset-password-now', async (req, res) => {
  const { username, phone, answer, newPassword } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  if (!user || user.phone !== phone || user.securityAnswer !== answer) {
    return res.status(401).json({ message: '验证信息不匹配，重置失败' });
  }
  user.password = await bcrypt.hash(newPassword, 10);
  await db.write();
  res.json({ message: '密码重置成功' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for user: ${username}`);
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  
  if (!user) {
    console.log(`User not found: ${username}`);
    return res.status(401).json({ message: '用户不存在' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    console.log(`Login successful: ${username}`);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } else {
    console.log(`Password mismatch for user: ${username}`);
    res.status(401).json({ message: '密码错误' });
  }
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

// 12. Admin User Management
app.get('/api/admin/users', authenticate, async (req, res) => {
  try {
    const role = (req.user.role || '').toLowerCase();
    if (role !== 'admin' && role !== 'manager') {
      return res.status(403).json({ message: '需要管理员权限' });
    }

    const db = await getDb();
    const users = db.data.users.map(({ password, ...u }) => u);
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: '服务器内部错误' });
  }
});

app.post('/api/admin/change-role', authenticate, async (req, res) => {
  const myRole = (req.user.role || '').toLowerCase();
  if (myRole !== 'admin') return res.status(403).json({ message: '只有最高管理员可以调整角色' });
  
  const { userId, newRole } = req.body;
  if (!['manager', 'staff'].includes(newRole)) return res.status(400).json({ message: '无效的角色类型' });
  
  const db = await getDb();
  const targetUser = db.data.users.find(u => u.id === userId);
  if (!targetUser) return res.status(404).json({ message: '用户不存在' });
  if (targetUser.role === 'admin') return res.status(403).json({ message: '最高管理员权限不可被修改' });

  targetUser.role = newRole;
  await db.write();
  res.json({ message: `用户 ${targetUser.username} 的权限已调整为 ${newRole}` });
});

app.post('/api/admin/reset-user-password', authenticate, async (req, res) => {
  const myRole = (req.user.role || '').toLowerCase();
  if (myRole !== 'admin' && myRole !== 'manager') return res.status(403).json({ message: '无权限' });
  
  const { userId, newPassword } = req.body;
  const db = await getDb();
  const targetUser = db.data.users.find(u => u.id === userId);
  if (!targetUser) return res.status(404).json({ message: '用户不存在' });

  // 权限校验：普通管理员不能重置 admin 或 manager
  if (myRole === 'manager' && (targetUser.role === 'admin' || targetUser.role === 'manager')) {
    return res.status(403).json({ message: '普通管理员无权修改高级别账号密码' });
  }
  
  targetUser.password = await bcrypt.hash(newPassword, 10);
  await db.write();
  res.json({ message: `用户 ${targetUser.username} 的密码已重置` });
});

app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
  const myRole = (req.user.role || '').toLowerCase();
  if (myRole !== 'admin') return res.status(403).json({ message: '只有最高管理员可以删除用户' });
  
  const db = await getDb();
  const targetUser = db.data.users.find(u => u.id === req.params.id);
  if (!targetUser) return res.status(404).json({ message: '用户不存在' });
  if (targetUser.role === 'admin') return res.status(403).json({ message: '无法删除最高管理员' });
  if (req.params.id === req.user.id) return res.status(400).json({ message: '不能删除自己' });

  db.data.users = db.data.users.filter(u => u.id !== req.params.id);
  await db.write();
  res.json({ message: '用户已删除' });
});

// --- Products ---
app.get('/api/products', authenticate, async (req, res) => {
  const db = await getDb();
  res.json(db.data.products);
});

app.post('/api/products', authenticate, upload.single('image'), async (req, res) => {
  const db = await getDb();
  const { name, sku, category, spec, material, unitPrice, factoryId, factoryName, customerId, customerName, packaging, notes } = req.body;
  const newProduct = { 
    id: Date.now().toString(), name, sku, category: category || '默认', spec: spec || '', material: material || '',
    unitPrice: parseFloat(unitPrice) || 0,
    packaging: packaging || '',
    notes: notes || '',
    factoryId: factoryId || null,
    factoryName: factoryName || null,
    customerId: customerId || null,
    customerName: customerName || null,
    image: req.file ? `/uploads/${req.file.filename}` : null,
    createdBy: req.user.id,
    creatorName: req.user.username
  };
  db.data.products.push(newProduct);
  await db.write();
  res.status(201).json(newProduct);
});

app.put('/api/products/:id', authenticate, upload.single('image'), async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  const product = db.data.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ message: '未找到' });
  const { name, sku, category, spec, material, unitPrice, factoryId, factoryName, customerId, customerName, packaging, notes } = req.body;
  if (name) product.name = name;
  if (sku) product.sku = sku;
  if (category) product.category = category;
  if (spec !== undefined) product.spec = spec;
  if (material !== undefined) product.material = material;
  if (unitPrice !== undefined) product.unitPrice = parseFloat(unitPrice) || 0;
  if (packaging !== undefined) product.packaging = packaging;
  if (notes !== undefined) product.notes = notes;
  if (factoryId !== undefined) product.factoryId = factoryId;
  if (factoryName !== undefined) product.factoryName = factoryName;
  if (customerId !== undefined) product.customerId = customerId;
  if (customerName !== undefined) product.customerName = customerName;
  if (req.file) product.image = `/uploads/${req.file.filename}`;
  await db.write();
  res.json({ message: 'OK' });
});

app.delete('/api/products/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  if (db.data.transactions.some(t => t.productId === req.params.id)) return res.status(400).json({ message: '该产品已有流水，请先删除流水' });
  db.data.products = db.data.products.filter(p => p.id !== req.params.id);
  await db.write();
  res.json({ message: 'Deleted' });
});

// --- Transactions ---
app.get('/api/transactions', authenticate, async (req, res) => {
  const db = await getDb();
  const role = (req.user.role || '').toLowerCase();
  let results = db.data.transactions;
  if (role !== 'admin' && role !== 'manager') {
    // 权限穿透：包含“样品”字样的品类，全员可见
    const sampleProductIds = db.data.products.filter(p => p.category && p.category.includes('样品')).map(p => p.id);
    results = results.filter(t => t.userId === req.user.id || sampleProductIds.includes(t.productId));
  }
  res.json(results);
});

// --- Common Data ---
app.get('/api/inventory', authenticate, async (req, res) => {
  const db = await getDb();
  const role = (req.user.role || '').toLowerCase();
  const inventory = db.data.products.map(p => {
    const pTrans = db.data.transactions.filter(t => t.productId === p.id);
    const isSample = p.category && p.category.includes('样品');
    const relTrans = (role === 'admin' || role === 'manager' || isSample) ? pTrans : pTrans.filter(t => t.userId === req.user.id);
    const balance = relTrans.reduce((acc, t) => t.type === 'in' ? acc + t.quantity : acc - t.quantity, 0);
    return { ...p, balance };
  });
  res.json(inventory);
});

app.post('/api/transactions', authenticate, upload.single('transImage'), async (req, res) => {
  const db = await getDb();
  const { productId, type, quantity, notes, orderNo, logisticsNo } = req.body;
  
  // 1. 创建流水记录
  const transaction = {
    id: Date.now().toString(), productId, type, quantity: parseInt(quantity),
    userId: req.user.id, username: req.user.username, date: new Date().toISOString(),
    notes: notes || '', orderNo: orderNo || '', logisticsNo: logisticsNo || '',
    image: req.file ? `/uploads/${req.file.filename}` : null
  };
  db.data.transactions.push(transaction);

  // 2. 同步更新产品档案备注 (核心同步逻辑)
  const product = db.data.products.find(p => p.id === productId);
  if (product && notes) {
    product.notes = notes;
  }

  await db.write();
  res.status(201).json(transaction);
});

app.delete('/api/transactions/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  db.data.transactions = db.data.transactions.filter(t => t.id !== req.params.id);
  await db.write();
  res.json({ message: 'Deleted' });
});

app.get('/api/categories', authenticate, async (req, res) => {
  const db = await getDb();
  res.json(db.data.categories || ['嘴贴', '鼻贴', '样品']);
});

app.post('/api/categories', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  db.data.categories = db.data.categories || [];
  if (!db.data.categories.includes(req.body.name)) db.data.categories.push(req.body.name);
  await db.write();
  res.status(201).json(db.data.categories);
});

app.delete('/api/categories/:name', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'No Permission' });
  const db = await getDb();
  db.data.categories = (db.data.categories || []).filter(c => c !== req.params.name);
  await db.write();
  res.json(db.data.categories);
});

app.get('/api/dashboard-stats', authenticate, async (req, res) => {
  const db = await getDb();
  const role = (req.user.role || '').toLowerCase();
  const isStaff = role === 'staff';
  const sampleProductIds = db.data.products.filter(p => p.category && p.category.includes('样品')).map(p => p.id);
  
  const myTrans = isStaff ? db.data.transactions.filter(t => t.userId === req.user.id || sampleProductIds.includes(t.productId)) : db.data.transactions;
  
  const productMix = db.data.products.map(p => {
    const pt = db.data.transactions.filter(t => t.productId === p.id);
    const isSample = p.category && p.category.includes('样品');
    const rt = (role === 'admin' || role === 'manager' || isSample) ? pt : pt.filter(t => t.userId === req.user.id);
    const bal = rt.reduce((a, b) => b.type === 'in' ? a + b.quantity : a - b.quantity, 0);
    return { name: p.name, balance: Math.max(0, bal), category: p.category };
  }).filter(p => p.balance > 0);
  
  let leaderboard = [];
  if (!isStaff) {
    leaderboard = db.data.users.map(u => ({ username: u.username, totalOut: db.data.transactions.filter(t => t.userId === u.id && t.type === 'out').reduce((a,b)=>a+b.quantity,0) })).sort((a,b)=>b.totalOut - a.totalOut).slice(0, 5);
  }
  res.json({ productMix, performance: { totalOut: myTrans.filter(t=>t.type==='out').reduce((a,b)=>a+b.quantity,0), totalIn: myTrans.filter(t=>t.type==='in').reduce((a,b)=>a+b.quantity,0), transCount: myTrans.length, activeSkus: productMix.length }, leaderboard });
});

app.get('/api/backup', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: 'No' });
  res.download(path.join(__dirname, '../data/db.json'), `Backup_${new Date().toISOString().split('T')[0]}.json`);
});

// 10. Factories Management
app.get('/api/factories', authenticate, async (req, res) => {
  const db = await getDb();
  res.json(db.data.factories || []);
});

app.post('/api/factories', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const { name, address } = req.body;
  const db = await getDb();
  db.data.factories = db.data.factories || [];
  if (db.data.factories.find(f => f.name === name)) return res.status(400).json({ message: '该工厂已存在' });
  
  const colors = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#0ea5e9'];
  const color = colors[db.data.factories.length % colors.length];

  const newFactory = { id: Date.now().toString(), name, address, color };
  db.data.factories.push(newFactory);
  await db.write();
  res.status(201).json(newFactory);
});

app.delete('/api/factories/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  db.data.factories = (db.data.factories || []).filter(f => f.id !== req.params.id);
  await db.write();
  res.json({ message: 'Deleted' });
});

// 11. Customers Management
app.get('/api/customers', authenticate, async (req, res) => {
  const db = await getDb();
  res.json(db.data.customers || []);
});

app.post('/api/customers', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const { name, contact, address, phone } = req.body;
  const db = await getDb();
  db.data.customers = db.data.customers || [];
  if (db.data.customers.find(c => c.name === name)) return res.status(400).json({ message: '该客户已存在' });
  
  const newCustomer = { id: Date.now().toString(), name, contact: contact || '', address: address || '', phone: phone || '' };
  db.data.customers.push(newCustomer);
  await db.write();
  res.status(201).json(newCustomer);
});

app.delete('/api/customers/:id', authenticate, async (req, res) => {
  const role = (req.user.role || '').toLowerCase();
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ message: '无权限' });
  const db = await getDb();
  db.data.customers = (db.data.customers || []).filter(c => c !== req.params.id);
  await db.write();
  res.json({ message: 'Deleted' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
