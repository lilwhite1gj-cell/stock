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

// Multer Image Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '../public/uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, '../public/uploads')));

// Set view engine
app.set('view engine', 'ejs');

// Render main page
app.get('/', (req, res) => {
  res.render('index');
});

const SECRET = process.env.JWT_SECRET || 'mouth-nasal-tape-secret';

// Auth Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
    req.user = decoded;
    next();
  });
};

// --- API Routes ---

// 1. Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const db = await getDb();
  if (db.data.users.find(u => u.username === username)) {
    return res.status(400).json({ message: '用户名已存在' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, role: 'staff' };
  db.data.users.push(newUser);
  await db.write();
  res.status(201).json({ message: '注册成功' });
});

// 2. Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '24h' });
    res.json({ token, user: { username: user.username, role: user.role } });
  } else {
    res.status(401).json({ message: '用户名或密码错误' });
  }
});

// 3. Change Password
app.post('/api/change-password', authenticate, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const db = await getDb();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
    return res.status(401).json({ message: '旧密码错误' });
  }
  user.password = await bcrypt.hash(newPassword, 10);
  await db.write();
  res.json({ message: '密码修改成功' });
});

// 4. Products
app.get('/api/products', authenticate, async (req, res) => {
  const db = await getDb();
  res.json(db.data.products);
});

app.post('/api/products', authenticate, upload.single('image'), async (req, res) => {
  const db = await getDb();
  const { name, sku, category, spec, material } = req.body;
  const newProduct = { 
    id: Date.now().toString(), name, sku, category: category || '默认', spec: spec || '', material: material || '',
    image: req.file ? `/uploads/${req.file.filename}` : null,
    createdBy: req.user.id 
  };
  db.data.products.push(newProduct);
  await db.write();
  res.status(201).json(newProduct);
});

// 5. Transactions
app.get('/api/transactions', authenticate, async (req, res) => {
  const db = await getDb();
  let results = db.data.transactions;
  if (req.user.role !== 'admin') {
    results = results.filter(t => t.userId === req.user.id);
  }
  res.json(results);
});

app.post('/api/transactions', authenticate, async (req, res) => {
  const db = await getDb();
  const { productId, type, quantity, notes, orderNo, logisticsNo } = req.body;
  const transaction = {
    id: Date.now().toString(), productId, type, quantity: parseInt(quantity),
    userId: req.user.id, username: req.user.username, date: new Date().toISOString(),
    notes: notes || '', orderNo: orderNo || '', logisticsNo: logisticsNo || ''
  };
  db.data.transactions.push(transaction);
  await db.write();
  res.status(201).json(transaction);
});

// 6. Inventory Ledger
app.get('/api/inventory', authenticate, async (req, res) => {
  const db = await getDb();
  const { products, transactions } = db.data;
  const inventory = products.map(p => {
    const pTransactions = transactions.filter(t => t.productId === p.id);
    const userTransactions = req.user.role === 'admin' ? pTransactions : pTransactions.filter(t => t.userId === req.user.id);
    const balance = userTransactions.reduce((acc, t) => t.type === 'in' ? acc + t.quantity : acc - t.quantity, 0);
    return { ...p, balance };
  });
  res.json(inventory);
});

// 7. Backup
app.get('/api/backup', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: '无权限' });
  const dbPath = path.join(__dirname, '../data/db.json');
  res.download(dbPath, `库存备份_${new Date().toISOString().split('T')[0]}.json`);
});

// 8. Enhanced Dashboard Stats
app.get('/api/dashboard-stats', authenticate, async (req, res) => {
  const db = await getDb();
  const { products, transactions, users } = db.data;
  const isAlt = req.user.role !== 'admin';
  const myTransactions = isAlt ? transactions.filter(t => t.userId === req.user.id) : transactions;

  const productMix = products.map(p => {
    const pTrans = transactions.filter(t => t.productId === p.id);
    const relevantTrans = isAlt ? pTrans.filter(t => t.userId === req.user.id) : pTrans;
    const balance = relevantTrans.reduce((acc, t) => t.type === 'in' ? acc + t.quantity : acc - t.quantity, 0);
    return { name: p.name, balance: Math.max(0, balance) };
  }).filter(p => p.balance > 0);

  const totalOut = myTransactions.filter(t => t.type === 'out').reduce((a, b) => a + b.quantity, 0);
  const totalIn = myTransactions.filter(t => t.type === 'in').reduce((a, b) => a + b.quantity, 0);
  
  let leaderboard = [];
  if (!isAlt) {
    leaderboard = users.map(u => {
      const uOut = transactions.filter(t => t.userId === u.id && t.type === 'out').reduce((a, b) => a + b.quantity, 0);
      return { username: u.username, totalOut: uOut };
    }).sort((a, b) => b.totalOut - a.totalOut).slice(0, 5);
  }

  res.json({
    productMix,
    performance: { totalOut, totalIn, transCount: myTransactions.length, activeSkus: productMix.length },
    leaderboard
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
