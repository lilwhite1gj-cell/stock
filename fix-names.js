import { getDb } from './src/db.js';

async function fixNames() {
  const db = await getDb();
  const adminId = "1"; // 预设管理员 ID
  
  // 1. 修复产品责任人
  db.data.products.forEach(p => {
    if (!p.creatorName || p.creatorName === '系统') {
      const user = db.data.users.find(u => u.id === p.createdBy);
      if (user) {
        p.creatorName = user.username;
      } else {
        p.creatorName = "管理员";
      }
    }
  });

  // 2. 修复流水录入人
  db.data.transactions.forEach(t => {
    if (!t.username || t.username === '系统') {
      const user = db.data.users.find(u => u.id === t.userId);
      if (user) {
        t.username = user.username;
      } else {
        t.username = "管理员";
      }
    }
  });

  await db.write();
  console.log("Names fixed in database.");
}

fixNames();
