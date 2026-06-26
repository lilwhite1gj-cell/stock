import bcrypt from 'bcryptjs';
import { getDb } from './src/db.js';

async function reset() {
  const db = await getDb();
  
  // Reset admin
  const admin = db.data.users.find(u => u.username === 'admin');
  if (admin) {
    admin.password = await bcrypt.hash('admin123', 10);
    console.log('Admin password reset to admin123');
  }

  // Reset staff
  const staff = db.data.users.find(u => u.username === 'staff');
  if (staff) {
    staff.password = await bcrypt.hash('staff123', 10);
    console.log('Staff password reset to staff123');
  }

  await db.write();
}

reset();
