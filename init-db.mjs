import bcrypt from 'bcryptjs';
import { getDb } from './src/db.js';

async function init() {
  const db = await getDb();
  
  if (db.data.users.length === 0) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    db.data.users.push({
      id: '1',
      username: 'admin',
      password: hashedPassword,
      role: 'admin'
    });
    
    // Also create a staff user for testing
    const staffPassword = await bcrypt.hash('staff123', 10);
    db.data.users.push({
      id: '2',
      username: 'staff',
      password: staffPassword,
      role: 'staff'
    });
    
    await db.write();
    console.log('Default users created: admin/admin123, staff/staff123');
  } else {
    console.log('Users already exist.');
  }
}

init();
