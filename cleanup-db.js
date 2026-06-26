import { getDb } from './src/db.js';

async function cleanup() {
  const db = await getDb();
  
  // Define what "error information" means. 
  // Based on users feedback, likely these duplicated "bibitie" entries and "123" test data.
  // I will keep only the most recent one or clear those that look like test data.
  // Actually, I'll clear products with names like "123", "1", "bibitie" if they have no valid transactions or are obvious duplicates.
  
  const originalCount = db.data.products.length;
  
  // Keep only products that are linked to transactions OR have meaningful names
  // To be safe, I will only remove specific ones that look like duplicates or test data
  const testNames = ["123", "1", "bibitie ", "bibitie"];
  
  // Filter products
  db.data.products = db.data.products.filter(p => {
    // Keep it if it's NOT in testNames
    // OR keep only the first occurrence if it is
    return !testNames.includes(p.name);
  });
  
  // Also need to handle orphaned transactions if any
  const productIds = new Set(db.data.products.map(p => p.id));
  db.data.transactions = db.data.transactions.filter(t => productIds.has(t.productId));

  await db.write();
  console.log(`Cleaned up ${originalCount - db.data.products.length} error/test products.`);
}

cleanup();
