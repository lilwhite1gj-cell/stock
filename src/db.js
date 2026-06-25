import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';

const defaultData = { 
  users: [], 
  products: [], 
  transactions: [] 
};

export const getDb = async () => {
  const adapter = new JSONFile('data/db.json');
  const db = new Low(adapter, defaultData);
  await db.read();
  // Ensure data exists
  db.data ||= defaultData;
  return db;
};
