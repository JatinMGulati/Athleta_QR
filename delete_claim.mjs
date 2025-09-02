import sqlite3 from 'sqlite3';
sqlite3.verbose();

const email = process.argv[2];
if (!email) {
  console.error('Usage: node delete_claim.mjs <email>');
  process.exit(1);
}

const db = new sqlite3.Database('./claims.db', (err) => {
  if (err) {
    console.error('Failed to open DB:', err.message);
    process.exit(2);
  }
});

function printCount(label, cb) {
  db.get('SELECT COUNT(*) as cnt FROM claims', (err, row) => {
    if (err) return cb(err);
    console.log(`${label} count:`, row.cnt);
    cb(null, row.cnt);
  });
}

printCount('Before', (err) => {
  if (err) {
    console.error('Error reading before count:', err);
    db.close();
    process.exit(3);
  }

  db.run('DELETE FROM claims WHERE email = ?', [email], function(err) {
    if (err) {
      console.error('Delete error:', err.message);
      db.close();
      process.exit(4);
    }
    console.log(`Deleted rows: ${this.changes}`);

    printCount('After', (err2) => {
      if (err2) console.error('Error reading after count:', err2);
      db.close();
      process.exit(0);
    });
  });
});
