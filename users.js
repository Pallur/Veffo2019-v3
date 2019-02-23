const bcrypt = require('bcrypt');
const { Client } = require('pg');

const connectionString = process.env.DATABASE_URL;

async function query(q, values = []) {
  const client = new Client({ connectionString });
  await client.connect();

  try {
    const result = await client.query(q, values);

    return result;
  } catch (err) {
    throw err;
  } finally {
    await client.end();
  }
}

async function comparePasswords(password, user) {
  const result = await bcrypt.compare(password, user.password);

  if (result) {
    return user;
  }
  return false;
}

async function findByUsername(username) {
  const q = 'SELECT * FROM users WHERE username = $1';
  const result = await query(q, [username]);

  if (result.rowCount === 1) {
    return result.rows[0];
  }

  return null;
}

async function findById(id) {
  const q = 'SELECT * FROM users WHERE id = $1';
  const result = await query(q, [id]);

  if (result.rowCount === 1) {
    return result.rows[0];
  }

  return null;
}

async function setAdminFalse() {
  const q = 'UPDATE users SET admin = false where admin = true';
  const done = await query(q); // eslint-disable-line
}

async function setAdmin(usernames) {
  const q = 'UPDATE users SET admin = true WHERE username = $1';
  for (let i = 0; i < usernames.length; i++) { // eslint-disable-line
    console.log('Notandi er admin: ' + usernames[i]); // eslint-disable-line
    const result = await query(q, [usernames[i]]); // eslint-disable-line
  }
}

module.exports = {
  comparePasswords,
  findByUsername,
  findById,
  setAdminFalse,
  setAdmin,
};
