require('dotenv').config();

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

async function insert(data) {
  const q = `
INSERT INTO applications
(name, email, phone, text, job)
VALUES
($1, $2, $3, $4, $5)`;
  const values = [data.name, data.email, data.phone, data.text, data.job];

  return query(q, values);
}

async function select() {
  const result = await query('SELECT * FROM applications ORDER BY id');

  return result.rows;
}

async function update(id) {
  const q = `
UPDATE applications
SET processed = true, updated = current_timestamp
WHERE id = $1`;

  return query(q, id);
}

async function deleteRow(id) {
  const q = 'DELETE FROM applications WHERE id = $1';

  return query(q, id);
}

async function insert2(data) {
  const q = `
INSERT INTO users
(username, password, name, email)
VALUES
($1, $2, $3, $4)`;
  const values = [data.username, data.password, data.name, data.email];

  return query(q, values);
}

async function select2() {
  const result = await query('SELECT * FROM users ORDER BY id');

  return result.rows;
}

async function update2(id) {
  const q = `
UPDATE users
SET isAdmin = true, updated = current_timestamp
WHERE id = $1`;

  return query(q, id);
}

async function deleteRow2(id) {
  const q = 'DELETE FROM users WHERE id = $1';

  return query(q, id);
}

module.exports = {
  query,
  insert,
  select,
  update,
  deleteRow, // delete er frátekið orð
  insert2,
  select2,
  update2,
  deleteRow2,
};
