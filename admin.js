const express = require('express');
const { select2 } = require('./db');

const {
  setAdmin,
  setAdminFalse,
} = require('./users');

const router = express.Router();

// Hjálpar middleware sem athugar hvort notandi sé innskráður og hleypir okkur
// þá áfram, annars sendir á /login
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.redirect('/login');
}

async function admin(req, res) {
  const list = await select2();

  res.render('admin', { title: 'Notendalisti', list, page: 'admin' });
}

async function adminUser(req, res) {
  // Setjum alla notendur með false
  await setAdminFalse();

  // Setjum þá sem voru valdir sem admin
  const usernames = req.body.admin;
  await setAdmin(usernames);

  const list = await select2();
  res.render('admin', { title: 'Notendalisti', list, page: 'admin' });
}

function catchErrors(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

router.get('/', ensureLoggedIn, catchErrors(admin));
router.post('/', adminUser);

module.exports = router;
