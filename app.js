require('dotenv').config();

const path = require('path');
const express = require('express');
const sessionSecret = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-local');

const apply = require('./apply');
const register = require('./register');
const admin = require('./admin');
const applications = require('./applications');
const users = require('./users');

/* todo sækja stillingar úr env */

if (!sessionSecret) {
  console.error('Add SESSION_SECRET to .env');
  process.exit(1);
}

const app = express();

const {
  HOST: hostname = '127.0.0.1',
  PORT: port = 3000,
} = process.env;

app.use(express.urlencoded({ extended: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, 'public')));


app.use(sessionSecret({
  resave: false,
  saveUninitialized: true,
  // secret: sessionSecret,
  secret: 'secret here',
}));

app.use(passport.initialize());
app.use(passport.session());

async function strat(username, password, done) {
  try {
    const user = await users.findByUsername(username);

    if (!user) {
      return done(null, false);
    }

    const passwordValid = await users.comparePasswords(password, user);

    done(null, passwordValid);
  } catch (err) {
    done(null, err);
  }

  return false;
}

passport.use(new Strategy(strat));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await users.findById(id);
    return done(null, user);
  } catch (error) {
    return done(error);
  }
});

app.use((req, res, next) => {
  if (req.isAuthenticated()) {
    res.locals.user = req.user;
    res.locals.login = req.isAuthenticated();
    res.locals.isAdmin = req.user.admin;
  }
  next();
});

app.use('/', apply);

app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/applications', applications);
  }
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Innskráning', username: '', password: '', errors: [], page: 'login',
  });
});

app.post(
  '/login',
  passport.authenticate('local', {
    failureMessage: 'Notandi eða lykilorð vitlaust.',
    failureRedirect: '/login',
  }),
  (req, res) => {
    res.redirect('/applications');
  },
);

/**
 * Hjálparfall til að athuga hvort reitur sé gildur eða ekki.
 *
 * @param {string} field Middleware sem grípa á villur fyrir
 * @param {array} errors Fylki af villum frá express-validator pakkanum
 * @returns {boolean} `true` ef `field` er í `errors`, `false` annars
 */
function isInvalid(field, errors) {
  return Boolean(errors.find(i => i.param === field));
}

app.locals.isInvalid = isInvalid;

/* todo setja upp login og logout virkni */

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.use('/', apply);
app.use('/register', register);
app.use('/applications', applications);
app.use('/admin', admin);

function notFoundHandler(req, res, next) { // eslint-disable-line
  res.status(404).render('error', { page: 'error', title: '404', error: '404 fannst ekki' });
}

function errorHandler(error, req, res, next) { // eslint-disable-line
  console.error(error);
  res.status(500).render('error', { page: 'error', title: 'Villa', error });
}

app.use(notFoundHandler);
app.use(errorHandler);

app.listen(port, hostname, () => {
  console.info(`Server running at http://${hostname}:${port}/`);
});
