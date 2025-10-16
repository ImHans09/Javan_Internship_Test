import bcrypt from 'bcrypt';
import dotenv from 'dotenv'
import express from 'express';
import flash from 'connect-flash';
import session from 'express-session';
import validator from 'validator';
import { Pool } from 'pg';

dotenv.config();

const app = express();
const port = 3000;
const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
  max: process.env.DB_MAX
});

app.set('view engine', 'hbs');

app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'keySecret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 3600000 }
}));
app.use(flash());

// Route to index.hbs
app.get('/', getHomePage);

// Post user account
app.post('/register-user', registerUser);

// Route to project_detail.hbs
app.get('/user-detail/:id', getUserDetailPage);

// Delete user account
app.post('/delete-user/:id', deleteUser);

async function getHomePage(req, res) {
  try {
    const warningMessage = req.flash('warningMessage')[0] || '';
    const successMessage = req.flash('successMessage')[0] || '';
    const query = {
      name: 'fetch-all-users',
      text: 'SELECT id, name FROM users'
    };
    const users = await pool.query(query);
    const data = {
      warningMessage: warningMessage,
      successMessage: successMessage,
      users: users.rows
    };

    res.render('index', data);
  } catch (error) {
    console.error('ERROR: ', error);
    res.status(500).send('Internal Server Error');
  }
}

async function registerUser(req, res) {
  try {
    const { username, email, password, verifyPassword } = req.body;

    if (!username) {
      req.flash('warningMessage', "Username can't be empty.");
      return res.redirect('/');
    }

    if (!validator.isEmail(email)) {
      req.flash('warningMessage', 'Please input a valid email.');
      return res.redirect('/');
    }

    const fetchUserQuery = {
      name: 'fetch-user',
      text: "SELECT email FROM users WHERE email = $1",
      values: [email]
    };
    const user = await pool.query(fetchUserQuery);

    if (user.rowCount > 0) {
      req.flash('warningMessage', 'This email has been registered.');
      return res.redirect('/');
    }

    if (password.length < 8) {
      req.flash('warningMessage', 'Password must be 8 characters or longer.');
      return res.redirect('/');
    }

    if (password !== verifyPassword) {
      req.flash('warningMessage', 'Verify password is unmatched.');
      return res.redirect('/');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const insertUserQuery = {
      name: 'insert-user',
      text: "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
      values: [username, email, hashedPassword]
    };

    await pool.query(insertUserQuery);
    req.flash('successMessage', 'Register user account successfully.');

    res.redirect('/');
  } catch (error) {
    console.error('ERROR: ', error);
    res.status(400).send('Bad Request');
  }
}

async function getUserDetailPage(req, res) {
  try {
    const userId = Number(req.params.id);

    if (typeof userId !== 'number') {
      req.flash('warningMessage', "Can't delete user. User id is wrong.")
      return res.redirect('/');
    }

    const query = {
      name: 'fetch-user-detail',
      text: "SELECT id, name, email FROM users WHERE id = $1",
      values: [userId]
    };
    const user = await pool.query(query);

    if (user.rowCount === 0) {
      req.flash('warningMessage', "User is not found.")
      return res.redirect('/');
    }

    res.render('user_detail', user.rows[0]);
  } catch (error) {
    console.error('ERROR: ', error);
    res.status(400).send('Bad Request');
  }
}

async function deleteUser(req, res) {
  try {
    const userId = Number(req.params.id);
  
    if (typeof userId !== 'number') {
      req.flash('warningMessage', "Can't delete user. User id is wrong.")
      return res.redirect('/');
    }

    const query = {
      name: 'delete-user',
      text: 'DELETE FROM users WHERE id = $1',
      values: [userId]
    };

    await pool.query(query);
    req.flash('successMessage', 'Delete user account successfully.');

    res.redirect('/');
  } catch (error) {
    console.error('ERROR: ', error);
    res.status(400).send('Bad Request');
  }
}

app.listen(port, () => {
  console.log(`Web application can be accessed at http://localhost:3000`);
});