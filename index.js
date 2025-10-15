import bcrypt from 'bcrypt';
import express from 'express';
import pg from 'pg';
import validator from 'validator';

const app = express();
const port = 3000;

app.set('view engine', 'hbs');

app.use(express.urlencoded({ extended: false }));

// Route to index.hbs
app.get('/', (req, res) => {
  res.render('index')
});

// Post user account
app.post('/register', (req, res) => {
  console.log(req.body);
  res.redirect('/')
});

app.listen(port, () => {
  console.log(`Web application can be accessed at http://localhost:3000`);
});