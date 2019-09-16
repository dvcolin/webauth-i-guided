const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());


server.get('/hash', (req, res) => {
  const name = req.query.name;
  // hash the name
  const hash = bcrypt.hashSync(name, 12); // use bcryptjs to hash the name
  res.send(`the hash for ${name} is ${hash}`);
});


server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  const hash = bcrypt.hashSync(password, 12);

  Users.add({ username, password: hash })
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check password
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'You cannot pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', validateCredentials, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});



function validateCredentials(req, res, next) {
  let { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({ message: 'Invalid credentials' })
      }
    })
  } else {
    res.status(400).json({ message: 'No credentials provided' });
  }
}


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
