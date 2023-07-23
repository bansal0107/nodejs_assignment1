const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const cookieParser = require('cookie-parser');

const app = express();

const PORT = 3000;
const secretKey = 'your_secret_key'; // Replace this with your own secret key for signing JWT

app.use(cookieParser());

// MongoDB connection URL 
mongoose.connect('mongodb+srv://sakshi01:Bangalore01@sakshi.tfswvtq.mongodb.net/')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));

// User schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));

// Home page
app.get('/', (req, res) => {
  res.render('login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

// Register page
app.get('/register', (req, res) => {
  res.render('register');
});


// Register route
app.post('/register', async (req, res) => {
  const { name, username, password, role } = req.body;

  try {
    // Check if the username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.render('register', { error: 'Username is already taken. Please choose another username.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user in the database
    const newUser = new User({
      name,
      username,
      password: hashedPassword,
      role
    });

    await newUser.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).send('An error occurred while registering the user.');
  }
});


// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.render('login', { error: 'Invalid credentials. Please try again.' });
      }

      bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) {
          return res.render('login', { error: 'Invalid credentials. Please try again.' });
        }

        // Generate a JWT token with the user ID and role as the payload
        const token = jwt.sign({ userId: user._id, role: user.role }, secretKey, { expiresIn: '1h' }); // Token expires in 1 hour

        res.cookie('token', token);
        res.redirect('/home');
      });
    })
    .catch((err) => {
      console.error('Error finding user:', err);
      res.render('login', { error: 'An error occurred. Please try again later.' });
    });
});

// Protected dashboard route
app.get('/home', authenticateToken, (req, res) => {
  res.render('home', { user: req.user });
});

// Middleware to authenticate the JWT token
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/');
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.redirect('/');
    }

    // Set the authenticated user object in the request for access in the protected route
    User.findById(decoded.userId)
      .then((user) => {
        if (!user) {
          return res.redirect('/');
        }

        req.user = user;
        next();
      })
      .catch((err) => {
        console.error('Error finding user:', err);
        res.redirect('/');
      });
  });
}

// Add User route (form)
app.get('/users/add', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to add users.');
  }

  res.render('addUser');
});

// Create User route
app.post('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to add users.');
  }

  try {
    const { name, username, role } = req.body;
    const defaultPassword = username; // Set default password same as username

    // Check if the username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.render('addUser', { error: 'Username is already taken. Please choose another username.' });
    }

    // Hash the default password
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    // Create a new user in the database with default password
    const newUser = new User({
      name,
      username,
      password: hashedPassword,
      role,
    });

    await newUser.save();
    res.redirect('/users');
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).send('An error occurred while creating the user.');
  }
});


app.get('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to view this page.');
  }

  try {
    const page = parseInt(req.query.page) || 1; // Get the current page from query parameters
    const pageSize = 5; // Number of users per page

    // Count total number of users in the database
    const totalUsers = await User.countDocuments();

    // Calculate total number of pages based on the total users and pageSize
    const totalPages = Math.ceil(totalUsers / pageSize);

    // Calculate the number of users to skip to get the current page
    const skipUsers = (page - 1) * pageSize;

    // Fetch users for the current page from the database with required fields
    const users = await User.find({}, 'id name username role createdAt')
      .skip(skipUsers)
      .limit(pageSize)
      .sort({ createdAt: 'desc' }); // Sort by createdAt in descending order

    res.render('users', { users, user: req.user, page, totalPages });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('An error occurred while fetching users.');
  }
});


// Delete User route
app.post('/users/:id/delete', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to delete users.');
  }

  try {
    const userId = req.params.id;
    // Find the user by ID and delete from the database
    await User.findByIdAndDelete(userId);
    res.redirect('/users');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send('An error occurred while deleting the user.');
  }
});

// Edit User route (form)
app.get('/users/:id/edit', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to edit users.');
  }

  try {
    const userId = req.params.id;
    // Find the user by ID in the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found.');
    }

    res.render('edit', { user });
  } catch (err) {
    console.error('Error editing user:', err);
    res.status(500).send('An error occurred while editing the user.');
  }
});

// Update User route
app.post('/users/:id/update', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access denied. You do not have permission to update users.');
  }

  try {
    const userId = req.params.id;
    const { name, username, role } = req.body;

    // Find the user by ID and update the details in the database
    await User.findByIdAndUpdate(userId, { name, username, role });
    res.redirect('/users');
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).send('An error occurred while updating the user.');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  res.clearCookie('accessToken'); // Clear the access token cookie
  res.redirect('/login'); // Redirect to the login page after logout
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
