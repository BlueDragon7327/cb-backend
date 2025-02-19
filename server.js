// server.js
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB Connection Error:', err));

// User Schema & Model
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Message Schema & Model (for storing DMs)
const MessageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model('Message', MessageSchema);

// Register Route
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint to fetch conversation history between two users
// GET /api/messages?user1=Alice&user2=Bob
app.get('/api/messages', async (req, res) => {
  const { user1, user2 } = req.query;
  try {
    const messages = await Message.find({
      $or: [
        { sender: user1, recipient: user2 },
        { sender: user2, recipient: user1 }
      ]
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint to fetch active DM conversation partners for a user
// GET /api/dmList?user=Alice
app.get('/api/dmList', async (req, res) => {
  const { user } = req.query;
  try {
    const messages = await Message.find({
      $or: [
        { sender: user },
        { recipient: user }
      ]
    });
    const dmSet = new Set();
    messages.forEach(msg => {
      if (msg.sender !== user) dmSet.add(msg.sender);
      if (msg.recipient !== user) dmSet.add(msg.recipient);
    });
    res.json(Array.from(dmSet));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// WebSocket DM Logic
const users = {}; // Maps username -> socket.id

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('registerUser', (username) => {
    users[username] = socket.id;
    console.log(`User registered: ${username} with socket ${socket.id}`);
  });

  // When a DM is sent, store it and send it to the recipient
  socket.on('sendMessage', async (data) => {
    const { sender, recipient, message } = data;
    try {
      const newMessage = new Message({ sender, recipient, message });
      await newMessage.save();
    } catch (error) {
      console.error('Error saving message:', error);
    }
    const targetSocketId = users[recipient];
    if (targetSocketId) {
      io.to(targetSocketId).emit('receiveMessage', data);
    }
    // Echo back to sender
    socket.emit('receiveMessage', data);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    for (const username in users) {
      if (users[username] === socket.id) {
        delete users[username];
        break;
      }
    }
  });
});

server.listen(3003, () => console.log('Server running on port 3003'));
