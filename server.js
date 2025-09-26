require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');      // for password hashing
const jwt = require('jsonwebtoken');   // for authentication
const { MongoClient, ObjectId } = require('mongodb');
const app = express();
app.use(cors());
app.use(express.json());
const useDb = process.env.USE_DB === 'true';
let storage; // array for in-memory users
let db, usersCollection;
// Initialize storage based on mode
if (useDb) {
    const uri = process.env.MONGO_URI;
    const client = new MongoClient(uri);
client.connect().then(() => {
db = client.db('loginAuthDB');
usersCollection = db.collection('users');
console.log('Connected to MongoDB');
    }).catch(err =>console.error(err));
} else {
    storage = []; // in-memory user storage
}
// Helper: generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });
};
// Routes for AngularJS frontend
// Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    if (useDb) {
        const existing = await usersCollection.findOne({ email });
        if (existing) return res.status(400).json({ message: 'User already exists' });
        const result = await usersCollection.insertOne({ username, email, password: hashedPassword });
        return res.json({ message: 'User registered', id: result.insertedId });
    } else {
        if (storage.find(u =>u.email === email)) return res.status(400).json({ message: 'User already exists' });
        const id = storage.length + 1;
storage.push({ id, username, email, password: hashedPassword });
        return res.json({ message: 'User registered', id });
    }
});
// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    let user;
    if (useDb) {
        user = await usersCollection.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    } else {
        user = storage.find(u =>u.email === email);
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials' });
    const token = generateToken(user._id || user.id);
res.json({ message: 'Login successful', token });
});
// Profile Edit
app.put('/api/profile/:id', async (req, res) => {
    const { username, email } = req.body;
    const userId = req.params.id;
    if (useDb) {
        await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { username, email } });
        return res.json({ message: 'Profile updated' });
    } else {
        const user = storage.find(u => u.id == userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
user.username = username;
user.email = email;
        return res.json({ message: 'Profile updated' });
    }
});
// Delete Account
app.delete('/api/delete/:id', async (req, res) => {
    const userId = req.params.id;
    if (useDb) {
        await usersCollection.deleteOne({ _id: new ObjectId(userId) });
        return res.json({ message: 'User deleted' });
    } else {
        storage = storage.filter(u => u.id != userId);
        return res.json({ message: 'User deleted' });
    }
});
// Start server
app.listen(3000, () =>console.log('Server running on port 3000'));
