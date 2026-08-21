require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();

// Connect to MongoDB Atlas (using options optimized for serverless environments)
if (process.env.MONGODB_URI) {
    mongoose.connect(process.env.MONGODB_URI)
        .then(() => console.log("Connected to MongoDB securely!"))
        .catch(err => console.error("Database connection error:", err));
} else {
    console.warn("WARNING: MONGODB_URI environment variable is missing.");
}

// User Schema & Model
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Express Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_dont_use_in_prod',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/test_fallback',
        ttl: 24 * 60 * 60 // 1 day session caching
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: true, // Vercel provides automatic HTTPS globally
        sameSite: 'lax'
    }
}));

// Setup view configurations relative to project root directory
app.set('views', path.join(__dirname, '../views'));
app.set('view engine', 'ejs');

// Serve static elements out of public asset folder
app.use(express.static(path.join(__dirname, '../public')));

// Mock Clothing Catalog Database
const clothes = [
    { id: 1, name: "Classic Denim Jacket", price: 2499, img: "https://unsplash.com" },
    { id: 2, name: "Minimalist White Tee", price: 799, img: "https://unsplash.com" },
    { id: 3, name: "Vintage Cargo Pants", price: 1899, img: "https://unsplash.com" },
    { id: 4, name: "Urban Knit Sweater", price: 3299, img: "https://unsplash.com" }
];

// ---- MAIN AND PRODUCT ROUTES (Session Protected) ----

app.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('index', { products: clothes });
});

app.get('/product/:id', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    const product = clothes.find(p => p.id === parseInt(req.params.id));
    if (!product) return res.status(404).send('Product not found');
    res.render('product', { product });
});

// ---- AUTHENTICATION VIEW AND LOGIC ROUTES ----

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.render('login', { error: null });
});

app.get('/signup', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.render('signup', { error: 'Email account already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email: email.toLowerCase(), password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        res.render('signup', { error: 'Error creating account. Try again.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.render('login', { error: 'Invalid email username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            req.session.userId = user._id;
            res.redirect('/');
        } else {
            res.render('login', { error: 'Invalid email username or password' });
        }
    } catch (err) {
        res.render('login', { error: 'System processing login error.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Export server application for serverless computing execution on Vercel
module.exports = app;
