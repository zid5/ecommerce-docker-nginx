require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { MongoStore } = require('connect-mongo');
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const session = require('express-session');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;
const sessionName = 'ecommerce.sid';
let productsCollection;
let usersCollection;

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

let sessionMiddleware;
app.use((req, res, next) => {
	if (!sessionMiddleware) {
		return next(new Error('Session store is unavailable'));
	}
	return sessionMiddleware(req, res, next);
});

function publicUser(user) {
	return { name: user.name, email: user.email, role: user.role };
}

function csrfProtection(req, res, next) {
	const submittedToken = req.get('x-csrf-token') || req.body?.csrfToken;
	const sessionToken = req.session.csrfToken;
	const submittedBytes = typeof submittedToken === 'string' ? Buffer.from(submittedToken) : null;
	const sessionBytes = typeof sessionToken === 'string' ? Buffer.from(sessionToken) : null;
	if (
		!submittedBytes
		|| !sessionBytes
		|| submittedBytes.length !== sessionBytes.length
		|| !crypto.timingSafeEqual(submittedBytes, sessionBytes)
	) {
		return res.status(403).json({ error: 'Your session expired. Refresh the page and try again.' });
	}

	return next();
}

function requireAdmin(req, res, next) {
	if (!req.session.user) {
		if (req.path.startsWith('/api/')) {
			return res.status(401).json({ error: 'Please sign in to continue' });
		}
		return res.redirect('/login');
	}

	if (req.session.user.role !== 'admin') {
		if (req.path.startsWith('/api/')) {
			return res.status(403).json({ error: 'Administrator access is required' });
		}
		return res.status(403).render('forbidden', { currentUser: req.session.user });
	}

	return next();
}

function regenerateSession(req) {
	return new Promise((resolve, reject) => {
		req.session.regenerate((error) => {
			if (error) {
				reject(error);
				return;
			}
			resolve();
		});
	});
}

const authRateLimit = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 10,
	standardHeaders: true,
	legacyHeaders: false,
	message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
});

app.use((req, res, next) => {
	if (!req.session) {
		return next();
	}

	if (req.method === 'GET' && !req.path.startsWith('/api/') && !req.session.csrfToken) {
		req.session.csrfToken = crypto.randomBytes(32).toString('hex');
	}
	res.locals.csrfToken = req.session.csrfToken;
	res.locals.currentUser = req.session.user || null;
	return next();
});

app.get('/', async (req, res) => {
	const products = await productsCollection.find().sort({ _id: -1 }).toArray();
	res.render('index', {
		products: products.map(({ _id, ...product }) => ({
			...product,
			id: _id.toString(),
		})),
	});
});

app.get('/login', (req, res) => {
	if (req.session.user) {
		return res.redirect(req.session.user.role === 'admin' ? '/admin' : '/');
	}
	return res.render('auth', { mode: 'login' });
});

app.get('/signup', (req, res) => {
	if (req.session.user) {
		return res.redirect(req.session.user.role === 'admin' ? '/admin' : '/');
	}
	return res.render('auth', { mode: 'signup' });
});

app.get('/admin', requireAdmin, async (req, res) => {
	const products = await productsCollection.find().sort({ _id: -1 }).toArray();
	res.render('admin', {
		products: products.map(({ _id, ...product }) => ({
			...product,
			id: _id.toString(),
		})),
	});
});

app.get('/api/health', (req, res) => {
	res.json({ status: 'ok' });
});

app.get('/api/auth/me', (req, res) => {
	res.json({ user: req.session.user ? publicUser(req.session.user) : null });
});

app.post('/api/auth/signup', authRateLimit, csrfProtection, async (req, res) => {
	const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
	const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
	const password = typeof req.body.password === 'string' ? req.body.password : '';

	if (!name || name.length > 80) {
		return res.status(400).json({ error: 'Enter a name between 1 and 80 characters.' });
	}
	if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		return res.status(400).json({ error: 'Enter a valid email address.' });
	}
	if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
		return res.status(400).json({ error: 'Password must be at least 12 characters and no more than 72 bytes.' });
	}

	const passwordHash = await bcrypt.hash(password, 12);
	let result;
	try {
		result = await usersCollection.insertOne({
			name,
			email,
			passwordHash,
			role: 'customer',
			createdAt: new Date(),
		});
	} catch (error) {
		if (error.code === 11000) {
			return res.status(409).json({ error: 'An account with this email already exists.' });
		}
		throw error;
	}

	await regenerateSession(req);
	req.session.user = { id: result.insertedId.toString(), name, email, role: 'customer' };
	req.session.csrfToken = crypto.randomBytes(32).toString('hex');
	return res.status(201).json({ user: publicUser(req.session.user), redirect: '/' });
});

app.post('/api/auth/login', authRateLimit, csrfProtection, async (req, res) => {
	const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
	const password = typeof req.body.password === 'string' ? req.body.password : '';
	const user = email.length <= 254 && Buffer.byteLength(password, 'utf8') <= 72
		? await usersCollection.findOne({ email })
		: null;

	if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
		return res.status(401).json({ error: 'Email or password is incorrect.' });
	}

	await regenerateSession(req);
	req.session.user = {
		id: user._id.toString(),
		name: user.name,
		email: user.email,
		role: user.role,
	};
	req.session.csrfToken = crypto.randomBytes(32).toString('hex');
	return res.json({
		user: publicUser(req.session.user),
		redirect: user.role === 'admin' ? '/admin' : '/',
	});
});

app.post('/api/auth/logout', csrfProtection, (req, res, next) => {
	req.session.destroy((error) => {
		if (error) {
			return next(error);
		}
		res.clearCookie(sessionName, {
			httpOnly: true,
			sameSite: 'lax',
			secure: req.secure,
			path: '/',
		});
		return res.json({ success: true });
	});
});

app.get('/api/products', async (req, res) => {
	const products = await productsCollection.find().sort({ _id: -1 }).toArray();
	res.json(products.map(({ _id, ...product }) => ({
		...product,
		id: _id.toString(),
	})));
});

app.post('/api/products', requireAdmin, csrfProtection, async (req, res) => {
	const body = req.body;
	if (!body || typeof body !== 'object' || Array.isArray(body)) {
		return res.status(400).json({ error: 'A product object is required.' });
	}

	const name = typeof body.name === 'string' ? body.name.trim() : '';
	const price = typeof body.price === 'number'
		? body.price
		: typeof body.price === 'string' && body.price.trim()
			? Number(body.price)
			: Number.NaN;
	if (!name || name.length > 120) {
		return res.status(400).json({ error: 'Product name is required and must be 120 characters or fewer.' });
	}
	if (!Number.isFinite(price) || price < 0) {
		return res.status(400).json({ error: 'Enter a valid product price.' });
	}

	const category = typeof body.category === 'string' ? body.category.trim() : '';
	const description = typeof body.description === 'string' ? body.description.trim() : '';
	const imageUrl = typeof body.imageUrl === 'string' ? body.imageUrl.trim() : '';
	if (category.length > 60 || description.length > 500) {
		return res.status(400).json({ error: 'Category or description is too long.' });
	}
	if (imageUrl) {
		let parsedImageUrl;
		try {
			parsedImageUrl = new URL(imageUrl);
		} catch {
			return res.status(400).json({ error: 'Enter a valid image URL.' });
		}
		if (!['http:', 'https:'].includes(parsedImageUrl.protocol)) {
			return res.status(400).json({ error: 'Image URL must use HTTP or HTTPS.' });
		}
	}

	const productData = { name, price, category, description, imageUrl };
	const result = await productsCollection.insertOne(productData);
	return res.status(201).json({ ...productData, id: result.insertedId.toString() });
});

app.use((error, req, res, next) => {
	console.error('Request failed:', error);
	if (res.headersSent) {
		return next(error);
	}

	const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500
		? error.status
		: 500;
	const message = status === 413 ? 'Request body is too large.' : 'The request could not be completed.';
	if (req.path.startsWith('/api/')) {
		return res.status(status).json({ error: message });
	}

	return res.status(status).send(message);
});

async function start() {
	if (!process.env.MONGODB_URI) {
		throw new Error('MONGODB_URI is required');
	}
	if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
		throw new Error('SESSION_SECRET must be set to a random value of at least 32 characters');
	}

	const client = new MongoClient(process.env.MONGODB_URI);
	await client.connect();
	const db = client.db('ecommerce');
	await db.command({ ping: 1 });
	productsCollection = db.collection('products');
	usersCollection = db.collection('users');
	await usersCollection.createIndex({ email: 1 }, { unique: true });

	sessionMiddleware = session({
		name: sessionName,
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: false,
		store: MongoStore.create({
			client,
			dbName: 'ecommerce',
			collectionName: 'sessions',
			ttl: 60 * 60 * 24 * 7,
		}),
		cookie: {
			httpOnly: true,
			sameSite: 'lax',
			secure: 'auto',
			maxAge: 1000 * 60 * 60 * 24 * 7,
		},
	});

	app.listen(port, '0.0.0.0', () => {
		console.log(`Server listening on port ${port}`);
	});
}

start().catch((error) => {
	console.error('Failed to start server:', error.message);
	process.exit(1);
});
