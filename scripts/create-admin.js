require('dotenv').config();

const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

async function main() {
	const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
	const password = process.env.ADMIN_PASSWORD;
	const name = process.env.ADMIN_NAME?.trim() || 'Store administrator';

	if (!process.env.MONGODB_URI) {
		throw new Error('MONGODB_URI is required');
	}
	if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		throw new Error('Set ADMIN_EMAIL to a valid email address');
	}
	if (!password || password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
		throw new Error('ADMIN_PASSWORD must be at least 12 characters and no more than 72 bytes');
	}

	const client = new MongoClient(process.env.MONGODB_URI);
	try {
		await client.connect();
		const users = client.db('ecommerce').collection('users');
		await users.createIndex({ email: 1 }, { unique: true });
		const passwordHash = await bcrypt.hash(password, 12);
		await users.updateOne(
			{ email },
			{
				$set: { name, passwordHash, role: 'admin' },
				$setOnInsert: { email, createdAt: new Date() },
			},
			{ upsert: true },
		);
		console.log(`Administrator account created or updated for ${email}.`);
	} finally {
		await client.close();
	}
}

main().catch((error) => {
	console.error('Failed to create administrator:', error.message);
	process.exit(1);
});
