# Field & Form

## Run locally

1. Copy `.env.example` to `.env`.
2. Set `MONGODB_URI` to your MongoDB Atlas connection string.
3. Generate a session secret and set `SESSION_SECRET` in `.env`:

   ```powershell
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. Install dependencies and start the app:

   ```powershell
   npm install
   npm start
   ```

   Open `http://localhost:3000`.

## Run with Docker Compose

Set `MONGODB_URI` and `SESSION_SECRET` in `.env`, then run:

```powershell
docker compose up --build
```

Open `http://localhost`.

## Create the first administrator

Public signups create customer accounts only. Create or promote an administrator explicitly from PowerShell:

```powershell
$env:ADMIN_EMAIL = "admin@example.com"
$env:ADMIN_PASSWORD = "use-a-unique-password-of-at-least-12-characters"
npm run create-admin
Remove-Item Env:ADMIN_EMAIL
Remove-Item Env:ADMIN_PASSWORD
```

For Docker Compose, build the image and run the one-off setup command:

```powershell
docker compose build app
docker compose run --rm -e ADMIN_EMAIL=admin@example.com -e ADMIN_PASSWORD="use-a-unique-password-of-at-least-12-characters" app npm run create-admin
```

Sign in at `/login` with that account, then use `/admin` to add products. The administrator setup command creates or promotes the supplied email to admin and sets its password.

## Accounts and products

- `/signup` creates a customer account. Passwords are stored as bcrypt hashes in the MongoDB `ecommerce.users` collection.
- `/login` starts a MongoDB-backed session. Session records are stored in the `ecommerce.sessions` collection.
- `/admin` is restricted to administrator accounts. Product creation is also protected at `POST /api/products`.
- Products are stored in `ecommerce.products`; the public storefront and `GET /api/products` read from that collection.
- Keep `.env` private. Use a distinct random `SESSION_SECRET` for each deployment.
