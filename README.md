# AdvanceEdu Solutions API

Production-ready REST API for e-commerce/subscription system with Stripe integration.

## Tech Stack
- **Runtime**: Bun / Node.js
- **Framework**: Express.js
- **Database**: PostgreSQL (Prisma ORM)
- **Payment**: Stripe (test mode)
- **Deployment**: Vercel Serverless

## Getting Started

### Prerequisites
- Node.js >= 20 or Bun
- PostgreSQL database
- Stripe account (test mode)

### Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   # or
   bun install
   ```
3. Set up environment variables:
   Copy `.env.example` to `.env` and fill in the values.

### Database Setup
```bash
npx prisma migrate dev
```

### Running Locally
```bash
npm run dev
# or
bun run dev
```

## API Documentation

### Base URL
- Local: `http://localhost:3000/api`
- Production: `https://your-deployment-url.vercel.app/api`

### Endpoints

#### Health Check
- `GET /api/health` - API health status

#### Auth
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get JWT token

#### Users (Protected)
- `GET /api/users/me` - Get current user profile

#### Products
- `GET /api/products` - List all products
- `GET /api/products/:id` - Get product by ID
- `POST /api/products` - Create a product (requires auth)

#### Orders (Protected)
- `POST /api/orders` - Create an order and get Stripe Checkout URL

### Webhooks
- `POST /api/webhooks/stripe` - Stripe webhook endpoint
  - Handles `checkout.session.completed` → Order PAID
  - Handles `checkout.session.expired` → Order CANCELLED

## Postman Collection

A complete Postman collection is available in `postman/collection.json`. Import it to test all API endpoints with sample data.

### Setup
1. Import `postman/collection.json` into Postman
2. Set environment variables in Postman:
   - `baseUrl`: `http://localhost:3000`
   - `token`: (automatically set after login)

## Deployment

### Vercel
1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` to deploy.
3. Set environment variables in Vercel Dashboard:
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `STRIPE_SECRET_KEY`
   - `STRIPE_WEBHOOK_SECRET`
   - `API_BASE_URL`

## Testing

Run tests:
```bash
npm run test
```

Run with coverage:
```bash
npm run test:coverage
```
