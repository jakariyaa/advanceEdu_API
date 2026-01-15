# AdvanceEdu E-commerce API

[![Node.js](https://img.shields.io/badge/Node.js-≥20-339933?logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Express](https://img.shields.io/badge/Express-5.x-000000?logo=express)](https://expressjs.com/)
[![Prisma](https://img.shields.io/badge/Prisma-7.x-2D3748?logo=prisma)](https://www.prisma.io/)
[![Stripe](https://img.shields.io/badge/Stripe-Integrated-635BFF?logo=stripe)](https://stripe.com/)

Production-ready REST API for e-commerce platform with secure authentication, role-based access control, and Stripe payment integration.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Environment Variables](#-environment-variables)
- [API Endpoints](#-api-endpoints)
- [Payment Flow](#-payment-flow)
- [Testing](#-testing)
- [Deployment](#-deployment)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Access + refresh token rotation with HttpOnly cookies |
| **Security** | CSRF protection (production only), rate limiting, Helmet headers |
| **Role-Based Access** | USER and ADMIN roles with middleware enforcement |
| **Stripe Payments** | Checkout sessions with webhook handling |
| **Input Validation** | Zod schemas for all endpoints |
| **OpenAPI Docs** | Auto-generated from Zod schemas |


---

## 🛠 Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js ≥20 / Bun |
| Framework | Express.js 5.x |
| Language | TypeScript (strict mode) |
| Database | PostgreSQL + Prisma ORM |
| Payments | Stripe API |
| Validation | Zod |
| Testing | Vitest + Supertest |
| Deployment | Vercel Serverless |

---

## 🚀 Quick Start

### Prerequisites

- Node.js ≥20 (or Bun)
- PostgreSQL database
- Stripe account ([test mode](https://dashboard.stripe.com/test/apikeys))

### 1. Clone & Install

```bash
git clone <repository-url>
cd <repository-name>
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/advanceedu

# JWT (min 32 characters each)
JWT_ACCESS_SECRET=your-super-secret-access-key-min-32-chars
JWT_REFRESH_SECRET=your-super-secret-refresh-key-min-32-chars
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Stripe (from https://dashboard.stripe.com/test/apikeys)
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# API
API_BASE_URL=http://localhost:3000
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:4000
```

### 3. Setup Database

```bash
# Generate Prisma client
npm run db:generate

# Run migrations
npm run db:migrate
```

### 4. Start Development Server

```bash
npm run dev
```

Server runs at `http://localhost:3000`

---

## 🔐 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `JWT_ACCESS_SECRET` | ✅ | Access token signing key (≥32 chars) |
| `JWT_REFRESH_SECRET` | ✅ | Refresh token signing key (≥32 chars) |
| `STRIPE_SECRET_KEY` | ✅ | Stripe secret key (starts with `sk_`) |
| `STRIPE_WEBHOOK_SECRET` | ✅ | Stripe webhook secret (starts with `whsec_`) |
| `API_BASE_URL` | ✅ | Base URL for payment callbacks |
| `PORT` | ❌ | Server port (default: 3000) |
| `NODE_ENV` | ❌ | Environment (development/production/test) |
| `FRONTEND_URL` | ❌ | Frontend URL for CORS (default: http://localhost:4000) |

---

## 📡 API Endpoints

### Base URL
- **Local**: `http://localhost:3000/api`
- **Production**: `https://your-app.vercel.app/api`

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/auth/register` | Create new account | ❌ |
| POST | `/auth/login` | Login, returns access token | ❌ |
| POST | `/auth/refresh` | Refresh access token | Cookie |
| POST | `/auth/logout` | Logout current session | ❌ |
| POST | `/auth/logout-all` | Logout all sessions | ✅ |

### Users

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/users/me` | Get current user profile | ✅ |

### Products

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/products` | List all products (paginated) | ❌ |
| GET | `/products/:id` | Get product by ID | ❌ |
| POST | `/products` | Create product | ✅ |
| PATCH | `/products/:id` | Update own product | ✅ |
| DELETE | `/products/:id` | Delete product | 🔒 Admin |

### Orders

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/orders` | Create order + Stripe Checkout URL | ✅ |

### Payments

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/payment/success` | Payment success callback | ❌ |
| GET | `/payment/cancel` | Payment cancel callback | ❌ |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/webhooks/stripe` | Stripe payment events |

---

## 💳 Payment Flow

The API uses **Stripe Checkout** for secure payment processing.

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant API
    participant Stripe
    participant Database

    Client->>API: POST /api/orders (items array)
    API->>Database: Create order (PENDING)
    API->>Stripe: Create Checkout Session
    Stripe-->>API: Return session URL
    API-->>Client: { url, sessionId, order }
    
    Client->>Stripe: Redirect to Checkout
    Note over Stripe: User completes payment
    
    Stripe->>API: POST /api/webhooks/stripe
    Note right of Stripe: checkout.session.completed
    API->>API: Verify webhook signature
    API->>Database: Update order → PAID
    API-->>Stripe: 200 OK
    
    Stripe->>Client: Redirect to success_url
```

### Step-by-Step Process

1. **Create Order** - Client sends `POST /api/orders` with product items
2. **Order Created** - API saves order in database with `PENDING` status
3. **Checkout Session** - API creates Stripe Checkout Session with order metadata
4. **Return URL** - API returns Stripe-hosted checkout URL to client
5. **Redirect** - Client redirects user to Stripe Checkout page
6. **Payment** - User completes payment on Stripe's secure page
7. **Webhook** - Stripe sends `checkout.session.completed` event to `/api/webhooks/stripe`
8. **Verification** - API verifies Stripe signature to prevent fraud
9. **Order Update** - API updates order status to `PAID` in database
10. **Success** - User is redirected back to your success page

### Webhook Events Handled

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Order status → **PAID** |
| `checkout.session.expired` | Order status → **CANCELLED** |

### Local Webhook Testing

Use [Stripe CLI](https://stripe.com/docs/stripe-cli) to forward webhooks:

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Login to Stripe
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:3000/api/webhooks/stripe

# Copy the webhook signing secret (whsec_xxx) to your .env
```

---

## 🧪 Testing

```bash
# Run all tests
npm run test

# Run with watch mode
npm run test:watch

# Run with coverage report
npm run test:coverage

# Lint code
npm run lint

# Type check
npm run typecheck
```

### Test Coverage Thresholds

| Metric | Threshold |
|--------|-----------|
| Lines | 80% |
| Functions | 80% |
| Branches | 70% |
| Statements | 80% |

---

## 🚢 Deployment

### Vercel (Recommended)

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Deploy**
   ```bash
   vercel
   ```

3. **Set Environment Variables** in [Vercel Dashboard](https://vercel.com/dashboard):
   - `DATABASE_URL` - Production PostgreSQL URL
   - `JWT_ACCESS_SECRET` - Strong random string (32+ chars)
   - `JWT_REFRESH_SECRET` - Strong random string (32+ chars)
   - `STRIPE_SECRET_KEY` - Live/test Stripe key
   - `STRIPE_WEBHOOK_SECRET` - From Stripe webhook settings
   - `API_BASE_URL` - Your deployed URL
   - `NODE_ENV` - `production`

4. **Configure Stripe Webhook**
   - Go to [Stripe Webhooks](https://dashboard.stripe.com/webhooks)
   - Add endpoint: `https://your-app.vercel.app/api/webhooks/stripe`
   - Select events: `checkout.session.completed`, `checkout.session.expired`
   - Copy webhook secret to Vercel env vars

---

## 📁 Project Structure

```
src/
├── app.ts                 # Express app configuration
├── server.ts              # Server bootstrap
├── config/                # Security & CORS config
├── common/
│   ├── interfaces/        # TypeScript interfaces
│   ├── lib/               # Core utilities (env, logger, prisma, tokens)
│   ├── middleware/        # Auth, CSRF, rate-limit, validation
│   ├── providers/         # Payment provider abstraction
│   └── repositories/      # Base repository pattern
├── modules/
│   ├── auth/              # Authentication (login, register, tokens)
│   ├── users/             # User profile
│   ├── products/          # Product CRUD
│   ├── orders/            # Order creation + Stripe checkout
│   └── webhooks/          # Stripe webhook handling
└── docs/                  # OpenAPI spec generation
```

---

## 📚 Additional Resources

- **Postman Collection**: `postman/collection.json`
- **OpenAPI Spec**: `openapi.json`
- **Environment Template**: `.env.example`

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.


## Architecture

(Diagram placeholder)

