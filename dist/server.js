var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/app.ts
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { pinoHttp } from "pino-http";

// src/common/lib/logger.ts
import pino from "pino";
var isDev = process.env["NODE_ENV"] !== "production";
var devOptions = {
  level: process.env["LOG_LEVEL"] || "info",
  transport: {
    target: "pino-pretty",
    options: {
      colorize: true,
      ignore: "pid,hostname",
      translateTime: "SYS:standard",
      sync: true
    }
  }
};
var prodOptions = {
  level: process.env["LOG_LEVEL"] || "info"
};
var logger = pino(isDev ? devOptions : prodOptions);

// src/common/middleware/error-handler.ts
import { ZodError } from "zod";

// src/generated/prisma/client.ts
import * as path from "path";
import { fileURLToPath } from "url";

// src/generated/prisma/internal/class.ts
import * as runtime from "@prisma/client/runtime/client";
var config = {
  "previewFeatures": [],
  "clientVersion": "7.2.0",
  "engineVersion": "0c8ef2ce45c83248ab3df073180d5eda9e8be7a3",
  "activeProvider": "postgresql",
  "inlineSchema": 'datasource db {\n  provider = "postgresql"\n}\n\ngenerator client {\n  provider = "prisma-client"\n  output   = "../src/generated/prisma"\n}\n\nenum Role {\n  USER\n  ADMIN\n}\n\nmodel User {\n  id            Int            @id @default(autoincrement())\n  email         String         @unique\n  password      String\n  name          String?\n  role          Role           @default(USER)\n  stripeId      String?        @unique @map("stripe_customer_id")\n  createdAt     DateTime       @default(now()) @map("created_at")\n  updatedAt     DateTime       @updatedAt @map("updated_at")\n  orders        Order[]\n  products      Product[]\n  refreshTokens RefreshToken[]\n\n  @@map("users")\n}\n\nmodel RefreshToken {\n  id        Int      @id @default(autoincrement())\n  token     String   @unique // Hashed token\n  userId    Int      @map("user_id")\n  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)\n  familyId  String   @map("family_id") // ID for the token family/chain\n  isUsed    Boolean  @default(false) @map("is_used") // Track if token has been rotated\n  expiresAt DateTime @map("expires_at")\n  createdAt DateTime @default(now()) @map("created_at")\n\n  @@index([userId])\n  @@index([familyId])\n  @@index([expiresAt])\n  @@map("refresh_tokens")\n}\n\nmodel Product {\n  id          Int         @id @default(autoincrement())\n  name        String\n  description String?\n  price       Int // in cents\n  currency    String      @default("usd")\n  stripeId    String?     @unique @map("stripe_price_id")\n  isActive    Boolean     @default(true) @map("is_active")\n  createdAt   DateTime    @default(now()) @map("created_at")\n  updatedAt   DateTime    @updatedAt @map("updated_at")\n  userId      Int         @default(1) @map("user_id") // Temporary default for migration\n  user        User        @relation(fields: [userId], references: [id])\n  orderItems  OrderItem[]\n\n  @@map("products")\n}\n\nmodel Order {\n  id              Int         @id @default(autoincrement())\n  userId          Int         @map("user_id")\n  user            User        @relation(fields: [userId], references: [id])\n  status          OrderStatus @default(PENDING)\n  totalAmount     Int         @map("total_amount") // in cents\n  currency        String      @default("usd")\n  stripeSessionId String?     @unique @map("stripe_session_id")\n  stripePaymentId String?     @map("stripe_payment_intent_id")\n  createdAt       DateTime    @default(now()) @map("created_at")\n  updatedAt       DateTime    @updatedAt @map("updated_at")\n  items           OrderItem[]\n\n  @@map("orders")\n}\n\nmodel OrderItem {\n  id        Int     @id @default(autoincrement())\n  orderId   Int     @map("order_id")\n  order     Order   @relation(fields: [orderId], references: [id])\n  productId Int     @map("product_id")\n  product   Product @relation(fields: [productId], references: [id])\n  quantity  Int\n  price     Int // price at time of order, in cents\n\n  @@map("order_items")\n}\n\nenum OrderStatus {\n  PENDING\n  PAID\n  FAILED\n  CANCELLED\n  REFUNDED\n}\n',
  "runtimeDataModel": {
    "models": {},
    "enums": {},
    "types": {}
  }
};
config.runtimeDataModel = JSON.parse('{"models":{"User":{"fields":[{"name":"id","kind":"scalar","type":"Int"},{"name":"email","kind":"scalar","type":"String"},{"name":"password","kind":"scalar","type":"String"},{"name":"name","kind":"scalar","type":"String"},{"name":"role","kind":"enum","type":"Role"},{"name":"stripeId","kind":"scalar","type":"String","dbName":"stripe_customer_id"},{"name":"createdAt","kind":"scalar","type":"DateTime","dbName":"created_at"},{"name":"updatedAt","kind":"scalar","type":"DateTime","dbName":"updated_at"},{"name":"orders","kind":"object","type":"Order","relationName":"OrderToUser"},{"name":"products","kind":"object","type":"Product","relationName":"ProductToUser"},{"name":"refreshTokens","kind":"object","type":"RefreshToken","relationName":"RefreshTokenToUser"}],"dbName":"users"},"RefreshToken":{"fields":[{"name":"id","kind":"scalar","type":"Int"},{"name":"token","kind":"scalar","type":"String"},{"name":"userId","kind":"scalar","type":"Int","dbName":"user_id"},{"name":"user","kind":"object","type":"User","relationName":"RefreshTokenToUser"},{"name":"familyId","kind":"scalar","type":"String","dbName":"family_id"},{"name":"isUsed","kind":"scalar","type":"Boolean","dbName":"is_used"},{"name":"expiresAt","kind":"scalar","type":"DateTime","dbName":"expires_at"},{"name":"createdAt","kind":"scalar","type":"DateTime","dbName":"created_at"}],"dbName":"refresh_tokens"},"Product":{"fields":[{"name":"id","kind":"scalar","type":"Int"},{"name":"name","kind":"scalar","type":"String"},{"name":"description","kind":"scalar","type":"String"},{"name":"price","kind":"scalar","type":"Int"},{"name":"currency","kind":"scalar","type":"String"},{"name":"stripeId","kind":"scalar","type":"String","dbName":"stripe_price_id"},{"name":"isActive","kind":"scalar","type":"Boolean","dbName":"is_active"},{"name":"createdAt","kind":"scalar","type":"DateTime","dbName":"created_at"},{"name":"updatedAt","kind":"scalar","type":"DateTime","dbName":"updated_at"},{"name":"userId","kind":"scalar","type":"Int","dbName":"user_id"},{"name":"user","kind":"object","type":"User","relationName":"ProductToUser"},{"name":"orderItems","kind":"object","type":"OrderItem","relationName":"OrderItemToProduct"}],"dbName":"products"},"Order":{"fields":[{"name":"id","kind":"scalar","type":"Int"},{"name":"userId","kind":"scalar","type":"Int","dbName":"user_id"},{"name":"user","kind":"object","type":"User","relationName":"OrderToUser"},{"name":"status","kind":"enum","type":"OrderStatus"},{"name":"totalAmount","kind":"scalar","type":"Int","dbName":"total_amount"},{"name":"currency","kind":"scalar","type":"String"},{"name":"stripeSessionId","kind":"scalar","type":"String","dbName":"stripe_session_id"},{"name":"stripePaymentId","kind":"scalar","type":"String","dbName":"stripe_payment_intent_id"},{"name":"createdAt","kind":"scalar","type":"DateTime","dbName":"created_at"},{"name":"updatedAt","kind":"scalar","type":"DateTime","dbName":"updated_at"},{"name":"items","kind":"object","type":"OrderItem","relationName":"OrderToOrderItem"}],"dbName":"orders"},"OrderItem":{"fields":[{"name":"id","kind":"scalar","type":"Int"},{"name":"orderId","kind":"scalar","type":"Int","dbName":"order_id"},{"name":"order","kind":"object","type":"Order","relationName":"OrderToOrderItem"},{"name":"productId","kind":"scalar","type":"Int","dbName":"product_id"},{"name":"product","kind":"object","type":"Product","relationName":"OrderItemToProduct"},{"name":"quantity","kind":"scalar","type":"Int"},{"name":"price","kind":"scalar","type":"Int"}],"dbName":"order_items"}},"enums":{},"types":{}}');
async function decodeBase64AsWasm(wasmBase64) {
  const { Buffer: Buffer2 } = await import("buffer");
  const wasmArray = Buffer2.from(wasmBase64, "base64");
  return new WebAssembly.Module(wasmArray);
}
config.compilerWasm = {
  getRuntime: async () => await import("@prisma/client/runtime/query_compiler_bg.postgresql.mjs"),
  getQueryCompilerWasmModule: async () => {
    const { wasm } = await import("@prisma/client/runtime/query_compiler_bg.postgresql.wasm-base64.mjs");
    return await decodeBase64AsWasm(wasm);
  }
};
function getPrismaClientClass() {
  return runtime.getPrismaClient(config);
}

// src/generated/prisma/internal/prismaNamespace.ts
var prismaNamespace_exports = {};
__export(prismaNamespace_exports, {
  AnyNull: () => AnyNull2,
  DbNull: () => DbNull2,
  Decimal: () => Decimal2,
  JsonNull: () => JsonNull2,
  ModelName: () => ModelName,
  NullTypes: () => NullTypes2,
  NullsOrder: () => NullsOrder,
  OrderItemScalarFieldEnum: () => OrderItemScalarFieldEnum,
  OrderScalarFieldEnum: () => OrderScalarFieldEnum,
  PrismaClientInitializationError: () => PrismaClientInitializationError2,
  PrismaClientKnownRequestError: () => PrismaClientKnownRequestError2,
  PrismaClientRustPanicError: () => PrismaClientRustPanicError2,
  PrismaClientUnknownRequestError: () => PrismaClientUnknownRequestError2,
  PrismaClientValidationError: () => PrismaClientValidationError2,
  ProductScalarFieldEnum: () => ProductScalarFieldEnum,
  QueryMode: () => QueryMode,
  RefreshTokenScalarFieldEnum: () => RefreshTokenScalarFieldEnum,
  SortOrder: () => SortOrder,
  Sql: () => Sql2,
  TransactionIsolationLevel: () => TransactionIsolationLevel,
  UserScalarFieldEnum: () => UserScalarFieldEnum,
  defineExtension: () => defineExtension,
  empty: () => empty2,
  getExtensionContext: () => getExtensionContext,
  join: () => join2,
  prismaVersion: () => prismaVersion,
  raw: () => raw2,
  sql: () => sql
});
import * as runtime2 from "@prisma/client/runtime/client";
var PrismaClientKnownRequestError2 = runtime2.PrismaClientKnownRequestError;
var PrismaClientUnknownRequestError2 = runtime2.PrismaClientUnknownRequestError;
var PrismaClientRustPanicError2 = runtime2.PrismaClientRustPanicError;
var PrismaClientInitializationError2 = runtime2.PrismaClientInitializationError;
var PrismaClientValidationError2 = runtime2.PrismaClientValidationError;
var sql = runtime2.sqltag;
var empty2 = runtime2.empty;
var join2 = runtime2.join;
var raw2 = runtime2.raw;
var Sql2 = runtime2.Sql;
var Decimal2 = runtime2.Decimal;
var getExtensionContext = runtime2.Extensions.getExtensionContext;
var prismaVersion = {
  client: "7.2.0",
  engine: "0c8ef2ce45c83248ab3df073180d5eda9e8be7a3"
};
var NullTypes2 = {
  DbNull: runtime2.NullTypes.DbNull,
  JsonNull: runtime2.NullTypes.JsonNull,
  AnyNull: runtime2.NullTypes.AnyNull
};
var DbNull2 = runtime2.DbNull;
var JsonNull2 = runtime2.JsonNull;
var AnyNull2 = runtime2.AnyNull;
var ModelName = {
  User: "User",
  RefreshToken: "RefreshToken",
  Product: "Product",
  Order: "Order",
  OrderItem: "OrderItem"
};
var TransactionIsolationLevel = runtime2.makeStrictEnum({
  ReadUncommitted: "ReadUncommitted",
  ReadCommitted: "ReadCommitted",
  RepeatableRead: "RepeatableRead",
  Serializable: "Serializable"
});
var UserScalarFieldEnum = {
  id: "id",
  email: "email",
  password: "password",
  name: "name",
  role: "role",
  stripeId: "stripeId",
  createdAt: "createdAt",
  updatedAt: "updatedAt"
};
var RefreshTokenScalarFieldEnum = {
  id: "id",
  token: "token",
  userId: "userId",
  familyId: "familyId",
  isUsed: "isUsed",
  expiresAt: "expiresAt",
  createdAt: "createdAt"
};
var ProductScalarFieldEnum = {
  id: "id",
  name: "name",
  description: "description",
  price: "price",
  currency: "currency",
  stripeId: "stripeId",
  isActive: "isActive",
  createdAt: "createdAt",
  updatedAt: "updatedAt",
  userId: "userId"
};
var OrderScalarFieldEnum = {
  id: "id",
  userId: "userId",
  status: "status",
  totalAmount: "totalAmount",
  currency: "currency",
  stripeSessionId: "stripeSessionId",
  stripePaymentId: "stripePaymentId",
  createdAt: "createdAt",
  updatedAt: "updatedAt"
};
var OrderItemScalarFieldEnum = {
  id: "id",
  orderId: "orderId",
  productId: "productId",
  quantity: "quantity",
  price: "price"
};
var SortOrder = {
  asc: "asc",
  desc: "desc"
};
var QueryMode = {
  default: "default",
  insensitive: "insensitive"
};
var NullsOrder = {
  first: "first",
  last: "last"
};
var defineExtension = runtime2.Extensions.defineExtension;

// src/generated/prisma/enums.ts
var Role = {
  USER: "USER",
  ADMIN: "ADMIN"
};
var OrderStatus = {
  PENDING: "PENDING",
  PAID: "PAID",
  FAILED: "FAILED",
  CANCELLED: "CANCELLED",
  REFUNDED: "REFUNDED"
};

// src/generated/prisma/client.ts
globalThis["__dirname"] = path.dirname(fileURLToPath(import.meta.url));
var PrismaClient = getPrismaClientClass();

// src/common/middleware/error-handler.ts
var ApiError = class extends Error {
  statusCode;
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "ApiError";
    Error.captureStackTrace(this, this.constructor);
  }
};
var errorHandler = (err, req, res, _next) => {
  const sanitizeBody = (body) => {
    const sensitiveFields = [
      "password",
      "token",
      "secret",
      "key",
      "authorization",
      "apiKey",
      "api_key",
      "refreshToken",
      "accessToken",
      "creditCard",
      "ssn",
      "cvv"
    ];
    const sanitized = { ...body };
    for (const field of sensitiveFields) {
      if (field in sanitized) {
        sanitized[field] = "[REDACTED]";
      }
    }
    return sanitized;
  };
  const errorInfo = {
    name: err.name,
    message: err.message,
    stack: err.stack,
    req: {
      method: req.method,
      url: req.url,
      body: req.body ? sanitizeBody(req.body) : void 0
    }
  };
  logger.error(errorInfo, `[${err.name}] ${err.message}`);
  if (err instanceof ApiError) {
    const response2 = {
      status: err.statusCode >= 500 ? "error" : "fail",
      message: err.message
    };
    res.status(err.statusCode).json(response2);
    return;
  }
  if (err instanceof ZodError) {
    const response2 = {
      status: "fail",
      message: "Validation Error",
      errors: err.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message
      }))
    };
    res.status(400).json(response2);
    return;
  }
  if (err instanceof prismaNamespace_exports.PrismaClientKnownRequestError) {
    const prismaErr = err;
    if (prismaErr.code === "P2002") {
      const response2 = {
        status: "fail",
        message: "Resource already exists"
      };
      res.status(409).json(response2);
      return;
    }
    if (prismaErr.code === "P2025") {
      const response2 = {
        status: "fail",
        message: "Resource not found"
      };
      res.status(404).json(response2);
      return;
    }
  }
  if (err instanceof prismaNamespace_exports.PrismaClientValidationError) {
    const response2 = {
      status: "fail",
      message: "Database validation error"
    };
    res.status(400).json(response2);
    return;
  }
  if (err instanceof prismaNamespace_exports.PrismaClientInitializationError) {
    const response2 = {
      status: "error",
      message: "Database connection error"
    };
    logger.fatal({ err }, "Database connection failed");
    res.status(503).json(response2);
    return;
  }
  const response = {
    status: "error",
    message: process.env["NODE_ENV"] === "development" ? err.message : "Internal Server Error"
  };
  res.status(500).json(response);
};

// src/common/middleware/csrf.middleware.ts
import crypto from "crypto";

// src/modules/auth/auth.constants.ts
var REFRESH_TOKEN_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1e3;
var REFRESH_TOKEN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env["NODE_ENV"] === "production",
  sameSite: "strict",
  maxAge: REFRESH_TOKEN_COOKIE_MAX_AGE_MS
};
var REFRESH_TOKEN_CLEAR_OPTIONS = {
  httpOnly: true,
  secure: process.env["NODE_ENV"] === "production",
  sameSite: "strict"
};
var CSRF_COOKIE_NAME = "csrf-token";
var CSRF_HEADER_NAME = "x-csrf-token";
var CSRF_COOKIE_MAX_AGE_MS = 60 * 60 * 1e3;

// src/common/middleware/csrf.middleware.ts
var CSRF_EXEMPT_PATHS = [
  "/auth/login",
  "/auth/register",
  "/auth/refresh",
  "/auth/logout",
  "/auth/logout-all"
];
var csrfProtection = (req, res, next) => {
  if (process.env["NODE_ENV"] === "development") {
    return next();
  }
  const safeMethodsRegex = /^(GET|HEAD|OPTIONS)$/i;
  if (safeMethodsRegex.test(req.method)) {
    if (!req.cookies[CSRF_COOKIE_NAME]) {
      const token = crypto.randomBytes(32).toString("hex");
      res.cookie(CSRF_COOKIE_NAME, token, {
        httpOnly: false,
        secure: process.env["NODE_ENV"] === "production",
        sameSite: "strict",
        maxAge: CSRF_COOKIE_MAX_AGE_MS
      });
    }
    return next();
  }
  if (CSRF_EXEMPT_PATHS.includes(req.path)) {
    return next();
  }
  const cookieToken = req.cookies[CSRF_COOKIE_NAME];
  const headerToken = req.headers[CSRF_HEADER_NAME];
  if (!cookieToken || !headerToken) {
    throw new ApiError(403, "CSRF token missing");
  }
  if (cookieToken !== headerToken) {
    throw new ApiError(403, "CSRF token mismatch");
  }
  next();
};

// src/common/middleware/rate-limit.ts
import rateLimit from "express-rate-limit";
var limiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: (req, res, _next, options) => {
    logger.warn(`Rate limit exceeded for IP ${req.ip}`);
    res.status(options.statusCode).json({
      status: "fail",
      message: "Too many requests, please try again later."
    });
  }
});
var authLimiter = rateLimit({
  windowMs: 60 * 60 * 1e3,
  limit: 5,
  message: "Too many accounts created from this IP, please try again after an hour",
  handler: (req, res, _next, options) => {
    logger.warn(`Auth rate limit exceeded for IP ${req.ip}`);
    res.status(options.statusCode).json({
      status: "fail",
      message: "Too many login attempts, please try again later."
    });
  }
});

// src/routes/index.ts
import { Router as Router6 } from "express";

// src/modules/auth/auth.routes.ts
import { Router } from "express";

// src/modules/auth/auth.service.ts
import bcrypt from "bcrypt";

// src/common/lib/token.service.ts
import jwt from "jsonwebtoken";
import crypto2 from "crypto";

// src/common/lib/env.ts
import "dotenv/config";
import { z } from "zod";
var envSchema = z.object({
  DATABASE_URL: z.url({ message: "DATABASE_URL must be a valid database connection URL" }),
  JWT_ACCESS_SECRET: z.string().min(32, "JWT_ACCESS_SECRET must be at least 32 characters for security"),
  JWT_REFRESH_SECRET: z.string().min(32, "JWT_REFRESH_SECRET must be at least 32 characters"),
  JWT_ACCESS_EXPIRES_IN: z.string().default("15m"),
  JWT_REFRESH_EXPIRES_IN: z.string().default("7d"),
  STRIPE_SECRET_KEY: z.string().startsWith("sk_", "STRIPE_SECRET_KEY must start with sk_"),
  STRIPE_WEBHOOK_SECRET: z.string().startsWith("whsec_", "STRIPE_WEBHOOK_SECRET must start with whsec_"),
  PORT: z.string().regex(/^\d+$/, "PORT must be a number").default("3000").transform(Number),
  API_BASE_URL: z.url().default("http://localhost:3000"),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  FRONTEND_URL: z.url().default("http://localhost:4000")
});
function validateEnv() {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const errors = result.error.issues.map((issue) => {
      return `  - ${issue.path.join(".")}: ${issue.message}`;
    }).join("\n");
    console.error("\nEnvironment validation failed:\n");
    console.error(errors);
    console.error("\nPlease check your .env file matches .env.example\n");
    throw new Error("Invalid environment configuration");
  }
  return result.data;
}
var env = validateEnv();

// src/common/lib/prisma.ts
import { PrismaPg } from "@prisma/adapter-pg";
var connectionString = env.DATABASE_URL;
var isRemoteDb = !connectionString.includes("@localhost") && !connectionString.includes("@127.0.0.1");
var isProduction = env.NODE_ENV === "production";
if (isRemoteDb && !isProduction) {
  if (connectionString.includes("sslmode=require")) {
    connectionString = connectionString.replace("sslmode=require", "sslmode=no-verify");
    console.warn("[SECURITY] SSL certificate validation bypassed for development. Do not use in production.");
  } else if (!connectionString.includes("sslmode")) {
    const separator = connectionString.includes("?") ? "&" : "?";
    connectionString = `${connectionString}${separator}sslmode=no-verify`;
    console.warn("[SECURITY] SSL certificate validation bypassed for development. Do not use in production.");
  }
}
var adapter = new PrismaPg({ connectionString });
var globalForPrisma = global;
var prisma = globalForPrisma.prisma || new PrismaClient({ adapter });
if (env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;

// src/common/lib/token.service.ts
var TokenService = class {
  accessSecret = env.JWT_ACCESS_SECRET;
  refreshSecret = env.JWT_REFRESH_SECRET;
  accessExpiresIn = env.JWT_ACCESS_EXPIRES_IN;
  refreshExpiresIn = env.JWT_REFRESH_EXPIRES_IN;
  /**
   * Generate access and refresh token pair.
   * Stores hashed refresh token in database.
   */
  async generateTokenPair(user, familyId) {
    const tokenId = crypto2.randomUUID();
    const currentFamilyId = familyId || crypto2.randomUUID();
    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        type: "access"
      },
      this.accessSecret,
      { expiresIn: this.accessExpiresIn }
    );
    const refreshToken = jwt.sign(
      {
        userId: user.id,
        tokenId,
        familyId: currentFamilyId,
        type: "refresh"
      },
      this.refreshSecret,
      { expiresIn: this.refreshExpiresIn }
    );
    const hashedToken = this.hashToken(refreshToken);
    const expiresAt = this.calculateExpiry(this.refreshExpiresIn);
    await prisma.refreshToken.create({
      data: {
        token: hashedToken,
        userId: user.id,
        familyId: currentFamilyId,
        expiresAt
      }
    });
    const decoded = jwt.decode(accessToken);
    const expiresIn = decoded.exp - decoded.iat;
    return { accessToken, refreshToken, expiresIn };
  }
  /**
   * Verify access token and return payload.
   */
  verifyAccessToken(token) {
    const payload = jwt.verify(token, this.accessSecret);
    if (payload.type !== "access") {
      throw new Error("Invalid token type");
    }
    return payload;
  }
  /**
   * Refresh tokens with rotation and reuse detection.
   * If a used token is presented, revokes the entire token family.
   */
  async refreshTokens(refreshToken) {
    const payload = jwt.verify(refreshToken, this.refreshSecret);
    if (payload.type !== "refresh") {
      throw new Error("Invalid token type");
    }
    const hashedToken = this.hashToken(refreshToken);
    const storedToken = await prisma.refreshToken.findUnique({
      where: { token: hashedToken },
      include: { user: true }
    });
    if (!storedToken) {
      throw new Error("Refresh token not found");
    }
    if (storedToken.isUsed) {
      await prisma.refreshToken.deleteMany({
        where: { familyId: storedToken.familyId }
      });
      throw new Error("Security Alert: Refresh token reuse detected. All sessions revoked.");
    }
    if (storedToken.expiresAt < /* @__PURE__ */ new Date()) {
      await prisma.refreshToken.delete({ where: { id: storedToken.id } });
      throw new Error("Refresh token expired");
    }
    await prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { isUsed: true }
    });
    return this.generateTokenPair({
      id: storedToken.user.id,
      email: storedToken.user.email,
      role: storedToken.user.role
    }, storedToken.familyId);
  }
  /**
   * Invalidate refresh token (logout).
   */
  async revokeRefreshToken(refreshToken) {
    const hashedToken = this.hashToken(refreshToken);
    await prisma.refreshToken.deleteMany({
      where: { token: hashedToken }
    });
  }
  /**
   * Invalidate all refresh tokens for a user.
   */
  async revokeAllUserTokens(userId) {
    await prisma.refreshToken.deleteMany({
      where: { userId }
    });
  }
  /**
   * Clean up expired tokens (call periodically).
   */
  async cleanupExpiredTokens() {
    const result = await prisma.refreshToken.deleteMany({
      where: { expiresAt: { lt: /* @__PURE__ */ new Date() } }
    });
    return result.count;
  }
  hashToken(token) {
    return crypto2.createHash("sha256").update(token).digest("hex");
  }
  calculateExpiry(duration) {
    const ms = this.parseDuration(duration);
    return new Date(Date.now() + ms);
  }
  parseDuration(duration) {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 7 * 24 * 60 * 60 * 1e3;
    }
    const value = parseInt(match[1] ?? "7", 10);
    const unit = match[2] ?? "d";
    switch (unit) {
      case "s":
        return value * 1e3;
      case "m":
        return value * 60 * 1e3;
      case "h":
        return value * 60 * 60 * 1e3;
      case "d":
        return value * 24 * 60 * 60 * 1e3;
      default:
        return 7 * 24 * 60 * 60 * 1e3;
    }
  }
};
var tokenService = new TokenService();

// src/common/repositories/base.repository.ts
var BaseRepository = class {
  prisma;
  constructor() {
    this.prisma = prisma;
  }
};

// src/modules/users/user.repository.ts
var UserRepository = class extends BaseRepository {
  async findByEmail(email) {
    return this.prisma.user.findUnique({
      where: { email }
    });
  }
  async findById(id) {
    return this.prisma.user.findUnique({
      where: { id }
    });
  }
  async create(data) {
    return this.prisma.user.create({
      data
    });
  }
  async updateStripeId(userId, stripeId) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { stripeId }
    });
  }
};

// src/modules/auth/auth.service.ts
var AuthService = class {
  constructor(userRepository = new UserRepository()) {
    this.userRepository = userRepository;
  }
  async register(data) {
    const existingUser = await this.userRepository.findByEmail(data.email);
    if (existingUser) {
      throw new ApiError(409, "User already exists");
    }
    const hashedPassword = await bcrypt.hash(data.password, 10);
    const user = await this.userRepository.create({
      email: data.email,
      password: hashedPassword,
      name: data.name ?? null
    });
    const { password: _password, ...userWithoutPassword } = user;
    return { user: userWithoutPassword };
  }
  async login(data) {
    const user = await this.userRepository.findByEmail(data.email);
    if (!user) {
      throw new ApiError(401, "Invalid email or password");
    }
    const isPasswordValid = await bcrypt.compare(data.password, user.password);
    if (!isPasswordValid) {
      throw new ApiError(401, "Invalid email or password");
    }
    const tokens = await tokenService.generateTokenPair({
      id: user.id,
      email: user.email,
      role: user.role
    });
    const { password: _password, ...userWithoutPassword } = user;
    return { user: userWithoutPassword, tokens };
  }
  async refreshTokens(refreshToken) {
    try {
      return await tokenService.refreshTokens(refreshToken);
    } catch {
      throw new ApiError(401, "Invalid or expired refresh token");
    }
  }
  async logout(refreshToken) {
    await tokenService.revokeRefreshToken(refreshToken);
  }
  async logoutAll(userId) {
    await tokenService.revokeAllUserTokens(userId);
  }
};

// src/common/utils/async-handler.ts
var catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
var asyncHandler = catchAsync;

// src/modules/auth/auth.controller.ts
var authService = new AuthService();
var register = asyncHandler(async (req, res) => {
  const result = await authService.register(req.body);
  res.status(201).json({
    status: "success",
    message: "User registered successfully",
    data: result
  });
});
var login = asyncHandler(async (req, res) => {
  const result = await authService.login(req.body);
  res.cookie("refreshToken", result.tokens.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
  res.status(200).json({
    status: "success",
    message: "Login successful",
    data: {
      user: result.user,
      accessToken: result.tokens.accessToken,
      expiresIn: result.tokens.expiresIn
    }
  });
});
var refresh = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies["refreshToken"];
  if (!refreshToken) {
    throw new ApiError(401, "Refresh token is required");
  }
  const tokens = await authService.refreshTokens(refreshToken);
  res.cookie("refreshToken", tokens.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
  res.status(200).json({
    status: "success",
    message: "Token refreshed successfully",
    data: {
      accessToken: tokens.accessToken,
      expiresIn: tokens.expiresIn
    }
  });
});
var logout = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies["refreshToken"];
  if (refreshToken) {
    await authService.logout(refreshToken);
  }
  res.clearCookie("refreshToken", REFRESH_TOKEN_CLEAR_OPTIONS);
  res.status(200).json({
    status: "success",
    message: "Logged out successfully"
  });
});
var logoutAll = asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new ApiError(401, "Authentication required");
  }
  await authService.logoutAll(req.user.userId);
  res.status(200).json({
    status: "success",
    message: "Logged out from all devices"
  });
});

// src/common/middleware/validate.ts
var validate = (schema) => (req, _res, next) => {
  try {
    schema.parse({
      body: req.body,
      query: req.query,
      params: req.params
    });
    next();
  } catch (error) {
    next(error);
  }
};

// src/modules/auth/auth.schema.ts
import { z as z2 } from "zod";
var registerSchema = z2.object({
  body: z2.object({
    email: z2.email({ message: "Invalid email format" }),
    password: z2.string().min(8, "Password must be at least 8 characters").regex(/[A-Z]/, "Password must contain at least one uppercase letter").regex(/[a-z]/, "Password must contain at least one lowercase letter").regex(/[0-9]/, "Password must contain at least one number"),
    name: z2.string().min(2).optional()
  })
});
var loginSchema = z2.object({
  body: z2.object({
    email: z2.email(),
    password: z2.string()
  })
});

// src/common/middleware/auth.middleware.ts
var authenticate = async (req, _res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new ApiError(401, "Unauthorized");
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
      throw new ApiError(401, "Unauthorized");
    }
    try {
      const decoded = tokenService.verifyAccessToken(token);
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId }
      });
      if (!user) {
        throw new ApiError(401, "User not found");
      }
      req.user = {
        userId: user.id,
        email: user.email,
        name: user.name ?? null,
        role: user.role,
        stripeId: user.stripeId ?? null
      };
      next();
    } catch {
      throw new ApiError(401, "Invalid or expired token");
    }
  } catch (error) {
    next(error);
  }
};

// src/modules/auth/auth.routes.ts
var router = Router();
router.post("/register", authLimiter, validate(registerSchema), register);
router.post("/login", authLimiter, validate(loginSchema), login);
router.post("/refresh", authLimiter, refresh);
router.post("/logout", logout);
router.post("/logout-all", authenticate, logoutAll);
var auth_routes_default = router;

// src/modules/users/user.routes.ts
import { Router as Router2 } from "express";

// src/modules/users/user.service.ts
var UserService = class {
  async getUserProfile(userId) {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });
    if (!user) {
      throw new ApiError(404, "User not found");
    }
    const { password: _password, ...userWithoutPassword } = user;
    return { user: userWithoutPassword };
  }
};

// src/modules/users/user.controller.ts
var userService = new UserService();
var getMe = asyncHandler(async (req, res) => {
  if (!req.user?.userId) {
    throw new ApiError(401, "Unauthorized");
  }
  const result = await userService.getUserProfile(req.user.userId);
  res.status(200).json({
    status: "success",
    message: "User profile retrieved successfully",
    data: result
  });
});

// src/modules/users/user.routes.ts
var router2 = Router2();
router2.get("/me", authenticate, getMe);
var user_routes_default = router2;

// src/modules/products/product.routes.ts
import { Router as Router3 } from "express";

// src/modules/products/product.repository.ts
var ProductRepository = class extends BaseRepository {
  async findActiveByIds(ids) {
    return this.prisma.product.findMany({
      where: {
        id: { in: ids },
        isActive: true
      }
    });
  }
  async findAll(skip, take) {
    return this.prisma.product.findMany({
      where: { isActive: true },
      orderBy: { createdAt: "desc" },
      skip,
      take
    });
  }
  async countActive() {
    return this.prisma.product.count({
      where: { isActive: true }
    });
  }
  async findById(id) {
    return this.prisma.product.findUnique({
      where: { id }
    });
  }
  async create(data) {
    return this.prisma.product.create({
      data
    });
  }
  async update(id, data) {
    return this.prisma.product.update({
      where: { id },
      data
    });
  }
  async delete(id) {
    return this.prisma.product.delete({
      where: { id }
    });
  }
};

// src/modules/products/product.service.ts
var ProductService = class {
  constructor(productRepository = new ProductRepository()) {
    this.productRepository = productRepository;
  }
  async getAllProducts(page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    const [products, total] = await Promise.all([
      this.productRepository.findAll(skip, limit),
      this.productRepository.countActive()
    ]);
    return {
      products,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  }
  async getProductById(id) {
    const product = await this.productRepository.findById(id);
    if (!product) {
      throw new ApiError(404, "Product not found");
    }
    return product;
  }
  async createProduct(userId, data) {
    return this.productRepository.create({
      ...data,
      description: data.description ?? null,
      userId
    });
  }
  async updateProduct(id, userId, data) {
    const product = await this.productRepository.findById(id);
    if (!product) {
      throw new ApiError(404, "Product not found");
    }
    if (product.userId !== userId) {
      throw new ApiError(403, "You are not authorized to update this product");
    }
    const updateData = {};
    if (data.name) updateData.name = data.name;
    if (data.price) updateData.price = data.price;
    if (data.currency) updateData.currency = data.currency;
    if (data.isActive !== void 0) updateData.isActive = data.isActive;
    updateData.description = data.description ?? product.description;
    return this.productRepository.update(id, updateData);
  }
  async deleteProduct(id) {
    const product = await this.productRepository.findById(id);
    if (!product) {
      throw new ApiError(404, "Product not found");
    }
    return this.productRepository.delete(id);
  }
};

// src/modules/products/product.controller.ts
var productService = new ProductService();
var getAllProducts = asyncHandler(async (req, res) => {
  const page = Math.max(1, parseInt(req.query["page"]) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query["limit"]) || 20));
  const result = await productService.getAllProducts(page, limit);
  res.status(200).json({
    status: "success",
    message: "Products retrieved successfully",
    data: result
  });
});
var getProductById = asyncHandler(async (req, res) => {
  const id = parseInt(req.params["id"]);
  const product = await productService.getProductById(id);
  res.status(200).json({
    status: "success",
    message: "Product retrieved successfully",
    data: { product }
  });
});
var createProduct = asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new ApiError(401, "Authentication required");
  }
  const product = await productService.createProduct(req.user.userId, req.body);
  res.status(201).json({
    status: "success",
    message: "Product created successfully",
    data: { product }
  });
});
var updateProduct = asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new ApiError(401, "Authentication required");
  }
  const id = parseInt(req.params["id"]);
  const product = await productService.updateProduct(id, req.user.userId, req.body);
  res.status(200).json({
    status: "success",
    message: "Product updated successfully",
    data: { product }
  });
});
var deleteProduct = asyncHandler(async (req, res) => {
  const id = parseInt(req.params["id"]);
  await productService.deleteProduct(id);
  res.status(204).send();
});

// src/common/middleware/rbac.middleware.ts
var requireRole = (...roles) => {
  return (req, _res, next) => {
    if (!req.user) {
      throw new ApiError(401, "Authentication required");
    }
    if (!roles.includes(req.user.role)) {
      throw new ApiError(403, "Insufficient permissions");
    }
    next();
  };
};

// src/modules/products/product.schema.ts
import { z as z3 } from "zod";
var createProductSchema = z3.object({
  body: z3.object({
    name: z3.string().min(1),
    description: z3.string().optional(),
    price: z3.number().int().positive(),
    currency: z3.string().default("usd")
  })
});
var updateProductSchema = z3.object({
  body: z3.object({
    name: z3.string().min(1).optional(),
    description: z3.string().optional(),
    price: z3.number().int().positive().optional(),
    currency: z3.string().optional(),
    isActive: z3.boolean().optional()
  })
});

// src/modules/products/product.routes.ts
var router3 = Router3();
router3.get("/", getAllProducts);
router3.get("/:id", getProductById);
router3.post("/", authenticate, validate(createProductSchema), createProduct);
router3.patch("/:id", authenticate, validate(updateProductSchema), updateProduct);
router3.delete("/:id", authenticate, requireRole(Role.ADMIN), deleteProduct);
var product_routes_default = router3;

// src/modules/orders/order.routes.ts
import { Router as Router4 } from "express";

// src/modules/orders/order.repository.ts
var OrderRepository = class extends BaseRepository {
  async create(data) {
    return this.prisma.order.create({
      data,
      include: {
        items: {
          include: {
            product: true
          }
        },
        user: true
      }
    });
  }
  async updateStripeSessionId(orderId, sessionId) {
    return this.prisma.order.update({
      where: { id: orderId },
      data: { stripeSessionId: sessionId }
    });
  }
  async findById(id) {
    return this.prisma.order.findUnique({
      where: { id },
      include: { items: true }
    });
  }
};

// src/common/lib/stripe.ts
import Stripe from "stripe";
var stripe = new Stripe(env.STRIPE_SECRET_KEY, {
  apiVersion: "2025-12-15.clover"
});

// src/common/providers/stripe.provider.ts
var StripeProvider = class {
  async createCheckoutSession(input) {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: input.items.map((item) => ({
        price_data: {
          currency: item.currency,
          product_data: {
            name: item.name,
            ...item.description && { description: item.description }
          },
          unit_amount: item.price
        },
        quantity: item.quantity
      })),
      mode: "payment",
      success_url: input.successUrl.replace("{CHECKOUT_SESSION_ID}", "{CHECKOUT_SESSION_ID}"),
      cancel_url: input.cancelUrl,
      customer_email: input.userEmail,
      metadata: {
        orderId: input.orderId.toString(),
        userId: input.userId.toString()
      }
    });
    return { sessionId: session.id, url: session.url };
  }
};

// src/modules/orders/order.service.ts
var OrderService = class {
  constructor(orderRepository = new OrderRepository(), productRepository = new ProductRepository(), paymentProvider = new StripeProvider()) {
    this.orderRepository = orderRepository;
    this.productRepository = productRepository;
    this.paymentProvider = paymentProvider;
  }
  async createOrder(userId, data) {
    const { items } = data;
    const productIds = items.map((i) => i.productId);
    const products = await this.productRepository.findActiveByIds(productIds);
    if (products.length !== items.length) {
      throw new ApiError(400, "Some products are invalid or inactive");
    }
    let totalAmount = 0;
    const orderItemsData = items.map((item) => {
      const product = products.find((p) => p.id === item.productId);
      totalAmount += product.price * item.quantity;
      return {
        productId: item.productId,
        quantity: item.quantity,
        price: product.price
      };
    });
    const order = await this.orderRepository.create({
      userId,
      totalAmount,
      status: OrderStatus.PENDING,
      items: {
        create: orderItemsData
      }
    });
    const paymentItems = order.items.map((item) => ({
      name: item.product.name,
      ...item.product.description ? { description: item.product.description } : {},
      price: item.price,
      currency: item.product.currency,
      quantity: item.quantity
    }));
    const { sessionId, url } = await this.paymentProvider.createCheckoutSession({
      orderId: order.id,
      userId,
      userEmail: order.user.email,
      items: paymentItems,
      successUrl: `${env.API_BASE_URL}/api/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancelUrl: `${env.API_BASE_URL}/api/payment/cancel`
    });
    await this.orderRepository.updateStripeSessionId(order.id, sessionId);
    return { order, sessionId, url };
  }
};

// src/modules/orders/order.controller.ts
var orderService = new OrderService();
var createOrder = asyncHandler(async (req, res) => {
  if (!req.user?.userId) {
    throw new ApiError(401, "Unauthorized");
  }
  const result = await orderService.createOrder(req.user.userId, req.body);
  res.status(201).json({
    status: "success",
    message: "Order created successfully",
    data: result
  });
});

// src/modules/orders/order.schema.ts
import { z as z4 } from "zod";
var createOrderSchema = z4.object({
  body: z4.object({
    items: z4.array(z4.object({
      productId: z4.number().int().positive(),
      quantity: z4.number().int().positive()
    })).min(1)
  })
});

// src/modules/orders/order.routes.ts
var router4 = Router4();
router4.post("/", authenticate, validate(createOrderSchema), createOrder);
var order_routes_default = router4;

// src/modules/payments/payment.routes.ts
import { Router as Router5 } from "express";
var router5 = Router5();
router5.get("/success", (req, res) => {
  const sessionId = req.query["session_id"];
  res.status(200).json({
    status: "success",
    message: "Payment successful",
    data: {
      sessionId
    }
  });
});
router5.get("/cancel", (_req, res) => {
  res.status(200).json({
    status: "success",
    message: "Payment cancelled"
  });
});
var payment_routes_default = router5;

// src/routes/index.ts
var router6 = Router6();
router6.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
});
router6.use("/auth", auth_routes_default);
router6.use("/users", user_routes_default);
router6.use("/products", product_routes_default);
router6.use("/orders", order_routes_default);
router6.use("/payment", payment_routes_default);
var routes_default = router6;

// src/modules/webhooks/webhook.routes.ts
import { Router as Router7 } from "express";

// src/modules/webhooks/webhook.service.ts
var WebhookService = class {
  async handleStripeEvent(signature, payload) {
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        payload,
        signature,
        env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.error(`Webhook signature verification failed: ${message}`);
      throw new Error(`Webhook Error: ${message}`);
    }
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        await this.handleCheckoutSessionCompleted(session);
        break;
      }
      case "checkout.session.expired": {
        const expiredSession = event.data.object;
        await this.handleCheckoutSessionExpired(expiredSession);
        break;
      }
      default:
        logger.info(`Unhandled event type ${event.type}`);
    }
  }
  async handleCheckoutSessionCompleted(session) {
    const orderId = session.metadata?.["orderId"];
    if (!orderId) return;
    const orderIdNum = parseInt(orderId);
    await prisma.order.update({
      where: { id: orderIdNum },
      data: {
        status: OrderStatus.PAID,
        stripePaymentId: session.payment_intent
      }
    });
    logger.info(`Order ${orderIdNum} marked as PAID`);
  }
  async handleCheckoutSessionExpired(session) {
    const orderId = session.metadata?.["orderId"];
    if (!orderId) return;
    const orderIdNum = parseInt(orderId);
    await prisma.order.update({
      where: { id: orderIdNum },
      data: {
        status: OrderStatus.CANCELLED
      }
    });
    logger.info(`Order ${orderIdNum} marked as CANCELLED`);
  }
};

// src/modules/webhooks/webhook.controller.ts
var webhookService = new WebhookService();
var handleStripeWebhook = async (req, res) => {
  const signature = req.headers["stripe-signature"];
  if (!signature) {
    res.status(400).send("Missing stripe-signature header");
    return;
  }
  let rawBody;
  if (Buffer.isBuffer(req.body)) {
    rawBody = req.body;
  } else if (typeof req.body === "object") {
    rawBody = Buffer.from(JSON.stringify(req.body));
  } else if (typeof req.body === "string") {
    rawBody = Buffer.from(req.body);
  } else {
    res.status(400).send("Unable to parse request body");
    return;
  }
  try {
    await webhookService.handleStripeEvent(signature, rawBody);
    res.json({ received: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    res.status(400).send(message);
  }
};

// src/modules/webhooks/webhook.routes.ts
var router7 = Router7();
router7.post("/stripe", handleStripeWebhook);
var webhook_routes_default = router7;

// src/config/cors.ts
var allowedOrigins = [env.FRONTEND_URL];
var corsOptions = {
  origin: (origin, callback) => {
    if (!origin && env.NODE_ENV === "development") {
      return callback(null, true);
    }
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-csrf-token"]
};

// src/config/security.ts
var helmetOptions = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536e3,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
};

// src/app.ts
var app = express();
app.use(helmet(helmetOptions));
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(limiter);
app.use(pinoHttp({
  logger,
  autoLogging: true,
  quietReqLogger: false
}));
app.use("/api/webhooks", express.raw({ type: "application/json" }), webhook_routes_default);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api", csrfProtection, routes_default);
app.get("/", (_req, res) => {
  res.status(200).json({
    message: "Welcome to AdvanceEdu E-commerce API",
    version: "1.0.0",
    docs: "/api/health",
    endpoints: {
      health: "/api/health",
      auth: "/api/auth",
      users: "/api/users",
      products: "/api/products",
      orders: "/api/orders"
    }
  });
});
app.use(errorHandler);
var app_default = app;

// src/common/services/database.service.ts
var DatabaseService = class {
  async connect() {
    try {
      await prisma.$connect();
      logger.info("Database connection established");
    } catch (error) {
      logger.fatal({ err: error }, "Failed to connect to database");
      throw error;
    }
  }
  async disconnect() {
    await prisma.$disconnect();
    logger.info("Database connection closed");
  }
};
var databaseService = new DatabaseService();

// src/server.ts
var PORT = env.PORT;
async function bootstrap() {
  try {
    await databaseService.connect();
    const server = app_default.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });
    process.on("SIGTERM", async () => {
      logger.info("SIGTERM signal received: closing HTTP server");
      server.close(async () => {
        await databaseService.disconnect();
        logger.info("HTTP server closed");
        process.exit(0);
      });
    });
    process.on("SIGINT", async () => {
      logger.info("SIGINT signal received: closing HTTP server");
      server.close(async () => {
        await databaseService.disconnect();
        logger.info("HTTP server closed");
        process.exit(0);
      });
    });
  } catch (error) {
    logger.fatal({ err: error }, "Failed to start server");
    process.exit(1);
  }
}
if (!process.env["VERCEL"]) {
  bootstrap();
}
var server_default = app_default;
export {
  server_default as default
};
//# sourceMappingURL=server.js.map