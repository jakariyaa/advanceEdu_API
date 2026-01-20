/**
 * OpenAPI Document Generator
 * 
 * Generates OpenAPI 3.1 documentation from Zod schemas.
 * Run with: npx tsx src/docs/openapi.ts > openapi.json
 */
import { z } from 'zod';
import { createDocument } from 'zod-openapi';

// ============== Shared Schemas ==============

const errorResponseSchema = z.object({
    status: z.enum(['fail', 'error']),
    message: z.string(),
    errors: z.array(z.object({
        field: z.string(),
        message: z.string(),
    })).optional(),
}).meta({ id: 'ErrorResponse' });

const paginationSchema = z.object({
    page: z.number().int().positive(),
    limit: z.number().int().positive(),
    total: z.number().int(),
    totalPages: z.number().int(),
}).meta({ id: 'Pagination' });

// ============== Auth Schemas ==============

const registerRequestSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    name: z.string().min(2).optional(),
}).meta({ id: 'RegisterRequest' });

const loginRequestSchema = z.object({
    email: z.string().email(),
    password: z.string(),
}).meta({ id: 'LoginRequest' });

const userSchema = z.object({
    id: z.number().int(),
    email: z.string().email(),
    name: z.string().nullable(),
    role: z.enum(['USER', 'ADMIN']),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
}).meta({ id: 'User' });

const loginResponseSchema = z.object({
    status: z.literal('success'),
    message: z.string(),
    data: z.object({
        user: userSchema,
        accessToken: z.string(),
        expiresIn: z.number().int(),
    }),
}).meta({ id: 'LoginResponse' });

// ============== Product Schemas ==============

const productSchema = z.object({
    id: z.number().int(),
    name: z.string(),
    description: z.string().nullable(),
    price: z.number().int().positive(),
    currency: z.string(),
    isActive: z.boolean(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
}).meta({ id: 'Product' });

const createProductRequestSchema = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    price: z.number().int().positive(),
    currency: z.string().default('usd'),
}).meta({ id: 'CreateProductRequest' });

const updateProductRequestSchema = z.object({
    name: z.string().min(1).optional(),
    description: z.string().optional(),
    price: z.number().int().positive().optional(),
    currency: z.string().optional(),
    isActive: z.boolean().optional(),
}).meta({ id: 'UpdateProductRequest' });

const productListResponseSchema = z.object({
    status: z.literal('success'),
    message: z.string(),
    data: z.object({
        products: z.array(productSchema),
        pagination: paginationSchema,
    }),
}).meta({ id: 'ProductListResponse' });

const singleProductResponseSchema = z.object({
    status: z.literal('success'),
    message: z.string(),
    data: z.object({
        product: productSchema,
    }),
}).meta({ id: 'SingleProductResponse' });

// ============== Order Schemas ==============

const orderItemSchema = z.object({
    productId: z.number().int().positive(),
    quantity: z.number().int().positive(),
}).meta({ id: 'OrderItem' });

const createOrderRequestSchema = z.object({
    items: z.array(orderItemSchema).min(1),
}).meta({ id: 'CreateOrderRequest' });

const orderResponseSchema = z.object({
    status: z.literal('success'),
    message: z.string(),
    data: z.object({
        order: z.object({
            id: z.number().int(),
            userId: z.number().int(),
            status: z.enum(['PENDING', 'PAID', 'FAILED', 'CANCELLED', 'REFUNDED']),
            totalAmount: z.number().int(),
        }),
        sessionId: z.string(),
        url: z.string().url().nullable(),
    }),
}).meta({ id: 'CreateOrderResponse' });

// ============== Generate Document ==============

const document = createDocument({
    openapi: '3.1.0',
    info: {
        title: 'AdvanceEdu E-commerce API',
        version: '1.0.0',
        description: 'Production-ready REST API for e-commerce/subscription system with Stripe integration.',
        contact: {
            name: 'API Support',
        },
    },
    servers: [
        { url: 'http://localhost:3000', description: 'Development' },
    ],
    tags: [
        { name: 'Auth', description: 'Authentication endpoints' },
        { name: 'Products', description: 'Product management' },
        { name: 'Orders', description: 'Order management' },
        { name: 'Users', description: 'User profile' },
    ],
    paths: {
        '/api/health': {
            get: {
                summary: 'Health Check',
                tags: ['Health'],
                responses: {
                    '200': {
                        description: 'API is healthy',
                        content: {
                            'application/json': {
                                schema: z.object({
                                    status: z.literal('ok'),
                                    timestamp: z.string().datetime(),
                                }),
                            },
                        },
                    },
                },
            },
        },
        '/api/auth/register': {
            post: {
                summary: 'Register a new user',
                tags: ['Auth'],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': { schema: registerRequestSchema },
                    },
                },
                responses: {
                    '201': {
                        description: 'User registered successfully',
                        content: {
                            'application/json': {
                                schema: z.object({
                                    status: z.literal('success'),
                                    message: z.string(),
                                    data: z.object({ user: userSchema }),
                                }),
                            },
                        },
                    },
                    '400': {
                        description: 'Validation error',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                    '409': {
                        description: 'User already exists',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/auth/login': {
            post: {
                summary: 'Login and get access token',
                tags: ['Auth'],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': { schema: loginRequestSchema },
                    },
                },
                responses: {
                    '200': {
                        description: 'Login successful',
                        content: { 'application/json': { schema: loginResponseSchema } },
                    },
                    '401': {
                        description: 'Invalid credentials',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/auth/refresh': {
            post: {
                summary: 'Refresh access token',
                tags: ['Auth'],
                description: 'Uses HttpOnly cookie to refresh tokens. Client must include credentials.',
                responses: {
                    '200': {
                        description: 'Token refreshed',
                        content: {
                            'application/json': {
                                schema: z.object({
                                    status: z.literal('success'),
                                    message: z.string(),
                                    data: z.object({
                                        accessToken: z.string(),
                                        expiresIn: z.number().int(),
                                    }),
                                }),
                            },
                        },
                    },
                    '401': {
                        description: 'Invalid or expired refresh token',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/auth/logout': {
            post: {
                summary: 'Logout current session',
                tags: ['Auth'],
                responses: {
                    '200': {
                        description: 'Logged out successfully',
                        content: {
                            'application/json': {
                                schema: z.object({
                                    status: z.literal('success'),
                                    message: z.string(),
                                }),
                            },
                        },
                    },
                },
            },
        },
        '/api/products': {
            get: {
                summary: 'List all products',
                tags: ['Products'],
                parameters: [
                    { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                    { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
                ],
                responses: {
                    '200': {
                        description: 'Products retrieved',
                        content: { 'application/json': { schema: productListResponseSchema } },
                    },
                },
            },
            post: {
                summary: 'Create a new product',
                tags: ['Products'],
                security: [{ bearerAuth: [] }],
                requestBody: {
                    required: true,
                    content: { 'application/json': { schema: createProductRequestSchema } },
                },
                responses: {
                    '201': {
                        description: 'Product created',
                        content: {
                            'application/json': {
                                schema: singleProductResponseSchema,
                            },
                        },
                    },
                    '401': {
                        description: 'Unauthorized',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/products/{id}': {
            get: {
                summary: 'Get product by ID',
                tags: ['Products'],
                requestParams: {
                    path: z.object({ id: z.string().regex(/^\d+$/) }),
                },
                responses: {
                    '200': {
                        description: 'Product found',
                        content: {
                            'application/json': {
                                schema: singleProductResponseSchema,
                            },
                        },
                    },
                    '404': {
                        description: 'Product not found',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
            patch: {
                summary: 'Update a product',
                tags: ['Products'],
                security: [{ bearerAuth: [] }],
                requestParams: {
                    path: z.object({ id: z.string().regex(/^\d+$/) }),
                },
                requestBody: {
                    required: true,
                    content: { 'application/json': { schema: updateProductRequestSchema } },
                },
                responses: {
                    '200': {
                        description: 'Product updated',
                        content: {
                            'application/json': {
                                schema: singleProductResponseSchema,
                            },
                        },
                    },
                },
            },
            delete: {
                summary: 'Delete a product',
                tags: ['Products'],
                security: [{ bearerAuth: [] }],
                requestParams: {
                    path: z.object({ id: z.string().regex(/^\d+$/) }),
                },
                responses: {
                    '204': { description: 'Product deleted' },
                    '403': {
                        description: 'Forbidden - Admin only',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/orders': {
            post: {
                summary: 'Create an order and get Stripe checkout URL',
                tags: ['Orders'],
                security: [{ bearerAuth: [] }],
                requestBody: {
                    required: true,
                    content: { 'application/json': { schema: createOrderRequestSchema } },
                },
                responses: {
                    '201': {
                        description: 'Order created with checkout session',
                        content: { 'application/json': { schema: orderResponseSchema } },
                    },
                    '400': {
                        description: 'Invalid products',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                    '401': {
                        description: 'Unauthorized',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
        '/api/users/me': {
            get: {
                summary: 'Get current user profile',
                tags: ['Users'],
                security: [{ bearerAuth: [] }],
                responses: {
                    '200': {
                        description: 'User profile',
                        content: {
                            'application/json': {
                                schema: z.object({
                                    status: z.literal('success'),
                                    message: z.string(),
                                    data: z.object({
                                        user: userSchema,
                                    }),
                                }),
                            },
                        },
                    },
                    '401': {
                        description: 'Unauthorized',
                        content: { 'application/json': { schema: errorResponseSchema } },
                    },
                },
            },
        },
    },
    components: {
        securitySchemes: {
            bearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
            },
        },
    },
});

console.log(JSON.stringify(document, null, 2));
