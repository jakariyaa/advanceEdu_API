export interface CreateCheckoutSessionInput {
    orderId: number;
    userId: number;
    userEmail: string;
    items: {
        name: string;
        description?: string;
        price: number;
        currency: string;
        quantity: number;
    }[];
    successUrl: string;
    cancelUrl: string;
}

export interface PaymentProvider {
    createCheckoutSession(input: CreateCheckoutSessionInput): Promise<{ sessionId: string; url: string | null }>;
}
