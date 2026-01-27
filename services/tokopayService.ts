// TokoPay Payment Gateway Service
// API Documentation: https://docs.tokopay.id

import { doc, getDoc, collection, addDoc, updateDoc, serverTimestamp } from 'firebase/firestore/lite';
import { db } from './firebase';
import CryptoJS from 'crypto-js';

// Collection names
const ORDERS_COLLECTION = 'texa_orders';

// TokoPay Configuration from Environment
export const TOKOPAY_CONFIG = {
    merchantId: 'M250828KEAYY483',
    secretKey: 'b3bb79b23b82ed33a54927dbaac95d8a70e19de7f5d47a613d1db4d32776125c',
    apiBaseUrl: 'https://api.tokopay.id/v1',
    webhookIp: '178.128.104.179'
};

// Payment Methods Available
export const PAYMENT_METHODS = {
    // QRIS
    QRIS: [
        { code: 'QRISREALTIME', name: 'QRIS (Semua Bank & E-Wallet)', icon: '📱', category: 'qris' },
    ],
    // E-Wallet
    EWALLET: [
        { code: 'DANABALANCE', name: 'DANA', icon: '💙', category: 'ewallet' },
        { code: 'OVOBALANCE', name: 'OVO', icon: '💜', category: 'ewallet' },
        { code: 'SHOPEEPAYBALANCE', name: 'ShopeePay', icon: '🧡', category: 'ewallet' },
        { code: 'GOPAYBALANCE', name: 'GoPay', icon: '💚', category: 'ewallet' },
    ],
    // Bank Transfer (Virtual Account)
    BANK: [
        { code: 'BCAVA', name: 'BCA Virtual Account', icon: '🏦', category: 'bank' },
        { code: 'BNIVA', name: 'BNI Virtual Account', icon: '🏦', category: 'bank' },
        { code: 'BRIVA', name: 'BRI Virtual Account', icon: '🏦', category: 'bank' },
        { code: 'MANDIRIVA', name: 'Mandiri Virtual Account', icon: '🏦', category: 'bank' },
        { code: 'PERMATAVA', name: 'Permata Virtual Account', icon: '🏦', category: 'bank' },
        { code: 'CIMBVA', name: 'CIMB Niaga Virtual Account', icon: '🏦', category: 'bank' },
    ]
};

// Get all available payment methods
export const getAllPaymentMethods = () => {
    return [
        ...PAYMENT_METHODS.QRIS,
        ...PAYMENT_METHODS.EWALLET,
        ...PAYMENT_METHODS.BANK
    ];
};

// Generate Reference ID
export const generateRefId = (type: 'subscription' | 'individual', itemId: string): string => {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    const prefix = type === 'subscription' ? 'SUB' : 'TXA';
    return `${prefix}${timestamp}${random}`;
};

// Generate Signature for TokoPay
export const generateSignature = (refId: string): string => {
    const signatureString = `${TOKOPAY_CONFIG.merchantId}:${TOKOPAY_CONFIG.secretKey}:${refId}`;
    return CryptoJS.MD5(signatureString).toString();
};

// Verify Signature from TokoPay Callback
export const verifySignature = (merchantId: string, refId: string, receivedSignature: string): boolean => {
    const expectedSignature = CryptoJS.MD5(`${merchantId}:${TOKOPAY_CONFIG.secretKey}:${refId}`).toString();
    return expectedSignature === receivedSignature;
};

// Order Type
export interface TokopayOrder {
    refId: string;
    userId: string;
    userEmail: string;
    type: 'subscription' | 'individual';
    itemId: string; // package id or tool id
    itemName: string;
    duration: number; // days
    nominal: number;
    paymentMethod: string;
    status: 'pending' | 'paid' | 'expired' | 'failed';
    tokopayTrxId?: string;
    payUrl?: string;
    qrLink?: string;
    nomorVa?: string;
    totalBayar?: number;
    totalDiterima?: number;
    createdAt: any;
    updatedAt: any;
    paidAt?: any;
}

// Create TokoPay Order URL (Simple Method - GET)
export const createOrderUrl = (refId: string, nominal: number, metode: string): string => {
    const params = new URLSearchParams({
        merchant: TOKOPAY_CONFIG.merchantId,
        secret: TOKOPAY_CONFIG.secretKey,
        ref_id: refId,
        nominal: nominal.toString(),
        metode: metode
    });
    return `${TOKOPAY_CONFIG.apiBaseUrl}/order?${params.toString()}`;
};

// Create Order via API
export const createTokopayOrder = async (
    refId: string,
    nominal: number,
    metode: string
): Promise<{
    success: boolean;
    data?: {
        payUrl: string;
        trxId: string;
        totalBayar: number;
        totalDiterima: number;
        qrLink?: string;
        nomorVa?: string;
    };
    error?: string;
}> => {
    try {
        const apiUrl = createOrderUrl(refId, nominal, metode);
        const response = await fetch(apiUrl);
        const result = await response.json();

        if (result.status === 'Success') {
            return {
                success: true,
                data: {
                    payUrl: result.data.pay_url,
                    trxId: result.data.trx_id,
                    totalBayar: result.data.total_bayar,
                    totalDiterima: result.data.total_diterima,
                    qrLink: result.data.qr_link,
                    nomorVa: result.data.nomor_va
                }
            };
        } else {
            return {
                success: false,
                error: result.message || 'Gagal membuat order'
            };
        }
    } catch (error: any) {
        console.error('TokoPay API Error:', error);
        return {
            success: false,
            error: error.message || 'Network error'
        };
    }
};

// Save Order to Firestore
export const saveOrderToFirestore = async (order: TokopayOrder): Promise<string> => {
    try {
        const ordersRef = collection(db, ORDERS_COLLECTION);
        const docRef = await addDoc(ordersRef, {
            ...order,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp()
        });
        return docRef.id;
    } catch (error) {
        console.error('Error saving order:', error);
        throw error;
    }
};

// Update Order Status
export const updateOrderStatus = async (
    refId: string,
    status: 'paid' | 'expired' | 'failed',
    additionalData?: Partial<TokopayOrder>
): Promise<boolean> => {
    try {
        // Find order by refId
        const q = doc(db, ORDERS_COLLECTION, refId);
        const orderDoc = await getDoc(q);

        if (orderDoc.exists()) {
            await updateDoc(q, {
                status,
                ...additionalData,
                updatedAt: serverTimestamp(),
                ...(status === 'paid' ? { paidAt: serverTimestamp() } : {})
            });
            return true;
        }
        return false;
    } catch (error) {
        console.error('Error updating order:', error);
        return false;
    }
};

// Format IDR
export const formatIDR = (amount: number): string => {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }).format(amount);
};
