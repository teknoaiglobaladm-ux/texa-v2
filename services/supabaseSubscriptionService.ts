// Supabase Subscription Service - Full Subscription Management with Admin API
import { supabase } from './supabaseService';

const SETTINGS_TABLE = 'settings';
const SUBSCRIPTION_DOC = 'subscription_config';
const REVENUE_SHARE_DOC = 'revenue_share_config';

// API Base URL for admin server
const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://127.0.0.1:8787'
            : '';
    }
    return 'http://127.0.0.1:8787';
};

// ============ SUBSCRIPTION SETTINGS INTERFACES ============

export interface PerToolDurationTier {
    id: string;
    name: string;
    duration: number;
    price: number;
    discountPrice?: number;
    popular?: boolean;
    active: boolean;
}

export interface SubscriptionSettings {
    paymentUrl: string;
    paymentApiUrl?: string;
    successRedirectUrl: string;
    failedRedirectUrl: string;
    pendingRedirectUrl?: string;
    webhookUrl?: string;
    webhookSecret?: string;
    packages: SubscriptionPackageLegacy[];
    popupTitle?: string;
    popupDescription?: string;
    buttonText?: string;
    whatsappNumber?: string;
    enableAutoActivation?: boolean;
    enableManualPayment?: boolean;
    enableQRIS?: boolean;
    enablePerToolPurchase?: boolean;
    perToolDurationTiers?: PerToolDurationTier[];
    perToolPaymentUrl?: string;
    perToolPopupTitle?: string;
    perToolPopupDescription?: string;
    defaultToolPrice?: number;
    defaultToolDuration?: number;
    updatedAt?: string;
    updatedBy?: string;
    // Tokopay Configuration
    tokopayMerchantId?: string;
    tokopayWebhookUrl?: string;
    tokopayEnabledMethods?: {
        qris: boolean;
        ewallet: string[];  // e.g. ['DANABALANCE', 'OVOBALANCE']
        bank: string[];     // e.g. ['BCAVA', 'BNIVA']
    };
}

export interface SubscriptionPackageLegacy {
    id: string;
    name: string;
    duration: number;
    price: number;
    discountPrice?: number;
    features: string[];
    popular?: boolean;
    active: boolean;
}

// Alias for backward compatibility with components using SubscriptionPackage
export type SubscriptionPackage = SubscriptionPackageLegacy;

export const DEFAULT_SETTINGS: SubscriptionSettings = {
    paymentUrl: '',
    successRedirectUrl: '',
    failedRedirectUrl: '',
    packages: [
        {
            id: 'pkg-7',
            name: 'Paket 7 Hari',
            duration: 7,
            price: 25000,
            features: ['Akses semua AI Tools', 'Support via WhatsApp'],
            active: true
        },
        {
            id: 'pkg-30',
            name: 'Paket 30 Hari',
            duration: 30,
            price: 75000,
            discountPrice: 65000,
            features: ['Akses semua AI Tools', 'Priority Support', 'Update Fitur Terbaru'],
            popular: true,
            active: true
        },
        {
            id: 'pkg-90',
            name: 'Paket 90 Hari',
            duration: 90,
            price: 180000,
            discountPrice: 150000,
            features: ['Akses semua AI Tools', 'Priority Support 24/7', 'Early Access Fitur Baru', 'Bonus Tools Eksklusif'],
            active: true
        }
    ],
    popupTitle: 'Berlangganan Premium',
    popupDescription: 'Pilih paket yang sesuai untuk akses penuh semua AI Tools premium.',
    buttonText: 'Beli Sekarang',
    enableAutoActivation: false,
    enableManualPayment: true,
    enableQRIS: false,
    enablePerToolPurchase: true,
    perToolDurationTiers: [
        { id: 'tier-7', name: '7 Hari', duration: 7, price: 15000, active: true },
        { id: 'tier-14', name: '2 Minggu', duration: 14, price: 25000, discountPrice: 22000, popular: true, active: true },
        { id: 'tier-30', name: '1 Bulan', duration: 30, price: 45000, discountPrice: 39000, active: true }
    ],
    perToolPopupTitle: 'Beli Akses Tool',
    perToolPopupDescription: 'Pilih durasi akses untuk tool ini',
    // Default Tokopay Configuration
    tokopayMerchantId: 'M250828KEAYY483',
    tokopayWebhookUrl: 'https://digistore.texa.ai/api/callback/tokopay',
    tokopayEnabledMethods: {
        qris: true,
        ewallet: ['DANABALANCE', 'OVOBALANCE', 'SHOPEEPAYBALANCE', 'GOPAYBALANCE'],
        bank: ['BCAVA', 'BNIVA', 'BRIVA', 'MANDIRIVA', 'PERMATAVA', 'CIMBVA']
    }
};

// ============ SUBSCRIPTION SETTINGS FUNCTIONS ============

export const getSubscriptionSettings = async (): Promise<SubscriptionSettings> => {
    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings?key=${SUBSCRIPTION_DOC}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data?.value) {
                return { ...DEFAULT_SETTINGS, ...result.data.value } as SubscriptionSettings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from(SETTINGS_TABLE)
            .select('value')
            .eq('key', SUBSCRIPTION_DOC)
            .single();

        if (error || !data) return DEFAULT_SETTINGS;
        return { ...DEFAULT_SETTINGS, ...data.value } as SubscriptionSettings;
    } catch (error) {
        console.error('Error getting subscription settings:', error);
        return DEFAULT_SETTINGS;
    }
};

export const subscribeToSettings = (callback: (settings: SubscriptionSettings) => void) => {
    // Initial fetch
    getSubscriptionSettings().then(callback);

    // Polling fallback (Supabase realtime can be used if enabled)
    let stopped = false;
    const intervalId = setInterval(async () => {
        if (stopped) return;
        const settings = await getSubscriptionSettings();
        callback(settings);
    }, 10000);

    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

export const saveSubscriptionSettings = async (
    settings: Partial<SubscriptionSettings>,
    updatedBy?: string
): Promise<boolean> => {
    try {
        const current = await getSubscriptionSettings();
        const merged = {
            ...current,
            ...settings,
            updatedAt: new Date().toISOString(),
            updatedBy: updatedBy || 'admin'
        };

        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            },
            body: JSON.stringify({
                key: SUBSCRIPTION_DOC,
                value: merged
            })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('✅ Subscription settings saved via Admin API');
                return true;
            }
        }

        // Fallback to direct Supabase
        console.log('Admin API unavailable, falling back to Supabase...');
        const { error } = await supabase
            .from(SETTINGS_TABLE)
            .upsert({
                key: SUBSCRIPTION_DOC,
                value: merged
            }, { onConflict: 'key' });

        return !error;
    } catch (error) {
        console.error('Error saving subscription settings:', error);
        return false;
    }
};

// Format price to IDR
export const formatIDR = (amount: number): string => {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0
    }).format(amount);
};

// Generate unique package ID
export const generatePackageId = (): string => {
    return `pkg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

// ============ REVENUE SHARE ============

export type RevenueShareRole = 'OWNER' | 'ADMIN' | 'KARYAWAN';

export interface RevenueSharePerson {
    id: string;
    name: string;
    role: RevenueShareRole;
    percent: number;
}

export interface RevenueShareSettings {
    people: RevenueSharePerson[];
    updatedAt?: string;
    updatedBy?: string;
}

export const DEFAULT_REVENUE_SHARE: RevenueShareSettings = {
    people: [
        { id: 'owner-1', name: 'Owner', role: 'OWNER', percent: 50 },
        { id: 'admin-1', name: 'Admin', role: 'ADMIN', percent: 30 },
        { id: 'karyawan-1', name: 'Karyawan', role: 'KARYAWAN', percent: 20 }
    ]
};

export const getRevenueShareSettings = async (): Promise<RevenueShareSettings> => {
    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings?key=${REVENUE_SHARE_DOC}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data?.value) {
                return { ...DEFAULT_REVENUE_SHARE, ...result.data.value } as RevenueShareSettings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from(SETTINGS_TABLE)
            .select('value')
            .eq('key', REVENUE_SHARE_DOC)
            .single();

        if (error || !data) return DEFAULT_REVENUE_SHARE;
        return { ...DEFAULT_REVENUE_SHARE, ...data.value } as RevenueShareSettings;
    } catch (error) {
        console.error('Error getting revenue share settings:', error);
        return DEFAULT_REVENUE_SHARE;
    }
};

export const subscribeToRevenueShareSettings = (callback: (settings: RevenueShareSettings) => void) => {
    getRevenueShareSettings().then(callback);

    let stopped = false;
    const intervalId = setInterval(async () => {
        if (stopped) return;
        const settings = await getRevenueShareSettings();
        callback(settings);
    }, 10000);

    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

export const saveRevenueShareSettings = async (
    settings: Partial<RevenueShareSettings>,
    updatedBy?: string
): Promise<boolean> => {
    try {
        const merged = {
            ...settings,
            updatedAt: new Date().toISOString(),
            updatedBy: updatedBy || 'admin'
        };

        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            },
            body: JSON.stringify({
                key: REVENUE_SHARE_DOC,
                value: merged
            })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('✅ Revenue share settings saved via Admin API');
                return true;
            }
        }

        // Fallback to direct Supabase
        console.log('Admin API unavailable, falling back to Supabase...');
        const { error } = await supabase
            .from(SETTINGS_TABLE)
            .upsert({
                key: REVENUE_SHARE_DOC,
                value: merged
            }, { onConflict: 'key' });

        return !error;
    } catch (error) {
        console.error('Error saving revenue share settings:', error);
        return false;
    }
};

// ============ SUBSCRIPTION PACKAGES (Table-based) ============
//
// Subscription Package Interface for database table
export interface SubscriptionPackageRecord {
    id: string;
    name: string;
    durationDays: number;
    price: number;
    discountPrice?: number;
    isActive: boolean;
    sortOrder: number;
    createdAt?: string;
}

// Default subscription packages
const DEFAULT_PACKAGES: Omit<SubscriptionPackageRecord, 'id' | 'createdAt'>[] = [
    { name: '7 Hari', durationDays: 7, price: 25000, discountPrice: 20000, isActive: true, sortOrder: 0 },
    { name: '2 Minggu', durationDays: 14, price: 45000, discountPrice: 35000, isActive: true, sortOrder: 1 },
    { name: '1 Bulan', durationDays: 30, price: 75000, discountPrice: 55000, isActive: true, sortOrder: 2 }
];

// Get all subscription packages
export const getSubscriptionPackages = async (): Promise<SubscriptionPackageRecord[]> => {
    try {
        const { data, error } = await supabase
            .from('subscription_packages')
            .select('*')
            .eq('is_active', true)
            .order('sort_order', { ascending: true });

        if (error) {
            console.error('Error getting subscription packages:', error);
            return DEFAULT_PACKAGES.map((p, i) => ({ ...p, id: `default-${i}` }));
        }

        if (!data || data.length === 0) {
            await seedDefaultPackages();
            return DEFAULT_PACKAGES.map((p, i) => ({ ...p, id: `default-${i}` }));
        }

        return data.map(p => ({
            id: p.id,
            name: p.name,
            durationDays: p.duration_days,
            price: p.price,
            discountPrice: p.discount_price,
            isActive: p.is_active,
            sortOrder: p.sort_order,
            createdAt: p.created_at
        }));
    } catch (error) {
        console.error('Error getting subscription packages:', error);
        return DEFAULT_PACKAGES.map((p, i) => ({ ...p, id: `default-${i}` }));
    }
};

// Subscribe to subscription packages
export const subscribeToSubscriptionPackages = (callback: (packages: SubscriptionPackageRecord[]) => void) => {
    let stopped = false;

    const fetchPackages = async () => {
        if (stopped) return;
        const packages = await getSubscriptionPackages();
        callback(packages);
    };

    void fetchPackages();
    const intervalId = setInterval(fetchPackages, 15000);
    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

// Seed default packages
export const seedDefaultPackages = async (): Promise<boolean> => {
    try {
        const { data: existing } = await supabase.from('subscription_packages').select('id').limit(1);
        if (existing && existing.length > 0) return false;

        const packages = DEFAULT_PACKAGES.map(p => ({
            name: p.name,
            duration_days: p.durationDays,
            price: p.price,
            discount_price: p.discountPrice,
            is_active: p.isActive,
            sort_order: p.sortOrder,
            created_at: new Date().toISOString()
        }));

        const { error } = await supabase.from('subscription_packages').insert(packages);
        if (error) {
            console.error('Error seeding packages:', error);
            return false;
        }
        return true;
    } catch (error) {
        console.error('Error seeding packages:', error);
        return false;
    }
};

// Add subscription package
export const addSubscriptionPackage = async (pkg: Omit<SubscriptionPackageRecord, 'id' | 'createdAt'>): Promise<string | null> => {
    try {
        const { data, error } = await supabase
            .from('subscription_packages')
            .insert({
                name: pkg.name,
                duration_days: pkg.durationDays,
                price: pkg.price,
                discount_price: pkg.discountPrice,
                is_active: pkg.isActive,
                sort_order: pkg.sortOrder,
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (error) {
            console.error('Error adding package:', error);
            return null;
        }
        return data?.id || null;
    } catch (error) {
        console.error('Error adding package:', error);
        return null;
    }
};

// Update subscription package
export const updateSubscriptionPackage = async (id: string, updates: Partial<SubscriptionPackageRecord>): Promise<boolean> => {
    try {
        const updateData: any = {};
        if (updates.name !== undefined) updateData.name = updates.name;
        if (updates.durationDays !== undefined) updateData.duration_days = updates.durationDays;
        if (updates.price !== undefined) updateData.price = updates.price;
        if (updates.discountPrice !== undefined) updateData.discount_price = updates.discountPrice;
        if (updates.isActive !== undefined) updateData.is_active = updates.isActive;
        if (updates.sortOrder !== undefined) updateData.sort_order = updates.sortOrder;

        const { error } = await supabase
            .from('subscription_packages')
            .update(updateData)
            .eq('id', id);

        if (error) {
            console.error('Error updating package:', error);
            return false;
        }
        return true;
    } catch (error) {
        console.error('Error updating package:', error);
        return false;
    }
};

// Delete subscription package
export const deleteSubscriptionPackage = async (id: string): Promise<boolean> => {
    try {
        const { error } = await supabase.from('subscription_packages').delete().eq('id', id);
        if (error) {
            console.error('Error deleting package:', error);
            return false;
        }
        return true;
    } catch (error) {
        console.error('Error deleting package:', error);
        return false;
    }
};

// Get default packages
export const getDefaultPackages = () => DEFAULT_PACKAGES;
