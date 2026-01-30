// Admin Service - Manage Users and Subscriptions - Migrated to Supabase
import { supabase } from './supabaseService';
import { TexaUser } from './supabaseAuthService';

// Table names for Supabase
const USERS_TABLE = 'users';
const TRANSACTIONS_TABLE = 'texa_transactions';

// Subscription Plan Interface
export interface SubscriptionPlan {
    id: string;
    name: string;
    durationDays: number;
    price: number;
    features: string[];
}

// Subscription Record Interface
export interface SubscriptionRecord {
    id: string;
    userId: string;
    userEmail: string;
    planName: string;
    startDate: string;
    endDate: string;
    price: number;
    status: 'active' | 'expired' | 'cancelled' | 'paid' | 'pending';
    createdAt: string;
}

// Stats Interface
export interface AdminStats {
    totalUsers: number;
    activeSubscriptions: number;
    expiredSubscriptions: number;
    totalRevenue: number;
    newUsersToday: number;
    adminCount: number;
}

const withTimeout = async <T,>(promise: Promise<T>, ms: number, timeoutMessage: string): Promise<T> => {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), ms);
    });
    try {
        return (await Promise.race([promise, timeoutPromise])) as T;
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
};

// Convert Supabase row to TexaUser format
const rowToTexaUser = (row: any): TexaUser => ({
    id: row.id,
    email: row.email || '',
    name: row.name || row.email || '',
    role: row.role || 'MEMBER',
    isActive: row.is_active !== false,
    subscriptionEnd: row.subscription_end || undefined,
    createdAt: row.created_at || new Date().toISOString(),
    lastLogin: row.last_login || undefined,
    photoURL: row.photo_url || undefined
});

// Get All Users (Realtime subscription via polling)
// Uses Admin API first to bypass RLS, with fallback to direct Supabase
export const subscribeToUsers = (callback: (users: TexaUser[]) => void) => {
    let stopped = false;
    let inFlight = false;

    // API Base URL for admin server
    const getApiBaseUrl = () => {
        if (typeof window !== 'undefined') {
            return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
                ? 'http://127.0.0.1:8787'
                : '';
        }
        return 'http://127.0.0.1:8787';
    };

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            // Try Admin API first (bypasses RLS)
            const apiBaseUrl = getApiBaseUrl();
            const response = await fetch(`${apiBaseUrl}/api/admin/users`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Dev-Bypass': 'true'
                }
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success && Array.isArray(result.data)) {
                    console.log(`✅ Loaded ${result.data.length} users via Admin API`);
                    const users: TexaUser[] = result.data.map(rowToTexaUser);
                    callback(users);
                    return;
                }
            }

            // Fallback to direct Supabase if Admin API fails
            console.log('Admin API unavailable for users, falling back to Supabase...');
            const { data, error } = await supabase
                .from(USERS_TABLE)
                .select('*')
                .order('created_at', { ascending: false });

            if (error) {
                console.error('Error fetching users:', error);
                callback([]);
                return;
            }

            const users: TexaUser[] = (data || []).map(rowToTexaUser);
            callback(users);
        } catch (error) {
            console.error('Error fetching users:', error);
            callback([]);
        } finally {
            inFlight = false;
        }
    };

    void fetchOnce();
    const intervalId = setInterval(fetchOnce, 5000);
    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

// Get All Users (One-time)
export const getAllUsers = async (): Promise<TexaUser[]> => {
    try {
        const { data, error } = await supabase
            .from(USERS_TABLE)
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            console.error('Error getting users:', error);
            return [];
        }

        return (data || []).map(rowToTexaUser);
    } catch (error) {
        console.error('Error getting users:', error);
        return [];
    }
};

// Admin API base URL
const ADMIN_API_BASE =
    (import.meta as any).env?.VITE_ADMIN_API_BASE || (import.meta.env.PROD ? '' : 'http://127.0.0.1:8787');

// Get auth token from Supabase
const getAuthToken = async (): Promise<string | null> => {
    try {
        const { data: { session } } = await supabase.auth.getSession();
        return session?.access_token || null;
    } catch {
        return null;
    }
};

const callAdminApi = async <T>(path: string, body: any): Promise<T> => {
    const token = await getAuthToken();
    const isDev = import.meta.env.DEV || window.location.hostname === 'localhost';

    const headers: Record<string, string> = {
        'content-type': 'application/json',
    };

    if (token) {
        headers['authorization'] = `Bearer ${token}`;
    }

    // Add dev bypass header for localhost
    if (isDev) {
        headers['x-dev-bypass'] = 'true';
    }

    let res: Response;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    try {
        res = await fetch(`${ADMIN_API_BASE}${path}`, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            signal: controller.signal
        });
    } catch (err: any) {
        if (err?.name === 'AbortError') {
            throw new Error('Timeout: server admin tidak merespons');
        }
        throw new Error('Server admin belum jalan');
    } finally {
        clearTimeout(timeoutId);
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data?.success) throw new Error(data?.message || 'Permintaan gagal');
    return data as T;
};

export const createManualMember = async (input: {
    email: string;
    name?: string;
    role?: 'ADMIN' | 'MEMBER';
    isActive?: boolean;
    subscriptionDays?: number;
}): Promise<{ success: boolean; action?: 'updated' | 'created' }> => {
    const email = (input.email || '').trim().toLowerCase();
    const role = input.role ?? 'MEMBER';
    const isActive = input.isActive ?? true;
    const name = (input.name || '').trim();

    if (!email) throw new Error('Email tidak valid');

    const result = await callAdminApi<{ success: true; uid: string; action: 'created' | 'updated' }>(
        '/api/admin/create-user',
        {
            email,
            name,
            role,
            isActive,
            subscriptionDays: input.subscriptionDays
        }
    );

    return { success: true, action: result.action };
};

export const createAuthMemberWithPassword = async (input: {
    email: string;
    password: string;
    name?: string;
    role?: 'ADMIN' | 'MEMBER';
    isActive?: boolean;
    subscriptionDays?: number;
}): Promise<{ success: true; uid: string; action: 'created' | 'updated' }> => {
    return callAdminApi('/api/admin/create-user', input);
};

export const setMemberPassword = async (input: {
    uid?: string;
    email?: string;
    password: string;
}): Promise<{ success: true }> => {
    return callAdminApi('/api/admin/set-password', input);
};

// Update User
export const updateUser = async (userId: string, data: Partial<TexaUser>): Promise<boolean> => {
    try {
        // Convert TexaUser fields to Supabase column names
        const updateData: Record<string, any> = {
            updated_at: new Date().toISOString()
        };

        if (data.name !== undefined) updateData.name = data.name;
        if (data.role !== undefined) updateData.role = data.role;
        if (data.isActive !== undefined) updateData.is_active = data.isActive;
        if (data.subscriptionEnd !== undefined) updateData.subscription_end = data.subscriptionEnd;
        if (data.email !== undefined) updateData.email = data.email;
        if (data.photoURL !== undefined) updateData.photo_url = data.photoURL;
        if (data.lastLogin !== undefined) updateData.last_login = data.lastLogin;

        const { error } = await supabase
            .from(USERS_TABLE)
            .update(updateData)
            .eq('id', userId);

        if (error) {
            console.error('Error updating user:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error updating user:', error);
        return false;
    }
};

// Test Database Permissions - Supabase Only
export const testDatabasePermissions = async (): Promise<{ supabase: string }> => {
    const results = { supabase: 'Testing...' };

    // Get Supabase URL from environment
    const supabaseUrl = (import.meta as any).env?.VITE_SUPABASE_URL || '';
    const supabaseKey = (import.meta as any).env?.VITE_SUPABASE_ANON_KEY || '';

    // Test Supabase Connection
    try {
        if (!supabaseUrl || !supabaseKey) {
            results.supabase = 'FAILED: Supabase not configured';
        } else {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);

            try {
                const response = await fetch(`${supabaseUrl}/rest/v1/`, {
                    method: 'GET',
                    headers: {
                        'apikey': supabaseKey,
                        'Authorization': `Bearer ${supabaseKey}`
                    },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    results.supabase = 'OK';
                } else {
                    results.supabase = `FAILED: HTTP ${response.status}`;
                }
            } catch (e: any) {
                clearTimeout(timeoutId);
                if (e.name === 'AbortError') {
                    results.supabase = 'FAILED: Connection timeout';
                } else {
                    results.supabase = `FAILED: ${e.message}`;
                }
            }
        }
    } catch (e: any) {
        results.supabase = `FAILED: ${e.message}`;
    }

    return results;
};

// Delete User
export const deleteUser = async (userId: string): Promise<boolean> => {
    try {
        const { error } = await supabase
            .from(USERS_TABLE)
            .delete()
            .eq('id', userId);

        if (error) {
            console.error('Error deleting user:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error deleting user:', error);
        return false;
    }
};

// Toggle User Active Status
export const toggleUserStatus = async (userId: string, isActive: boolean): Promise<boolean> => {
    return updateUser(userId, { isActive });
};

// Change User Role
export const changeUserRole = async (userId: string, role: 'ADMIN' | 'MEMBER'): Promise<boolean> => {
    return updateUser(userId, { role });
};

// Set User Subscription
export const setUserSubscription = async (
    userId: string,
    durationDays: number,
    planName: string = 'Premium',
    price: number = 0,
    userEmail?: string
): Promise<boolean> => {
    try {
        const startDate = new Date();
        const endDate = new Date();
        endDate.setDate(startDate.getDate() + durationDays);

        // Update user's subscription end date
        const updated = await updateUser(userId, {
            subscriptionEnd: endDate.toISOString()
        });
        if (!updated) return false;

        // Create subscription record
        const { error } = await supabase
            .from(TRANSACTIONS_TABLE)
            .insert({
                user_id: userId,
                user_email: (userEmail || '').trim().toLowerCase(),
                plan_name: planName,
                start_date: startDate.toISOString(),
                end_date: endDate.toISOString(),
                price,
                status: 'paid',
                created_at: new Date().toISOString()
            });

        if (error) {
            console.error('Error creating subscription record:', error);
            // Don't fail the whole operation if just the record fails
        }

        return true;
    } catch (error) {
        console.error('Error setting subscription:', error);
        return false;
    }
};

// Subscribe to Subscription Records
export const subscribeToSubscriptionRecords = (callback: (records: SubscriptionRecord[]) => void) => {
    let stopped = false;
    let inFlight = false;

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            const { data, error } = await supabase
                .from(TRANSACTIONS_TABLE)
                .select('*')
                .order('created_at', { ascending: false });

            if (error) {
                console.error('Error fetching transactions:', error);
                callback([]);
                return;
            }

            const records: SubscriptionRecord[] = (data || []).map((row: any) => ({
                id: row.id,
                userId: row.user_id,
                userEmail: row.user_email || '',
                planName: row.plan_name || '',
                startDate: row.start_date || '',
                endDate: row.end_date || '',
                price: row.price || 0,
                status: row.status || 'pending',
                createdAt: row.created_at || ''
            }));

            callback(records);
        } catch (error) {
            console.error('Error fetching transactions:', error);
            callback([]);
        } finally {
            inFlight = false;
        }
    };

    void fetchOnce();
    const intervalId = setInterval(fetchOnce, 5000);
    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

export const calculateTotalRevenue = (records: SubscriptionRecord[]): number => {
    return records
        .filter((r) => {
            const status = String((r as any).status || '').toLowerCase();
            const isPaidLike =
                status === '' ||
                status === 'paid' ||
                status === 'active' ||
                status === 'success' ||
                status === 'settlement' ||
                status === 'completed';
            return isPaidLike && typeof r.price === 'number' && r.price > 0;
        })
        .reduce((sum, r) => sum + r.price, 0);
};

// Remove User Subscription
export const removeUserSubscription = async (userId: string): Promise<boolean> => {
    try {
        const updated = await updateUser(userId, {
            subscriptionEnd: null
        });
        return updated;
    } catch (error) {
        console.error('Error removing subscription:', error);
        return false;
    }
};

// Get Admin Stats
export const getAdminStats = (users: TexaUser[], totalRevenue: number = 0): AdminStats => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    const activeSubscriptions = users.filter(u =>
        u.subscriptionEnd && new Date(u.subscriptionEnd) > now
    ).length;

    const expiredSubscriptions = users.filter(u =>
        u.subscriptionEnd && new Date(u.subscriptionEnd) <= now
    ).length;

    const newUsersToday = users.filter(u =>
        u.createdAt && new Date(u.createdAt) >= today
    ).length;

    const adminCount = users.filter(u => u.role === 'ADMIN').length;

    return {
        totalUsers: users.length,
        activeSubscriptions,
        expiredSubscriptions,
        totalRevenue,
        newUsersToday,
        adminCount
    };
};

// Search Users
export const searchUsers = (users: TexaUser[], searchTerm: string): TexaUser[] => {
    if (!searchTerm.trim()) return users;

    const term = searchTerm.toLowerCase();
    return users.filter(user =>
        user.email.toLowerCase().includes(term) ||
        user.name.toLowerCase().includes(term) ||
        user.id.toLowerCase().includes(term)
    );
};

// Filter Users by Status
export const filterUsersByStatus = (
    users: TexaUser[],
    filter: 'all' | 'active' | 'expired' | 'admin' | 'member'
): TexaUser[] => {
    const now = new Date();

    switch (filter) {
        case 'active':
            return users.filter(u => u.subscriptionEnd && new Date(u.subscriptionEnd) > now);
        case 'expired':
            return users.filter(u => !u.subscriptionEnd || new Date(u.subscriptionEnd) <= now);
        case 'admin':
            return users.filter(u => u.role === 'ADMIN');
        case 'member':
            return users.filter(u => u.role === 'MEMBER');
        default:
            return users;
    }
};

// Format Date for Display
export const formatDate = (dateString: string | null | undefined): string => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString('id-ID', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
};

// Calculate Days Remaining
export const getDaysRemaining = (endDate: string | null): number | null => {
    if (!endDate) return null;
    const now = new Date();
    const end = new Date(endDate);
    const diff = Math.ceil((end.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return diff;
};

// Get Status Badge
export const getSubscriptionStatus = (endDate: string | null): 'active' | 'expired' | 'none' => {
    if (!endDate) return 'none';
    const daysRemaining = getDaysRemaining(endDate);
    if (daysRemaining === null || daysRemaining <= 0) return 'expired';
    return 'active';
};
