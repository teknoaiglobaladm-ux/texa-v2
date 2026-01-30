// Supabase Service - Database Integration
// This service provides Supabase as the primary database 

import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Supabase Configuration
const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || '';
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

// Initialize Supabase client
export const supabase: SupabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Database Types
export interface SupabaseUser {
    id: string;
    email: string;
    name?: string;
    role: 'USER' | 'ADMIN';
    photo_url?: string;
    subscription_end?: string;
    is_active: boolean;
    created_at: string;
    updated_at: string;
    last_login?: string;
}

export interface SupabaseTool {
    id: string;
    name: string;
    description: string;
    category: string;
    image_url?: string;
    tool_url: string;
    is_premium: boolean;
    is_active: boolean;
    sort_order: number;
    created_at: string;
    updated_at: string;
}

export interface SupabaseOrder {
    id: string;
    ref_id: string;
    user_id: string;
    user_email: string;
    type: 'subscription' | 'individual';
    item_id: string;
    item_name: string;
    duration: number;
    nominal: number;
    payment_method: string;
    status: 'pending' | 'paid' | 'expired' | 'failed';
    tokopay_trx_id?: string;
    pay_url?: string;
    total_bayar?: number;
    total_diterima?: number;
    created_at: string;
    updated_at: string;
    paid_at?: string;
}

export interface SupabaseSettings {
    id: string;
    key: string;
    value: any;
    updated_at: string;
}

// ============================================
// User Functions
// ============================================

export const getUser = async (userId: string): Promise<SupabaseUser | null> => {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId)
        .single();

    if (error) {
        console.error('Error getting user:', error);
        return null;
    }
    return data;
};

export const getUserByEmail = async (email: string): Promise<SupabaseUser | null> => {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    if (error) {
        console.error('Error getting user by email:', error);
        return null;
    }
    return data;
};

export const createOrUpdateUser = async (user: Partial<SupabaseUser> & { id: string; email: string }): Promise<SupabaseUser | null> => {
    const { data, error } = await supabase
        .from('users')
        .upsert({
            ...user,
            updated_at: new Date().toISOString()
        }, { onConflict: 'id' })
        .select()
        .single();

    if (error) {
        console.error('Error creating/updating user:', error);
        return null;
    }
    return data;
};

export const updateUserSubscription = async (userId: string, subscriptionEnd: string): Promise<boolean> => {
    const { error } = await supabase
        .from('users')
        .update({
            subscription_end: subscriptionEnd,
            updated_at: new Date().toISOString()
        })
        .eq('id', userId);

    if (error) {
        console.error('Error updating subscription:', error);
        return false;
    }
    return true;
};

// ============================================
// Tools/Catalog Functions
// ============================================

export const getAllTools = async (): Promise<SupabaseTool[]> => {
    const { data, error } = await supabase
        .from('tools')
        .select('*')
        .eq('is_active', true)
        .order('sort_order', { ascending: true });

    if (error) {
        console.error('Error getting tools:', error);
        return [];
    }
    return data || [];
};

export const getTool = async (toolId: string): Promise<SupabaseTool | null> => {
    const { data, error } = await supabase
        .from('tools')
        .select('*')
        .eq('id', toolId)
        .single();

    if (error) {
        console.error('Error getting tool:', error);
        return null;
    }
    return data;
};

export const createTool = async (tool: Omit<SupabaseTool, 'id' | 'created_at' | 'updated_at'>): Promise<SupabaseTool | null> => {
    const { data, error } = await supabase
        .from('tools')
        .insert({
            ...tool,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        })
        .select()
        .single();

    if (error) {
        console.error('Error creating tool:', error);
        return null;
    }
    return data;
};

export const updateTool = async (toolId: string, updates: Partial<SupabaseTool>): Promise<boolean> => {
    const { error } = await supabase
        .from('tools')
        .update({
            ...updates,
            updated_at: new Date().toISOString()
        })
        .eq('id', toolId);

    if (error) {
        console.error('Error updating tool:', error);
        return false;
    }
    return true;
};

export const deleteTool = async (toolId: string): Promise<boolean> => {
    const { error } = await supabase
        .from('tools')
        .delete()
        .eq('id', toolId);

    if (error) {
        console.error('Error deleting tool:', error);
        return false;
    }
    return true;
};

// ============================================
// Orders Functions
// ============================================

export const createOrder = async (order: Omit<SupabaseOrder, 'id' | 'created_at' | 'updated_at'>): Promise<SupabaseOrder | null> => {
    const { data, error } = await supabase
        .from('orders')
        .insert({
            ...order,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        })
        .select()
        .single();

    if (error) {
        console.error('Error creating order:', error);
        return null;
    }
    return data;
};

export const getOrderByRefId = async (refId: string): Promise<SupabaseOrder | null> => {
    const { data, error } = await supabase
        .from('orders')
        .select('*')
        .eq('ref_id', refId)
        .single();

    if (error) {
        console.error('Error getting order:', error);
        return null;
    }
    return data;
};

export const updateOrderStatus = async (
    refId: string,
    status: 'paid' | 'expired' | 'failed',
    additionalData?: Partial<SupabaseOrder>
): Promise<boolean> => {
    const updateData: any = {
        status,
        updated_at: new Date().toISOString()
    };

    if (status === 'paid') {
        updateData.paid_at = new Date().toISOString();
    }

    if (additionalData) {
        Object.assign(updateData, additionalData);
    }

    const { error } = await supabase
        .from('orders')
        .update(updateData)
        .eq('ref_id', refId);

    if (error) {
        console.error('Error updating order status:', error);
        return false;
    }
    return true;
};

export const getUserOrders = async (userId: string): Promise<SupabaseOrder[]> => {
    const { data, error } = await supabase
        .from('orders')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

    if (error) {
        console.error('Error getting user orders:', error);
        return [];
    }
    return data || [];
};

// ============================================
// Settings Functions
// ============================================

export const getSetting = async (key: string): Promise<any> => {
    const { data, error } = await supabase
        .from('settings')
        .select('value')
        .eq('key', key)
        .single();

    if (error) {
        console.error('Error getting setting:', error);
        return null;
    }
    return data?.value;
};

export const setSetting = async (key: string, value: any): Promise<boolean> => {
    const { error } = await supabase
        .from('settings')
        .upsert({
            key,
            value,
            updated_at: new Date().toISOString()
        }, { onConflict: 'key' });

    if (error) {
        console.error('Error setting value:', error);
        return false;
    }
    return true;
};

export const getAllSettings = async (): Promise<Record<string, any>> => {
    const { data, error } = await supabase
        .from('settings')
        .select('*');

    if (error) {
        console.error('Error getting all settings:', error);
        return {};
    }

    const settings: Record<string, any> = {};
    (data || []).forEach(item => {
        settings[item.key] = item.value;
    });
    return settings;
};

// ============================================
// Real-time Subscriptions
// ============================================

export const subscribeToTools = (callback: (tools: SupabaseTool[]) => void) => {
    // Initial fetch
    getAllTools().then(callback);

    // Subscribe to changes
    const subscription = supabase
        .channel('tools_changes')
        .on('postgres_changes',
            { event: '*', schema: 'public', table: 'tools' },
            () => {
                getAllTools().then(callback);
            }
        )
        .subscribe();

    return () => {
        subscription.unsubscribe();
    };
};

export const subscribeToUserOrders = (userId: string, callback: (orders: SupabaseOrder[]) => void) => {
    // Initial fetch
    getUserOrders(userId).then(callback);

    // Subscribe to changes
    const subscription = supabase
        .channel(`orders_${userId}`)
        .on('postgres_changes',
            { event: '*', schema: 'public', table: 'orders', filter: `user_id=eq.${userId}` },
            () => {
                getUserOrders(userId).then(callback);
            }
        )
        .subscribe();

    return () => {
        subscription.unsubscribe();
    };
};

// ============================================
// Auth Integration Helper
// ============================================

export const syncUserToDatabase = async (authUser: {
    uid: string;
    email: string | null;
    displayName: string | null;
    photoURL: string | null;
}): Promise<SupabaseUser | null> => {
    if (!authUser.email) return null;

    return createOrUpdateUser({
        id: authUser.uid,
        email: authUser.email,
        name: authUser.displayName || undefined,
        photo_url: authUser.photoURL || undefined,
        role: 'USER',
        is_active: true,
        last_login: new Date().toISOString()
    });
};

export default supabase;
