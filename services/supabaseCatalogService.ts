// Supabase Catalog Service - Mengelola AI Tools di Supabase
// Service untuk CRUD operasi catalog tools

import { supabase, SupabaseTool } from './supabaseService';
import { AITool } from '../types';

// Extended interface for catalog document (compatible with existing code)
export interface CatalogItem extends AITool {
    createdAt?: string;
    updatedAt?: string;
    createdBy?: string;
    order?: number;
}

// Default categories (fallback)
export const DEFAULT_CATEGORIES = [
    'Menulis & Riset',
    'Desain & Art',
    'Desain Grafis',
    'Marketing',
    'Coding & Teks',
    'Produktivitas'
];

// Category Interface
export interface Category {
    id: string;
    name: string;
    order: number;
    createdAt?: string;
    updatedAt?: string;
}

// ============================================
// CATEGORY FUNCTIONS (Supabase)
// ============================================

// Get all categories 
export const getCategories = async (): Promise<Category[]> => {
    try {
        const { data, error } = await supabase
            .from('categories')
            .select('*')
            .order('order', { ascending: true });

        if (error) {
            console.error('Error getting categories:', error);
            return DEFAULT_CATEGORIES.map((name, index) => ({
                id: `default-${index}`,
                name,
                order: index
            }));
        }

        if (!data || data.length === 0) {
            // Seed default categories if empty
            await seedDefaultCategories();
            return DEFAULT_CATEGORIES.map((name, index) => ({
                id: `default-${index}`,
                name,
                order: index
            }));
        }

        return data.map(cat => ({
            id: cat.id,
            name: cat.name,
            order: cat.order || 0,
            createdAt: cat.created_at,
            updatedAt: cat.updated_at
        }));
    } catch (error) {
        console.error('Error getting categories:', error);
        return DEFAULT_CATEGORIES.map((name, index) => ({
            id: `default-${index}`,
            name,
            order: index
        }));
    }
};

// Subscribe to categories (polling untuk Supabase)
export const subscribeToCategories = (callback: (categories: Category[]) => void) => {
    let stopped = false;

    const fetchCategories = async () => {
        if (stopped) return;
        const categories = await getCategories();
        callback(categories);
    };

    // Initial fetch
    void fetchCategories();

    // Poll every 10 seconds
    const intervalId = setInterval(fetchCategories, 10000);

    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

// Seed default categories
export const seedDefaultCategories = async (): Promise<boolean> => {
    try {
        const categories = DEFAULT_CATEGORIES.map((name, index) => ({
            name,
            order: index,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }));

        const { error } = await supabase
            .from('categories')
            .insert(categories);

        if (error) {
            console.error('Error seeding categories:', error);
            return false;
        }

        console.log('Default categories seeded successfully');
        return true;
    } catch (error) {
        console.error('Error seeding categories:', error);
        return false;
    }
};

// Add category
export const addCategory = async (name: string): Promise<string | null> => {
    try {
        const { data: existing } = await supabase
            .from('categories')
            .select('order')
            .order('order', { ascending: false })
            .limit(1);

        const maxOrder = existing?.[0]?.order ?? -1;

        const { data, error } = await supabase
            .from('categories')
            .insert({
                name: name.trim(),
                order: maxOrder + 1,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();

        if (error) {
            console.error('Error adding category:', error);
            return null;
        }

        return data?.id || null;
    } catch (error) {
        console.error('Error adding category:', error);
        return null;
    }
};

// Update category
export const updateCategory = async (id: string, name: string): Promise<boolean> => {
    try {
        const { error } = await supabase
            .from('categories')
            .update({
                name: name.trim(),
                updated_at: new Date().toISOString()
            })
            .eq('id', id);

        if (error) {
            console.error('Error updating category:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error updating category:', error);
        return false;
    }
};

// Delete category
export const deleteCategory = async (id: string): Promise<boolean> => {
    try {
        const { error } = await supabase
            .from('categories')
            .delete()
            .eq('id', id);

        if (error) {
            console.error('Error deleting category:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error deleting category:', error);
        return false;
    }
};

// ============================================
// CATALOG FUNCTIONS (Supabase)
// ============================================

// Convert Supabase tool to CatalogItem format
const toLocalCatalogItem = (tool: any): CatalogItem => ({
    id: tool.id,
    name: tool.name,
    description: tool.description || '',
    category: tool.category || '',
    imageUrl: tool.image_url || '',
    targetUrl: tool.tool_url || '',
    status: tool.is_active ? 'active' : 'inactive',
    priceMonthly: tool.price_monthly || 0,
    order: tool.sort_order || 0,
    createdAt: tool.created_at,
    updatedAt: tool.updated_at,
    createdBy: tool.created_by,
    // Multi-tier pricing fields
    price7Days: tool.price_7_days ?? 0,
    price14Days: tool.price_14_days ?? 0,
    price30Days: tool.price_30_days ?? 0
});

// Convert CatalogItem to Supabase format
const toSupabaseTool = (item: Partial<CatalogItem>): any => {
    const converted: any = {};
    if (item.name !== undefined) converted.name = item.name;
    if (item.description !== undefined) converted.description = item.description;
    if (item.category !== undefined) converted.category = item.category;
    if (item.imageUrl !== undefined) converted.image_url = item.imageUrl;
    if (item.targetUrl !== undefined) converted.tool_url = item.targetUrl;
    if (item.status !== undefined) converted.is_active = item.status === 'active';
    if (item.priceMonthly !== undefined) converted.price_monthly = item.priceMonthly;
    if (item.order !== undefined) converted.sort_order = item.order;
    if (item.createdBy !== undefined) converted.created_by = item.createdBy;
    return converted;
};

// Get all catalog items - Uses admin API to bypass RLS and avoid connection issues
export const getCatalog = async (): Promise<CatalogItem[]> => {
    try {
        const apiBaseUrl = getApiBaseUrl();

        // Try Admin API first (works reliably)
        const response = await fetch(`${apiBaseUrl}/api/admin/tools`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && Array.isArray(result.data)) {
                console.log(`✅ Loaded ${result.data.length} tools via Admin API`);
                return result.data.map((tool: any) => ({
                    id: tool.id,
                    name: tool.name,
                    description: tool.description || '',
                    category: tool.category || '',
                    imageUrl: tool.image_url || tool.imageUrl || '',
                    targetUrl: tool.tool_url || tool.targetUrl || '',
                    status: tool.is_active ? 'active' : (tool.status || 'active'),
                    priceMonthly: tool.price_monthly || tool.priceMonthly || 0,
                    order: tool.sort_order || tool.order || 0,
                    createdAt: tool.created_at || tool.createdAt,
                    updatedAt: tool.updated_at || tool.updatedAt,
                    createdBy: tool.created_by || tool.createdBy,
                    // Multi-tier pricing fields (CRITICAL: these are used by CheckoutPopup)
                    price7Days: tool.price_7_days ?? tool.price7Days ?? 0,
                    price14Days: tool.price_14_days ?? tool.price14Days ?? 0,
                    price30Days: tool.price_30_days ?? tool.price30Days ?? 0,
                    // Individual pricing fields (legacy, preserve for compatibility)
                    individualPrice: tool.individual_price ?? tool.individualPrice ?? null,
                    individualDuration: tool.individual_duration ?? tool.individualDuration ?? 7,
                    individualDiscount: tool.individual_discount ?? tool.individualDiscount ?? null
                }));
            }
        }

        // Fallback to direct Supabase if Admin API fails
        console.log('Admin API unavailable, falling back to Supabase...');
        const { data, error } = await supabase
            .from('tools')
            .select('*')
            .order('sort_order', { ascending: true });

        if (error) {
            console.error('Error getting catalog:', error);
            return [];
        }

        return (data || []).map(toLocalCatalogItem);
    } catch (error) {
        console.error('Error getting catalog:', error);
        return [];
    }
};

// Subscribe to catalog (polling)
export const subscribeToCatalog = (callback: (items: CatalogItem[]) => void) => {
    let stopped = false;

    const fetchCatalog = async () => {
        if (stopped) return;
        const items = await getCatalog();
        callback(items);
    };

    // Initial fetch
    void fetchCatalog();

    // Poll every 7 seconds
    const intervalId = setInterval(fetchCatalog, 7000);

    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

// Get single catalog item
export const getCatalogItem = async (id: string): Promise<CatalogItem | null> => {
    try {
        const { data, error } = await supabase
            .from('tools')
            .select('*')
            .eq('id', id)
            .single();

        if (error) {
            console.error('Error getting catalog item:', error);
            return null;
        }

        return data ? toLocalCatalogItem(data) : null;
    } catch (error) {
        console.error('Error getting catalog item:', error);
        return null;
    }
};

// API Base URL for admin server
const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://127.0.0.1:8787'
            : '';
    }
    return 'http://127.0.0.1:8787';
};

// Add new catalog item - Uses admin API to bypass RLS
export const addCatalogItem = async (
    item: Omit<CatalogItem, 'id' | 'createdAt' | 'updatedAt'>,
    createdBy?: string
): Promise<string | null> => {
    try {
        const apiBaseUrl = getApiBaseUrl();

        const response = await fetch(`${apiBaseUrl}/api/admin/tools`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true' // For dev mode
            },
            body: JSON.stringify({
                name: item.name,
                description: item.description,
                category: item.category,
                imageUrl: item.imageUrl,
                targetUrl: item.targetUrl,
                status: item.status,
                priceMonthly: item.priceMonthly,
                createdBy: createdBy || 'admin'
            })
        });

        const result = await response.json();

        if (result.success) {
            console.log('✅ Tool added via admin API');
            return result.id || result.data?.id || 'success';
        } else {
            console.error('Error adding catalog item:', result.message);
            return null;
        }
    } catch (error) {
        console.error('Error adding catalog item:', error);
        return null;
    }
};

// Update catalog item - Uses admin API to bypass RLS
export const updateCatalogItem = async (
    id: string,
    updates: Partial<Omit<CatalogItem, 'id' | 'createdAt'>>
): Promise<boolean> => {
    try {
        const apiBaseUrl = getApiBaseUrl();

        const response = await fetch(`${apiBaseUrl}/api/admin/tools/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            },
            body: JSON.stringify({
                name: updates.name,
                description: updates.description,
                category: updates.category,
                imageUrl: updates.imageUrl,
                targetUrl: updates.targetUrl,
                status: updates.status,
                priceMonthly: updates.priceMonthly,
                order: updates.order,
                // Multi-tier pricing fields
                price7Days: (updates as any).price7Days,
                price14Days: (updates as any).price14Days,
                price30Days: (updates as any).price30Days
            })
        });

        const result = await response.json();

        if (result.success) {
            console.log('✅ Tool updated via admin API');
            return true;
        } else {
            console.error('Error updating catalog item:', result.message);
            return false;
        }
    } catch (error) {
        console.error('Error updating catalog item:', error);
        return false;
    }
};

// Delete catalog item - Uses admin API to bypass RLS
export const deleteCatalogItem = async (id: string): Promise<boolean> => {
    try {
        const apiBaseUrl = getApiBaseUrl();

        const response = await fetch(`${apiBaseUrl}/api/admin/tools/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        const result = await response.json();

        if (result.success) {
            console.log('✅ Tool deleted via admin API');
            return true;
        } else {
            console.error('Error deleting catalog item:', result.message);
            return false;
        }
    } catch (error) {
        console.error('Error deleting catalog item:', error);
        return false;
    }
};

// Toggle item status
export const toggleCatalogStatus = async (id: string, currentStatus: 'active' | 'inactive'): Promise<boolean> => {
    const newStatus = currentStatus === 'active' ? 'inactive' : 'active';
    return updateCatalogItem(id, { status: newStatus });
};

// Reorder catalog items
export const reorderCatalogItems = async (items: CatalogItem[]): Promise<boolean> => {
    try {
        const updates = items.map((item, index) =>
            supabase
                .from('tools')
                .update({ sort_order: index, updated_at: new Date().toISOString() })
                .eq('id', item.id)
        );
        await Promise.all(updates);
        return true;
    } catch (error) {
        console.error('Error reordering catalog:', error);
        return false;
    }
};

// Format price to Rupiah
export const formatPrice = (price: number): string => {
    return new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0
    }).format(price);
};

// Seed initial catalog data
export const seedCatalogData = async (): Promise<boolean> => {
    try {
        const existing = await getCatalog();
        if (existing.length > 0) {
            console.log('Catalog already has data, skipping seed');
            return false;
        }

        const initialData = [
            {
                name: 'ChatGPT Plus (Shared)',
                description: 'Akses penuh ke GPT-4o, DALL·E 3, dan fitur analisis data tercanggih.',
                category: 'Menulis & Riset',
                image_url: 'https://images.unsplash.com/photo-1677442136019-21780ecad995?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://chat.openai.com',
                is_active: true,
                is_premium: true,
                price_monthly: 45000,
                sort_order: 0
            },
            {
                name: 'Midjourney Pro',
                description: 'Generate gambar AI kualitas tinggi tanpa batas dengan mode cepat.',
                category: 'Desain & Art',
                image_url: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://midjourney.com',
                is_active: true,
                is_premium: true,
                price_monthly: 75000,
                sort_order: 1
            },
            {
                name: 'Canva Pro Teams',
                description: 'Buka jutaan aset premium dan hapus background otomatis.',
                category: 'Desain Grafis',
                image_url: 'https://images.unsplash.com/photo-1626785774573-4b799315345d?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://canva.com',
                is_active: true,
                is_premium: true,
                price_monthly: 15000,
                sort_order: 2
            },
            {
                name: 'Jasper AI Business',
                description: 'Bikin konten sosmed dan iklan 10x lebih cepat dengan AI.',
                category: 'Marketing',
                image_url: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://jasper.ai',
                is_active: true,
                is_premium: true,
                price_monthly: 99000,
                sort_order: 3
            },
            {
                name: 'Claude 3.5 Sonnet',
                description: 'AI cerdas untuk coding dan penulisan kreatif dengan konteks luas.',
                category: 'Coding & Teks',
                image_url: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://claude.ai',
                is_active: true,
                is_premium: true,
                price_monthly: 55000,
                sort_order: 4
            },
            {
                name: 'Grammarly Premium',
                description: 'Cek tata bahasa Inggris otomatis dan kirim email tanpa typo.',
                category: 'Produktivitas',
                image_url: 'https://images.unsplash.com/photo-1455390582262-044cdead277a?auto=format&fit=crop&q=80&w=400',
                tool_url: 'https://grammarly.com',
                is_active: true,
                is_premium: true,
                price_monthly: 25000,
                sort_order: 5
            }
        ].map(item => ({
            ...item,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            created_by: 'system'
        }));

        const { error } = await supabase
            .from('tools')
            .insert(initialData);

        if (error) {
            console.error('Error seeding catalog:', error);
            return false;
        }

        console.log('Catalog seeded successfully!');
        return true;
    } catch (error) {
        console.error('Error seeding catalog:', error);
        return false;
    }
};
