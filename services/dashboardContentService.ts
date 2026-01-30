// Dashboard Content Service - Migrated to Supabase with Admin API
import { supabase } from './supabaseService';

const SETTINGS_KEY = 'dashboard_content';

// API Base URL for admin server
const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://127.0.0.1:8787'
            : '';
    }
    return 'http://127.0.0.1:8787';
};

// Dashboard Content Settings Interface
export interface DashboardContentSettings {
    // Catalog Section Text
    catalogTitle: string;
    catalogBadgeText: string;  // Supports {count} placeholder
    catalogSubtitle: string;

    // Catalog Section Styling
    catalogTitleColor?: string;
    catalogSubtitleColor?: string;
    catalogBadgeBgColor?: string;
    catalogBadgeTextColor?: string;

    // Empty State
    emptyStateEmoji: string;
    emptyStateTitle: string;
    emptyStateSubtitle: string;
    emptyStateButtonText: string;

    // Metadata
    updatedAt?: string;
    updatedBy?: string;
}

// Default Settings
export const DEFAULT_DASHBOARD_CONTENT: DashboardContentSettings = {
    // Catalog Section
    catalogTitle: 'Katalog AI Premium',
    catalogBadgeText: '{count} Tools',
    catalogSubtitle: 'Aktifkan tool favoritmu dalam hitungan detik.',

    // Styling - empty means use default theme colors
    catalogTitleColor: '',
    catalogSubtitleColor: '',
    catalogBadgeBgColor: '',
    catalogBadgeTextColor: '',

    // Empty State
    emptyStateEmoji: '🔍',
    emptyStateTitle: 'Tidak Ada Tools',
    emptyStateSubtitle: 'Coba pilih kategori lain atau reset filter.',
    emptyStateButtonText: 'Reset Filter'
};

// Get dashboard content settings
export const getDashboardContentSettings = async (): Promise<DashboardContentSettings> => {
    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings?key=${SETTINGS_KEY}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data?.value) {
                return { ...DEFAULT_DASHBOARD_CONTENT, ...(result.data.value as object) } as DashboardContentSettings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from('settings')
            .select('value')
            .eq('key', SETTINGS_KEY)
            .single();

        if (error || !data) {
            return DEFAULT_DASHBOARD_CONTENT;
        }

        return { ...DEFAULT_DASHBOARD_CONTENT, ...(data.value as object) } as DashboardContentSettings;
    } catch (error) {
        console.error('Error getting dashboard content settings:', error);
        return DEFAULT_DASHBOARD_CONTENT;
    }
};

// Subscribe to dashboard content changes (polling-based)
export const subscribeToDashboardContent = (
    callback: (settings: DashboardContentSettings) => void
) => {
    let stopped = false;
    let inFlight = false;

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            const settings = await getDashboardContentSettings();
            if (!stopped) callback(settings);
        } catch (error) {
            console.error('Error subscribing to dashboard content:', error);
            if (!stopped) callback(DEFAULT_DASHBOARD_CONTENT);
        } finally {
            inFlight = false;
        }
    };

    void fetchOnce();
    const intervalId = setInterval(fetchOnce, 10000);

    return () => {
        stopped = true;
        clearInterval(intervalId);
    };
};

// Save dashboard content settings
export const saveDashboardContentSettings = async (
    settings: Partial<DashboardContentSettings>,
    updatedBy?: string
): Promise<boolean> => {
    try {
        const current = await getDashboardContentSettings();
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
                key: SETTINGS_KEY,
                value: merged
            })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('✅ Dashboard content saved via Admin API');
                return true;
            }
        }

        // Fallback to direct Supabase
        console.log('Admin API unavailable, falling back to Supabase...');
        const { error } = await supabase
            .from('settings')
            .upsert({
                key: SETTINGS_KEY,
                value: merged,
                updated_at: new Date().toISOString()
            }, { onConflict: 'key' });

        if (error) {
            console.error('Error saving dashboard content settings:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error saving dashboard content settings:', error);
        return false;
    }
};

