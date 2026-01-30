// Supabase Footer Service - Manage customizable footer settings with Admin API
import { supabase } from './supabaseService';

// API Base URL for admin server
const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://127.0.0.1:8787'
            : '';
    }
    return 'http://127.0.0.1:8787';
};

export interface SocialMediaLink {
    platform: string;
    label: string;
    url: string;
    icon: string;
    isActive: boolean;
}

export interface FooterSettings {
    id: string;
    companyName: string;
    companyTagline: string;
    copyrightText: string;
    whatsappUrl: string;
    email?: string;
    phone?: string;
    addressLine1: string;
    addressLine2?: string;
    city: string;
    country: string;
    mapsUrl: string;
    mapsEmbedUrl: string;
    socialMedia: SocialMediaLink[];
    updatedAt: string;
}

// Default footer settings
export const DEFAULT_FOOTER_SETTINGS: FooterSettings = {
    id: 'main',
    companyName: 'TEXA-Ai',
    companyTagline: 'Premium AI Tools Marketplace & Digital Creator',
    copyrightText: '© 2025 Texa Group. All rights reserved.',
    whatsappUrl: 'https://wa.link/32qf1o',
    email: 'contact@texa.ai',
    phone: '+62 xxx xxxx xxxx',
    addressLine1: 'Jl. Example Street No. 123',
    addressLine2: 'Gedung TEXA Lt. 5',
    city: 'Jakarta',
    country: 'Indonesia',
    mapsUrl: 'https://maps.app.goo.gl/VhzbPqZrVDMh3aU78',
    mapsEmbedUrl: 'https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d126920.45667891573!2d106.68942995!3d-6.229386699999999!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x2e69f3e945e34b9d%3A0x5371bf0fdad786a2!2sJakarta!5e0!3m2!1sen!2sid!4v1234567890123!5m2!1sen!2sid',
    socialMedia: [
        { platform: 'facebook', label: 'Facebook', url: 'https://facebook.com/texaai', icon: '📘', isActive: true },
        { platform: 'youtube', label: 'YouTube', url: 'https://youtube.com/@texaai', icon: '▶️', isActive: true },
        { platform: 'telegram', label: 'Telegram', url: 'https://t.me/texaai', icon: '✈️', isActive: true },
        { platform: 'instagram', label: 'Instagram', url: 'https://instagram.com/texaai', icon: '📷', isActive: true },
        { platform: 'threads', label: 'Threads', url: 'https://threads.net/@texaai', icon: '🧵', isActive: true },
        { platform: 'tiktok', label: 'TikTok', url: 'https://tiktok.com/@texaai', icon: '🎵', isActive: true }
    ],
    updatedAt: new Date().toISOString()
};

const LOCAL_STORAGE_KEY = 'texa_footer_settings';

const normalizeFooterSettings = (data: Partial<FooterSettings> | null | undefined): FooterSettings => {
    const merged = { ...DEFAULT_FOOTER_SETTINGS, ...(data || {}) } as FooterSettings;
    return {
        ...merged,
        id: merged.id || 'main',
        updatedAt: merged.updatedAt || new Date().toISOString()
    };
};

const loadFromLocalStorage = (): FooterSettings | null => {
    try {
        const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
        if (!raw) return null;
        return normalizeFooterSettings(JSON.parse(raw));
    } catch {
        return null;
    }
};

const saveToLocalStorage = (settings: FooterSettings): boolean => {
    try {
        localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(settings));
        return true;
    } catch {
        return false;
    }
};

// Get footer settings
export async function getFooterSettings(): Promise<FooterSettings | null> {
    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/footer-settings`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data) {
                const settings = normalizeFooterSettings({
                    id: result.data.id,
                    companyName: result.data.company_name,
                    companyTagline: result.data.company_tagline,
                    copyrightText: result.data.copyright_text,
                    whatsappUrl: result.data.whatsapp_url,
                    email: result.data.email,
                    phone: result.data.phone,
                    addressLine1: result.data.address_line1,
                    addressLine2: result.data.address_line2,
                    city: result.data.city,
                    country: result.data.country,
                    mapsUrl: result.data.maps_url,
                    mapsEmbedUrl: result.data.maps_embed_url,
                    socialMedia: result.data.social_media || [],
                    updatedAt: result.data.updated_at
                });
                saveToLocalStorage(settings);
                return settings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from('footer_settings')
            .select('*')
            .limit(1)
            .single();

        if (error || !data) {
            const local = loadFromLocalStorage();
            return local || normalizeFooterSettings(DEFAULT_FOOTER_SETTINGS);
        }

        const settings = normalizeFooterSettings({
            id: data.id,
            companyName: data.company_name,
            companyTagline: data.company_tagline,
            copyrightText: data.copyright_text,
            whatsappUrl: data.whatsapp_url,
            email: data.email,
            phone: data.phone,
            addressLine1: data.address_line1,
            addressLine2: data.address_line2,
            city: data.city,
            country: data.country,
            mapsUrl: data.maps_url,
            mapsEmbedUrl: data.maps_embed_url,
            socialMedia: data.social_media || [],
            updatedAt: data.updated_at
        });

        saveToLocalStorage(settings);
        return settings;
    } catch (error) {
        console.error('Error getting footer settings:', error);
        const local = loadFromLocalStorage();
        return local || normalizeFooterSettings(DEFAULT_FOOTER_SETTINGS);
    }
}

// Subscribe to footer settings changes
export function subscribeToFooterSettings(
    callback: (settings: FooterSettings | null) => void
): () => void {
    let stopped = false;
    let inFlight = false;

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            const settings = await getFooterSettings();
            if (stopped) return;
            callback(settings);
        } catch {
            if (stopped) return;
            callback(normalizeFooterSettings(DEFAULT_FOOTER_SETTINGS));
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
}

// Update footer settings
export async function updateFooterSettings(
    updates: Partial<FooterSettings>
): Promise<boolean> {
    const currentSettings = (await getFooterSettings()) || DEFAULT_FOOTER_SETTINGS;
    const updatedSettings: FooterSettings = normalizeFooterSettings({
        ...currentSettings,
        ...updates,
        id: 'main',
        updatedAt: new Date().toISOString()
    });

    saveToLocalStorage(updatedSettings);

    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/footer-settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            },
            body: JSON.stringify(updatedSettings)
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('✅ Footer settings saved via Admin API');
                return true;
            }
        }

        // Fallback to direct Supabase
        console.log('Admin API unavailable, falling back to Supabase...');
        const { data: existing } = await supabase.from('footer_settings').select('id').limit(1);

        const settingsData = {
            company_name: updatedSettings.companyName,
            company_tagline: updatedSettings.companyTagline,
            copyright_text: updatedSettings.copyrightText,
            whatsapp_url: updatedSettings.whatsappUrl,
            email: updatedSettings.email,
            phone: updatedSettings.phone,
            address_line1: updatedSettings.addressLine1,
            address_line2: updatedSettings.addressLine2,
            city: updatedSettings.city,
            country: updatedSettings.country,
            maps_url: updatedSettings.mapsUrl,
            maps_embed_url: updatedSettings.mapsEmbedUrl,
            social_media: updatedSettings.socialMedia,
            updated_at: updatedSettings.updatedAt
        };

        if (existing && existing.length > 0) {
            const { error } = await supabase
                .from('footer_settings')
                .update(settingsData)
                .eq('id', existing[0].id);
            if (error) throw error;
        } else {
            const { error } = await supabase
                .from('footer_settings')
                .insert(settingsData);
            if (error) throw error;
        }
        return true;
    } catch (error) {
        console.error('Error updating footer settings:', error);
        return false;
    }
}

// Update social media link
export async function updateSocialMediaLink(
    platform: string,
    updates: Partial<SocialMediaLink>
): Promise<boolean> {
    try {
        const settings = await getFooterSettings();
        if (!settings) return false;

        const updatedSocialMedia = settings.socialMedia.map(link =>
            link.platform === platform ? { ...link, ...updates } : link
        );

        return await updateFooterSettings({ socialMedia: updatedSocialMedia });
    } catch (error) {
        console.error('Error updating social media link:', error);
        return false;
    }
}

// Extract Google Maps embed URL from share URL
export function extractMapsEmbedUrl(shareUrl: string): string {
    if (shareUrl.includes('/maps/embed')) {
        return shareUrl;
    }
    const match = shareUrl.match(/\/maps\/.*\/(@[\d.-]+,[\d.-]+|place\/[^/]+)/);
    if (match) {
        return `https://www.google.com/maps/embed?pb=${encodeURIComponent(shareUrl)}`;
    }
    return shareUrl;
}
