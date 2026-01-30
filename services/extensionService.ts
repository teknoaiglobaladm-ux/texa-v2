// Extension Settings Service - Migrated to Supabase with Admin API
import { supabase } from './supabaseService';

const SETTINGS_KEY = 'extension_config';

// API Base URL for admin server
const getApiBaseUrl = () => {
    if (typeof window !== 'undefined') {
        return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://127.0.0.1:8787'
            : '';
    }
    return 'http://127.0.0.1:8787';
};

// Extension Settings Interface
export interface ExtensionSettings {
    // Download Links
    downloadUrl: string;              // Link download extension (Google Drive, Chrome Web Store, dll)
    downloadButtonText?: string;      // Text untuk tombol download

    // Tutorial Video
    tutorialVideoUrl: string;         // URL video tutorial (YouTube embed atau lainnya)
    tutorialArticleUrl?: string;      // URL artikel tutorial (opsional)

    // Popup Content
    popupTitle?: string;              // Judul popup warning
    popupDescription?: string;        // Deskripsi popup
    popupIcon?: string;               // Emoji/icon untuk popup

    // Feature Flags
    requireExtension?: boolean;       // Apakah wajib install extension
    showTutorialVideo?: boolean;      // Tampilkan video tutorial

    // Timestamps
    updatedAt?: string;
    updatedBy?: string;
}

// Default settings
export const DEFAULT_EXTENSION_SETTINGS: ExtensionSettings = {
    downloadUrl: '',
    downloadButtonText: '📦 Download Extension',
    tutorialVideoUrl: '',
    tutorialArticleUrl: '',
    popupTitle: 'Extension Belum Terpasang',
    popupDescription: 'Untuk menggunakan tools ini, Anda perlu memasang TEXA-Ai Extension terlebih dahulu. Ikuti tutorial di bawah untuk panduan instalasi.',
    popupIcon: '🧩',
    requireExtension: true,
    showTutorialVideo: true
};

// Get extension settings
export const getExtensionSettings = async (): Promise<ExtensionSettings> => {
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
                return { ...DEFAULT_EXTENSION_SETTINGS, ...(result.data.value as object) } as ExtensionSettings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from('settings')
            .select('value')
            .eq('key', SETTINGS_KEY)
            .single();

        if (error || !data) {
            return DEFAULT_EXTENSION_SETTINGS;
        }

        return { ...DEFAULT_EXTENSION_SETTINGS, ...(data.value as object) } as ExtensionSettings;
    } catch (error) {
        console.error('Error getting extension settings:', error);
        return DEFAULT_EXTENSION_SETTINGS;
    }
};

// Subscribe to settings changes
export const subscribeToExtensionSettings = (callback: (settings: ExtensionSettings) => void) => {
    let stopped = false;
    let inFlight = false;

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            const settings = await getExtensionSettings();
            if (!stopped) callback(settings);
        } catch (error) {
            console.error('Error subscribing to extension settings:', error);
            if (!stopped) callback(DEFAULT_EXTENSION_SETTINGS);
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

// Save extension settings
export const saveExtensionSettings = async (
    settings: Partial<ExtensionSettings>,
    updatedBy?: string
): Promise<boolean> => {
    try {
        const current = await getExtensionSettings();
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
                console.log('✅ Extension settings saved via Admin API');
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
            console.error('Error saving extension settings:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error saving extension settings:', error);
        return false;
    }
};

// Check if extension is installed
export const checkExtensionInstalled = (): Promise<boolean> => {
    return new Promise((resolve) => {
        // Method 1: Check for TEXAExtension global
        if (window.TEXAExtension && window.TEXAExtension.ready) {
            resolve(true);
            return;
        }

        // Method 2: Send a ping message and wait for response
        const requestId = `ext-check-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const timeout = setTimeout(() => {
            window.removeEventListener('message', onResponse);
            resolve(false);
        }, 500); // 500ms timeout

        const onResponse = (event: MessageEvent) => {
            if (event.origin !== window.location.origin) return;
            const data = (event.data || {}) as any;

            if (data.type === 'TEXA_EXTENSION_PONG' && data.requestId === requestId) {
                clearTimeout(timeout);
                window.removeEventListener('message', onResponse);
                resolve(true);
            }
        };

        window.addEventListener('message', onResponse);

        // Send ping message
        window.postMessage({
            type: 'TEXA_EXTENSION_PING',
            requestId,
            source: 'TEXA_DASHBOARD'
        }, window.location.origin);
    });
};

// Parse YouTube URL to embed URL
export const parseYouTubeToEmbed = (url: string): string | null => {
    if (!url) return null;

    try {
        let videoId: string | null = null;

        // Pattern 1: youtube.com/shorts/VIDEO_ID
        const shortsMatch = url.match(/youtube\.com\/shorts\/([a-zA-Z0-9_-]+)/);
        if (shortsMatch) videoId = shortsMatch[1];

        // Pattern 2: youtube.com/watch?v=VIDEO_ID
        const watchMatch = url.match(/youtube\.com\/watch\?v=([a-zA-Z0-9_-]+)/);
        if (watchMatch) videoId = watchMatch[1];

        // Pattern 3: youtu.be/VIDEO_ID
        const shortMatch = url.match(/youtu\.be\/([a-zA-Z0-9_-]+)/);
        if (shortMatch) videoId = shortMatch[1];

        // Pattern 4: youtube.com/embed/VIDEO_ID (already embed)
        const embedMatch = url.match(/youtube\.com\/embed\/([a-zA-Z0-9_-]+)/);
        if (embedMatch) videoId = embedMatch[1];

        if (videoId) {
            videoId = videoId.split('?')[0].split('&')[0];
            return `https://www.youtube.com/embed/${videoId}?rel=0`;
        }

        return null;
    } catch {
        return null;
    }
};
