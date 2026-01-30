// Header Service - Migrated to Supabase with Admin API
import { supabase } from './supabaseService';

const SETTINGS_KEY = 'header_config';

// API Base URL for admin server
const getApiBaseUrl = () => {
  if (typeof window !== 'undefined') {
    return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://127.0.0.1:8787'
      : '';
  }
  return 'http://127.0.0.1:8787';
};

export type HeaderNavActionType = 'route' | 'url';

export interface HeaderNavItem {
  id: string;
  label: string;
  actionType: HeaderNavActionType;
  actionValue: string;
  isActive?: boolean;
}

export interface HeaderContactInfo {
  phone: string;
  email: string;
  location: string;
}

export interface HeaderSettings {
  logoUrl: string;
  brandName: string;
  tagline: string;
  navItems: HeaderNavItem[];
  contact: HeaderContactInfo;
  updatedAt?: string;
  updatedBy?: string;
}

export const DEFAULT_HEADER_SETTINGS: HeaderSettings = {
  logoUrl: 'https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExcmZsdmIyeWFldDVlcXhoeGNpNWx3N2FyYml3Zjh4NnV2ancxaXBiayZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/dXlUFmuOWFRlHYgc9i/giphy.gif',
  brandName: 'TEXA',
  tagline: 'AI Digital Store',
  navItems: [
    { id: 'nav-1', label: 'Page 1', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-2', label: 'Page 2', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-3', label: 'Page 3', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-4', label: 'Page 4', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-5', label: 'Page 5', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-6', label: 'Page 6', actionType: 'route', actionValue: '', isActive: true },
    { id: 'nav-7', label: 'Page 7', actionType: 'route', actionValue: '', isActive: true }
  ],
  contact: {
    phone: '+62-812-8888-8888',
    email: 'support@texa.ai',
    location: 'Indonesia'
  }
};

export const getHeaderSettings = async (): Promise<HeaderSettings> => {
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
        return { ...DEFAULT_HEADER_SETTINGS, ...(result.data.value as object) } as HeaderSettings;
      }
    }

    // Fallback to direct Supabase
    const { data, error } = await supabase
      .from('settings')
      .select('value')
      .eq('key', SETTINGS_KEY)
      .single();

    if (error || !data) {
      return DEFAULT_HEADER_SETTINGS;
    }

    return { ...DEFAULT_HEADER_SETTINGS, ...(data.value as object) } as HeaderSettings;
  } catch (error) {
    console.error('Error getting header settings:', error);
    return DEFAULT_HEADER_SETTINGS;
  }
};

export const subscribeToHeaderSettings = (callback: (settings: HeaderSettings) => void) => {
  let stopped = false;
  let inFlight = false;

  const fetchOnce = async () => {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      const settings = await getHeaderSettings();
      if (!stopped) callback(settings);
    } catch (error) {
      console.error('Error subscribing to header settings:', error);
      if (!stopped) callback(DEFAULT_HEADER_SETTINGS);
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

export const saveHeaderSettings = async (
  settings: Partial<HeaderSettings>,
  updatedBy?: string
): Promise<boolean> => {
  try {
    const current = await getHeaderSettings();
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
        console.log('✅ Header settings saved via Admin API');
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
      console.error('Error saving header settings:', error);
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error saving header settings:', error);
    return false;
  }
};

