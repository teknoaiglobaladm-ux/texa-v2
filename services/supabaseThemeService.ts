// Supabase Theme Service - Full theme settings management
import { supabase } from './supabaseService';

const DEFAULT_CB_USAGE = `import ColorBends from './ColorBends';

<ColorBends 
  colors={["#ff5c7a", "#8a5cff", "#00ffd1"]} 
  rotation={0} 
  speed={0.2} 
  scale={1} 
  frequency={1} 
  warpStrength={1} 
  mouseInfluence={1} 
  parallax={0.5} 
  noise={0.1} 
  transparent={false} 
  autoRotate={0} 
/>`;

const DEFAULT_CB_CSS = `.color-bends-container {
  position: relative;
  width: 100%;
  height: 100%;
  overflow: hidden;
}`;

const DEFAULT_CB_CODE = `// ColorBends component code...`;

// Full Theme Settings Interface
export interface ThemeSettings {
    useColorBends: boolean;
    cbRotation: number;
    cbSpeed: number;
    cbColors: string[];
    cbTransparent: boolean;
    cbAutoRotate: number;
    cbScale: number;
    cbWarp: number;
    cbFreq: number;
    cbMouseInfluence: number;
    cbParallax: number;
    cbNoise: number;
    cbUsage: string;
    cbCode: string;
    cbCss: string;
    bgUrl: string;
    bgBlur: number;
    parallaxSpeed: number;
    accentColor: string;
    textColorLight: string;
    textColorDark: string;
    fontFamily: string;
    glassBg: string;
    glassOpacity: number;
    glassBgDark: string;
    glassBorder: string;
    glassBorderDark: string;
    blur: number;
    radius: number;
    borderWidth: number;
    saturate: number;
    shadowOpacity: number;
    transitionSpeed: number;
    hoverScale: number;
    customCSS: string;
    glassBgLight?: string;
    glassBorderLight?: string;
    glassOpacityLight?: number;
    glassBorderOpacityLight?: number;
    glassOpacityDark?: number;
    glassBorderOpacityDark?: number;
}

export const DEFAULT_THEME_SETTINGS: ThemeSettings = {
    useColorBends: true,
    cbRotation: 0,
    cbSpeed: 0.2,
    cbColors: ['#ff5c7a', '#8a5cff', '#00ffd1'],
    cbTransparent: false,
    cbAutoRotate: 0,
    cbScale: 1,
    cbWarp: 1,
    cbFreq: 1,
    cbMouseInfluence: 1,
    cbParallax: 0.5,
    cbNoise: 0.1,
    cbUsage: DEFAULT_CB_USAGE,
    cbCode: DEFAULT_CB_CODE,
    cbCss: DEFAULT_CB_CSS,
    bgUrl: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=2564&auto=format&fit=crop',
    bgBlur: 5,
    parallaxSpeed: 0.2,
    accentColor: '124, 58, 237',
    textColorLight: '30, 41, 59',
    textColorDark: '248, 250, 252',
    fontFamily: "'Plus Jakarta Sans'",
    glassBg: '255, 255, 255',
    glassOpacity: 0.15,
    glassBgDark: '15, 23, 42',
    glassBorder: '255, 255, 255',
    glassBorderDark: '255, 255, 255',
    blur: 30,
    radius: 20,
    borderWidth: 1,
    saturate: 160,
    shadowOpacity: 0.3,
    transitionSpeed: 300,
    hoverScale: 1.05,
    customCSS: ''
};

const LOCAL_STORAGE_KEY = 'texa_theme_settings';

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

// Load from localStorage
const loadFromLocalStorage = (): ThemeSettings | null => {
    try {
        const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
        if (!raw) return null;
        return { ...DEFAULT_THEME_SETTINGS, ...JSON.parse(raw) };
    } catch {
        return null;
    }
};

// Save to localStorage
const saveToLocalStorage = (settings: ThemeSettings): void => {
    try {
        localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(settings));
    } catch { }
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

// Get theme settings from Supabase (via Admin API to bypass RLS)
export const getThemeSettings = async (): Promise<ThemeSettings> => {
    try {
        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings?key=theme_config`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            }
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data?.value) {
                const settings = { ...DEFAULT_THEME_SETTINGS, ...(result.data.value as object) };
                saveToLocalStorage(settings);
                return settings;
            }
        }

        // Fallback to direct Supabase
        const { data, error } = await supabase
            .from('settings')
            .select('value')
            .eq('key', 'theme_config')
            .single();

        if (error || !data) {
            const local = loadFromLocalStorage();
            return local || DEFAULT_THEME_SETTINGS;
        }

        const settings = { ...DEFAULT_THEME_SETTINGS, ...(data.value as object) };
        saveToLocalStorage(settings);
        return settings;
    } catch (error) {
        console.error('Error getting theme settings:', error);
        const local = loadFromLocalStorage();
        return local || DEFAULT_THEME_SETTINGS;
    }
};

// Subscribe to theme settings (polling)
export const subscribeToThemeSettings = (callback: (settings: ThemeSettings) => void): (() => void) => {
    let stopped = false;
    let inFlight = false;

    const fetchOnce = async () => {
        if (stopped || inFlight) return;
        inFlight = true;
        try {
            const settings = await getThemeSettings();
            if (stopped) return;
            callback(settings);
        } catch {
            if (stopped) return;
            callback(DEFAULT_THEME_SETTINGS);
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

// Save theme settings to Supabase (via Admin API to bypass RLS)
export const saveThemeSettings = async (
    settings: Partial<ThemeSettings>,
    updatedBy?: string
): Promise<boolean> => {
    try {
        const current = await getThemeSettings();
        const merged = {
            ...current,
            ...settings,
            updatedAt: new Date().toISOString(),
            updatedBy: updatedBy || 'admin'
        };

        saveToLocalStorage(merged);

        // Try Admin API first (bypasses RLS)
        const apiBaseUrl = getApiBaseUrl();
        const response = await fetch(`${apiBaseUrl}/api/admin/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Dev-Bypass': 'true'
            },
            body: JSON.stringify({
                key: 'theme_config',
                value: merged
            })
        });

        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('✅ Theme settings saved via Admin API');
                return true;
            }
        }

        // Fallback to direct Supabase
        console.log('Admin API unavailable, falling back to Supabase...');
        const { error } = await supabase
            .from('settings')
            .upsert({
                key: 'theme_config',
                value: merged,
                updated_at: new Date().toISOString()
            }, { onConflict: 'key' });

        if (error) {
            console.error('Error saving theme settings:', error);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Error saving theme settings:', error);
        return false;
    }
};

// Apply theme settings to DOM
export const applyThemeSettings = (settings: ThemeSettings) => {
    const accentColor = settings.accentColor || DEFAULT_THEME_SETTINGS.accentColor;
    const textColorLight = settings.textColorLight || DEFAULT_THEME_SETTINGS.textColorLight;
    const textColorDark = settings.textColorDark || DEFAULT_THEME_SETTINGS.textColorDark;

    const glassBg = settings.glassBg || settings.glassBgLight || DEFAULT_THEME_SETTINGS.glassBg;
    const glassBorder = settings.glassBorder || settings.glassBorderLight || DEFAULT_THEME_SETTINGS.glassBorder;
    const glassBgDark = settings.glassBgDark || DEFAULT_THEME_SETTINGS.glassBgDark;
    const glassBorderDark = settings.glassBorderDark || DEFAULT_THEME_SETTINGS.glassBorderDark;

    const glassOpacity = clamp(
        typeof settings.glassOpacity === 'number' ? settings.glassOpacity : (settings.glassOpacityLight ?? DEFAULT_THEME_SETTINGS.glassOpacity),
        0,
        1
    );

    const lightBorderOpacity = clamp(
        typeof settings.glassBorderOpacityLight === 'number' ? settings.glassBorderOpacityLight : glassOpacity * 0.5,
        0,
        1
    );
    const darkBorderOpacity = clamp(
        typeof settings.glassBorderOpacityDark === 'number' ? settings.glassBorderOpacityDark : glassOpacity * 0.5,
        0,
        1
    );

    const blur = clamp(settings.blur, 0, 120);
    const radius = clamp(settings.radius, 0, 60);
    const borderWidth = clamp(settings.borderWidth, 0, 8);
    const saturate = clamp(settings.saturate, 0, 300);
    const shadowOpacity = clamp(settings.shadowOpacity, 0, 1);
    const transitionSpeed = clamp(settings.transitionSpeed, 0, 2000);
    const hoverScale = clamp(settings.hoverScale, 1, 1.2);
    const bgBlur = clamp(settings.bgBlur, 0, 120);

    const blurSm = Math.max(6, Math.round(blur * 0.5));
    const blurLg = Math.max(20, Math.round(blur * 1.6));
    const glassBlur = Math.max(8, Math.round(blur * 0.55));
    const weakLight = clamp(glassOpacity * 0.3, 0, 1);
    const strongLight = clamp(glassOpacity * 1.3, 0, 1);
    const weakDark = clamp(glassOpacity * 0.3, 0, 1);
    const strongDark = clamp(glassOpacity * 1.3, 0, 1);

    const accentPrimary = `rgb(${accentColor})`;
    const accentGlow = `rgba(${accentColor}, 0.35)`;

    const css = `
    :root {
      --accent: ${accentColor};
      --accent-primary: ${accentPrimary};
      --accent-glow: ${accentGlow};

      --text-color: ${textColorLight};
      --text-primary: rgb(${textColorLight});
      --text-secondary: rgba(${textColorLight}, 0.72);
      --text-muted: rgba(${textColorLight}, 0.56);
      --readable-text: 0, 0, 0;
      --readable-text-shadow: 0 1px 1px rgba(255, 255, 255, 0.55), 0 0 16px rgba(255, 255, 255, 0.22), 0 0 32px rgba(255, 255, 255, 0.12);

      --glass-bg-base: ${glassBg};
      --glass-border-base: ${glassBorder};
      --glass-bg: rgba(var(--glass-bg-base), ${glassOpacity});
      --glass-bg-weak: rgba(var(--glass-bg-base), ${weakLight});
      --glass-bg-strong: rgba(var(--glass-bg-base), ${strongLight});
      --glass-border: rgba(var(--glass-border-base), ${lightBorderOpacity});

      --blur: ${blur}px;
      --blur-sm: ${blurSm}px;
      --blur-lg: ${blurLg}px;
      --glass-blur: ${glassBlur}px;
      --radius: ${radius}px;

      --bg-blur: ${bgBlur}px;
      --border-width: ${borderWidth}px;
      --saturate: ${saturate}%;
      --font-main: ${settings.fontFamily || DEFAULT_THEME_SETTINGS.fontFamily};
      --shadow-opacity: ${shadowOpacity};
      --transition-speed: ${transitionSpeed}ms;
      --smooth-transition: all ${transitionSpeed}ms cubic-bezier(0.4, 0, 0.2, 1);
      --hover-scale: ${hoverScale};
    }

    .dark {
      --text-color: ${textColorDark};
      --text-primary: rgb(${textColorDark});
      --text-secondary: rgba(${textColorDark}, 0.72);
      --text-muted: rgba(${textColorDark}, 0.56);
      --readable-text: 255, 255, 255;
      --readable-text-shadow: 0 2px 2px rgba(0, 0, 0, 0.85), 0 8px 24px rgba(0, 0, 0, 0.65), 0 0 2px rgba(0, 0, 0, 0.9);

      --glass-bg: rgba(${glassBgDark}, ${glassOpacity});
      --glass-bg-weak: rgba(${glassBgDark}, ${weakDark});
      --glass-bg-strong: rgba(${glassBgDark}, ${strongDark});
      --glass-border: rgba(${glassBorderDark}, ${darkBorderOpacity});
    }

    body {
      font-family: var(--font-main), sans-serif;
      color: rgb(var(--readable-text));
      text-shadow: var(--readable-text-shadow);
    }

    body :where(h1, h2, h3, h4, h5, h6, p, span, div, a, li, label, th, td, small, strong, em, b, i) {
      color: rgb(var(--readable-text)) !important;
      text-shadow: var(--readable-text-shadow) !important;
    }

    body :where(input, textarea, select, button) {
      color: rgb(var(--readable-text)) !important;
      text-shadow: var(--readable-text-shadow) !important;
    }

    body :where(input, textarea)::placeholder {
      color: rgba(var(--readable-text), 0.7) !important;
      text-shadow: none !important;
    }

    .title-text { color: rgb(var(--text-color)); }
    .muted { color: rgba(var(--text-color), 0.62); }

    .glass {
      border-radius: var(--radius);
      background: var(--glass-bg);
      border: var(--border-width) solid var(--glass-border);
      box-shadow: 0 10px 40px rgba(0, 0, 0, var(--shadow-opacity));
      backdrop-filter: blur(var(--blur)) saturate(var(--saturate));
      -webkit-backdrop-filter: blur(var(--blur)) saturate(var(--saturate));
      transition: background var(--transition-speed), border var(--transition-speed), backdrop-filter var(--transition-speed);
    }

    .btn {
      transition: all var(--transition-speed) cubic-bezier(0.4, 0, 0.2, 1);
    }

    .btn:hover { transform: scale(var(--hover-scale)); }

    .wallpaper-container {
      position: fixed;
      inset: -100px;
      z-index: 0;
      pointer-events: none;
    }

    ${settings.cbCss || ''}

    ${settings.customCSS || ''}
  `.trim();

    const styleId = 'texa-theme-settings';
    let styleEl = document.getElementById(styleId) as HTMLStyleElement | null;
    if (!styleEl) {
        styleEl = document.createElement('style');
        styleEl.id = styleId;
        document.head.appendChild(styleEl);
    }
    styleEl.textContent = css;
};

// Export for compatibility
export const getDefaultThemeSettings = (): ThemeSettings => DEFAULT_THEME_SETTINGS;
export const applyTheme = applyThemeSettings;
