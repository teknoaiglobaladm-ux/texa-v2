
import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar';
import Marketplace from './components/Marketplace';
import AdminDashboard from './components/AdminDashboard';
import UserProfile from './components/UserProfile';
import Login from './components/Login';
import Hero from './components/Hero';
import SplashCursor from './components/SplashCursor';
import ColorBends from './components/ColorBends';
import ToolIframePage from './components/ToolIframePage';
import Footer from './components/Footer';
import PaymentPage from './pages/PaymentPage';
import { onAuthChange, logOut, TexaUser } from './services/firebase';
import { PopupProvider, usePopup } from './services/popupContext';
import { ThemeProvider } from './services/ThemeContext';
import Dock, { DockItemData } from './components/Dock';
import { subscribeToDockItems, DockItem } from './services/supabaseDockService';
import toketHtml from './tambahan/toket.txt?raw';
import { applyTheme as applyThemeSettings, getDefaultThemeSettings, subscribeToThemeSettings, ThemeSettings } from './services/supabaseThemeService';

const DEFAULT_THEME_SETTINGS = getDefaultThemeSettings();

// Inner component that has access to useLocation
const AppContent: React.FC<{
  user: TexaUser | null;
  onLogin: (userData: TexaUser) => void;
  onLogout: () => void;
}> = ({ user, onLogin, onLogout }) => {
  const location = useLocation();
  const { isAnyPopupOpen } = usePopup();
  const [dockItems, setDockItems] = React.useState<DockItemData[]>([]);
  const [themeSettings, setThemeSettings] = useState<ThemeSettings>(DEFAULT_THEME_SETTINGS);
  const [previewThemeSettings, setPreviewThemeSettings] = useState<ThemeSettings | null>(null);
  const [scrollY, setScrollY] = useState(0);
  const [coarsePointer, setCoarsePointer] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [smallScreen, setSmallScreen] = useState(false);

  // Subscribe to dock items from Firestore
  React.useEffect(() => {
    const unsubscribe = subscribeToDockItems((items: DockItem[]) => {
      const formattedItems: DockItemData[] = items.map(item => ({
        icon: item.icon,
        label: item.label,
        onClick: () => {
          if (item.actionType === 'route') {
            window.location.hash = item.actionValue;
          } else {
            window.open(item.actionValue, '_blank');
          }
        }
      }));
      setDockItems(formattedItems);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToThemeSettings((settings) => {
      setThemeSettings(settings);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const handler = (event: Event) => {
      const e = event as CustomEvent;
      const detail = e?.detail;
      if (detail && typeof detail === 'object') setPreviewThemeSettings(detail as ThemeSettings);
      else setPreviewThemeSettings(null);
    };
    window.addEventListener('texa-theme-preview', handler as EventListener);
    return () => window.removeEventListener('texa-theme-preview', handler as EventListener);
  }, []);

  useEffect(() => {
    const coarseMq = window.matchMedia?.('(pointer: coarse)');
    const reduceMq = window.matchMedia?.('(prefers-reduced-motion: reduce)');

    const sync = () => {
      setCoarsePointer(!!coarseMq?.matches);
      setReducedMotion(!!reduceMq?.matches);
      setSmallScreen(window.innerWidth < 768);
    };

    sync();

    const onResize = () => sync();
    window.addEventListener('resize', onResize, { passive: true });

    const coarseHandler = () => sync();
    const reduceHandler = () => sync();
    coarseMq?.addEventListener?.('change', coarseHandler);
    reduceMq?.addEventListener?.('change', reduceHandler);

    return () => {
      window.removeEventListener('resize', onResize);
      coarseMq?.removeEventListener?.('change', coarseHandler);
      reduceMq?.removeEventListener?.('change', reduceHandler);
    };
  }, []);

  const disableHeavyEffects = coarsePointer || reducedMotion || smallScreen;

  // Check if current route should hide header/footer
  const isAdminPage = location.pathname === '/admin';
  const isLoginPage = location.pathname === '/login';
  const isToketPage = location.pathname === '/toket';
  const isToolIframePage = location.pathname.startsWith('/tool/');
  const hideHeaderFooter = isAdminPage || isLoginPage || isToketPage || isToolIframePage;

  useEffect(() => {
    if (!isAdminPage && previewThemeSettings) setPreviewThemeSettings(null);
  }, [isAdminPage, previewThemeSettings]);

  const activeThemeSettings = isAdminPage && previewThemeSettings ? previewThemeSettings : themeSettings;

  useEffect(() => {
    applyThemeSettings(activeThemeSettings);
  }, [activeThemeSettings]);

  useEffect(() => {
    const parallaxSpeed = activeThemeSettings.parallaxSpeed ?? 0;
    if (disableHeavyEffects || !parallaxSpeed) {
      setScrollY(0);
      return;
    }

    let ticking = false;
    const handleScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        setScrollY(window.scrollY);
        ticking = false;
      });
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, [disableHeavyEffects, activeThemeSettings.parallaxSpeed]);

  const accentHex = React.useMemo(() => {
    const parts = (activeThemeSettings.accentColor || '')
      .split(',')
      .map((value) => Number.parseInt(value.trim(), 10))
      .filter((value) => Number.isFinite(value));
    if (parts.length < 3) return '#7c3aed';
    const [r, g, b] = parts;
    const toHex = (n: number) => Math.max(0, Math.min(255, n)).toString(16).padStart(2, '0');
    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  }, [activeThemeSettings.accentColor]);

  const colorBendsColors = React.useMemo(() => {
    const raw = Array.isArray(activeThemeSettings.cbColors) ? activeThemeSettings.cbColors : [];
    return raw.length ? raw : [accentHex, '#FF9FFC', '#7cff67'];
  }, [accentHex, activeThemeSettings.cbColors]);

  // Hide header/footer when any popup is open
  const shouldHideNavigation = hideHeaderFooter || isAnyPopupOpen;

  const renderColorBends = activeThemeSettings.useColorBends && !disableHeavyEffects;
  const effectiveBgBlur = disableHeavyEffects ? Math.min(activeThemeSettings.bgBlur ?? 0, 8) : (activeThemeSettings.bgBlur ?? 0);
  const effectiveParallax = disableHeavyEffects ? 0 : (activeThemeSettings.parallaxSpeed ?? 0);

  return (
    <div className="min-h-screen flex flex-col relative">
      <div className="wallpaper-container">
        <div
          className="w-full h-full"
          style={{
            transform: `translate3d(0, ${scrollY * effectiveParallax}px, 0)`,
            filter: `blur(${effectiveBgBlur}px)`,
            transition: 'filter 0.5s ease'
          }}
        >
          {renderColorBends ? (
            <ColorBends
              rotation={activeThemeSettings.cbRotation}
              speed={activeThemeSettings.cbSpeed}
              colors={colorBendsColors}
              transparent={activeThemeSettings.cbTransparent}
              autoRotate={activeThemeSettings.cbAutoRotate}
              scale={activeThemeSettings.cbScale}
              frequency={activeThemeSettings.cbFreq}
              warpStrength={activeThemeSettings.cbWarp}
              mouseInfluence={activeThemeSettings.cbMouseInfluence}
              parallax={activeThemeSettings.cbParallax}
              noise={activeThemeSettings.cbNoise}
            />
          ) : (
            <div className="w-full h-full bg-cover bg-center" style={{ backgroundImage: `url('${activeThemeSettings.bgUrl}')` }} />
          )}
        </div>
      </div>
      <div className="fixed inset-0 bg-gradient-to-b from-black/40 via-transparent to-black/80 pointer-events-none z-[1]" />
      <SplashCursor />

      {/* Conditionally render Navbar - hidden on admin/login pages and when popup is open */}
      <div
        className={`transition-all duration-300 ease-in-out ${shouldHideNavigation
          ? 'opacity-0 pointer-events-none h-0 overflow-hidden'
          : 'opacity-100'
          }`}
      >
        {!hideHeaderFooter && <Navbar user={user} onLogout={onLogout} />}
      </div>

      <main className={`flex-grow container mx-auto px-4 relative z-10 ${hideHeaderFooter ? 'py-4' : 'py-8'}`}>
        <Routes>
          <Route path="/" element={
            <>
              {!user && <Hero />}
              <Marketplace user={user} />
            </>
          } />

          <Route path="/login" element={
            user ? <Navigate to="/" /> : <Login onLogin={onLogin} />
          } />

          <Route path="/profile" element={
            user ? <UserProfile user={user} onLogout={onLogout} /> : <Navigate to="/login" />
          } />

          <Route path="/admin" element={
            user?.role === 'ADMIN' ? (
              <AdminDashboard />
            ) : (
              user ? (
                <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
                  <div className="text-6xl mb-4">🚫</div>
                  <h1 className="text-2xl font-bold text-white mb-2">Akses Ditolak</h1>
                  <p className="text-slate-400 mb-6">
                    Anda login sebagai <strong>{user.email}</strong>, namun akun ini tidak memiliki akses Admin.
                  </p>
                  <a href="/" className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold transition-all">
                    Kembali ke Marketplace
                  </a>
                </div>
              ) : (
                <Navigate to="/" />
              )
            )
          } />

          <Route path="/toket" element={
            <div className="w-full">
              <iframe title="Toket" srcDoc={toketHtml} className="w-full h-[92vh] rounded-2xl border border-white/10 bg-white" />
            </div>
          } />

          <Route path="/tool/:toolId" element={<ToolIframePage user={user} />} />

          <Route path="/payment" element={<PaymentPage />} />
        </Routes>
      </main>

      {/* Conditionally render Footer - hidden on admin/login pages and when popup is open */}
      <div
        className={`transition-all duration-300 ease-in-out ${shouldHideNavigation
          ? 'opacity-0 pointer-events-none h-0 overflow-hidden'
          : 'opacity-100'
          }`}
      >
        {!hideHeaderFooter && <Footer />}
      </div>

      {/* Floating Dock - hidden on admin/login pages */}
      {!hideHeaderFooter && dockItems.length > 0 && <Dock items={dockItems} />}
    </div>
  );
};

const App: React.FC = () => {
  const [user, setUser] = useState<TexaUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Listen to Firebase Auth state changes with error handling
  useEffect(() => {
    let unsubscribe: (() => void) | undefined;

    const initAuth = async () => {
      try {
        unsubscribe = onAuthChange(async (texaUser) => {
          try {
            setUser(texaUser);
            setLoading(false);

            if (texaUser) {
              // Sync with extension
              const { auth } = await import('./services/firebase');
              const idToken = auth.currentUser ? await auth.currentUser.getIdToken() : null;

              // Save to localStorage for extension to read directly
              if (idToken) {
                window.localStorage.setItem('texa_id_token', idToken);
                window.localStorage.setItem('texa_user_email', texaUser.email || '');
                window.localStorage.setItem('texa_user_role', texaUser.role || '');
                window.localStorage.setItem('texa_user_name', texaUser.name || '');
                window.localStorage.setItem('texa_subscription_end', texaUser.subscriptionEnd || '');
                window.localStorage.setItem('texa_current_user', JSON.stringify(texaUser));
              }

              // Send complete user profile to extension via postMessage
              window.postMessage({
                source: 'TEXA_DASHBOARD',
                type: 'TEXA_LOGIN_SYNC',
                origin: window.location.origin,
                idToken: idToken,
                user: {
                  id: texaUser.id,
                  email: texaUser.email,
                  name: texaUser.name,
                  role: texaUser.role,
                  subscriptionEnd: texaUser.subscriptionEnd,
                  isActive: texaUser.isActive,
                  photoURL: texaUser.photoURL,
                  createdAt: texaUser.createdAt,
                  lastLogin: texaUser.lastLogin
                }
              }, window.location.origin);
            }
          } catch (error) {
            console.error('Auth sync error (continuing without auth):', error);
            setLoading(false);
          }
        });
      } catch (error) {
        console.error('Firebase Auth init error (continuing without auth):', error);
        setUser(null);
        setLoading(false);
      }
    };

    // Set timeout to ensure app loads even if Firebase fails
    const timeoutId = setTimeout(() => {
      if (loading) {
        console.warn('Firebase taking too long, loading app without auth');
        setLoading(false);
      }
    }, 5000);

    initAuth();

    // Cleanup subscription
    return () => {
      clearTimeout(timeoutId);
      if (unsubscribe) unsubscribe();
    };
  }, []);

  const handleLogin = (userData: TexaUser) => {
    setUser(userData);
  };

  const handleLogout = async () => {
    try {
      await logOut();
      setUser(null);

      // Clear localStorage
      window.localStorage.removeItem('texa_id_token');
      window.localStorage.removeItem('texa_user_email');
      window.localStorage.removeItem('texa_user_role');
      window.localStorage.removeItem('texa_user_name');
      window.localStorage.removeItem('texa_subscription_end');
      window.localStorage.removeItem('texa_current_user');

      // Notify extension about logout
      window.postMessage({
        source: 'TEXA_DASHBOARD',
        type: 'TEXA_LOGOUT'
      }, window.location.origin);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  // Loading Screen
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#020617]">
        <div className="text-center">
          <div className="w-16 h-16 premium-gradient rounded-2xl mx-auto mb-4 flex items-center justify-center animate-pulse">
            <span className="text-white text-2xl font-black">T</span>
          </div>
          <div className="flex items-center justify-center gap-2">
            <div className="w-2 h-2 bg-indigo-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
            <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
            <div className="w-2 h-2 bg-pink-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
          </div>
          <p className="text-slate-500 text-sm mt-4">Memuat TEXA-Ai...</p>
        </div>
      </div>
    );
  }

  return (
    <ThemeProvider>
      <Router>
        <PopupProvider>
          <AppContent user={user} onLogin={handleLogin} onLogout={handleLogout} />
        </PopupProvider>
      </Router>
    </ThemeProvider>
  );
};

export default App;
