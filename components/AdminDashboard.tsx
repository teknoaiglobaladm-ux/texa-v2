import React, { useState, useEffect, useRef } from 'react';
import { TexaUser } from '../services/supabaseAuthService';
import {
  subscribeToUsers,
  updateUser,
  deleteUser,
  toggleUserStatus,
  changeUserRole,
  createManualMember,
  createAuthMemberWithPassword,
  setMemberPassword,
  setUserSubscription,
  removeUserSubscription,
  subscribeToSubscriptionRecords,
  calculateTotalRevenue,
  getAdminStats,
  searchUsers,
  filterUsersByStatus,
  formatDate,
  getDaysRemaining,
  getSubscriptionStatus,
  testDatabasePermissions,
  AdminStats
} from '../services/adminService';
import CatalogManager from './CatalogManager';
import DockManager from './DockManager';
import FooterManager from './FooterManager';
import SubscriptionSettingsManager from './SubscriptionSettings';
import {
  subscribeToRevenueShareSettings,
  saveRevenueShareSettings,
  RevenueSharePerson,
  RevenueShareRole,
  formatIDR
} from '../services/supabaseSubscriptionService';
import {
  ExtensionSettings,
  DEFAULT_EXTENSION_SETTINGS,
  subscribeToExtensionSettings,
  saveExtensionSettings
} from '../services/extensionService';
import {
  ThemeSettings,
  DEFAULT_THEME_SETTINGS,
  subscribeToThemeSettings,
  saveThemeSettings,
  applyThemeSettings
} from '../services/supabaseThemeService';
import {
  DEFAULT_HEADER_SETTINGS,
  HeaderContactInfo,
  HeaderNavItem,
  HeaderSettings,
  saveHeaderSettings,
  subscribeToHeaderSettings
} from '../services/headerService';
import {
  DashboardContentSettings,
  DEFAULT_DASHBOARD_CONTENT,
  subscribeToDashboardContent,
  saveDashboardContentSettings
} from '../services/dashboardContentService';
import toketHtml from '../tambahan/toket.txt?raw';
import toketExtHtml from '../tambahan/toket-ext.txt?raw';

// Tab type
type AdminTab = 'members' | 'catalog' | 'subscription' | 'revenueShare' | 'extension' | 'theme' | 'header' | 'toket' | 'tokenVault' | 'dock' | 'footer' | 'dashboardContent';

const hexToRgb = (hex: string) => {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}`
    : '255, 255, 255';
};

const rgbToHex = (rgb: string) => {
  if (!rgb || typeof rgb !== 'string') return '#ffffff';
  const parts = rgb.split(',').map((value) => parseInt(value.trim(), 10));
  if (parts.length < 3) return '#ffffff';
  const [r, g, b] = parts;
  return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
};

const ColorPicker: React.FC<{
  label: string;
  value: string;
  onChange: (value: string) => void;
}> = ({ label, value, onChange }) => {
  const hex = rgbToHex(value);
  return (
    <div className="flex items-center justify-between mb-4">
      <label className="text-[10px] uppercase tracking-wider font-bold opacity-60">{label}</label>
      <div className="flex items-center gap-2 bg-white/5 p-1 rounded-lg border border-white/10">
        <input
          type="color"
          value={hex}
          onChange={(event) => onChange(hexToRgb(event.target.value))}
          className="w-7 h-7 rounded cursor-pointer bg-transparent border-none p-0"
        />
        <span className="text-[9px] font-mono opacity-80 uppercase w-14">{hex}</span>
      </div>
    </div>
  );
};

const AdminSlider: React.FC<{
  label: string;
  value: number;
  min: number;
  max: number;
  step?: number;
  suffix?: string;
  onChange: (value: number) => void;
}> = ({ label, value, min, max, step = 1, suffix = '', onChange }) => {
  return (
    <div className="space-y-2 mb-4">
      <div className="flex justify-between items-center text-[10px] uppercase font-bold opacity-60">
        <span>{label}</span>
        <span className="font-mono bg-white/10 px-1.5 rounded">
          {value}
          {suffix}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="w-full h-1 bg-white/20 rounded-lg appearance-none cursor-pointer accent-white"
      />
    </div>
  );
};

const AdminDashboard: React.FC = () => {
  // Current active tab
  const [activeTab, setActiveTab] = useState<AdminTab>('members');

  const [users, setUsers] = useState<TexaUser[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<TexaUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'expired' | 'admin' | 'member'>('all');
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [totalRevenue, setTotalRevenue] = useState(0);
  const [revenueSharePeople, setRevenueSharePeople] = useState<RevenueSharePerson[]>([]);
  const [selectedUser, setSelectedUser] = useState<TexaUser | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [modalType, setModalType] = useState<'subscription' | 'edit' | 'delete' | 'add' | 'password'>('edit');
  const [subscriptionDays, setSubscriptionDays] = useState(30);
  const [actionLoading, setActionLoading] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [manualEmail, setManualEmail] = useState('');
  const [manualName, setManualName] = useState('');
  const [manualRole, setManualRole] = useState<'ADMIN' | 'MEMBER'>('MEMBER');
  const [manualDays, setManualDays] = useState(30);
  const [manualIsActive, setManualIsActive] = useState(true);
  const [manualPassword, setManualPassword] = useState('');
  const [manualPasswordConfirm, setManualPasswordConfirm] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('');
  const [dbStatus, setDbStatus] = useState<{ supabase: string } | null>(null);
  const [extensionSettings, setExtensionSettings] = useState<ExtensionSettings>(DEFAULT_EXTENSION_SETTINGS);
  const [themeSettings, setThemeSettings] = useState<ThemeSettings>(DEFAULT_THEME_SETTINGS);
  const [themeSyncedSettings, setThemeSyncedSettings] = useState<ThemeSettings>(DEFAULT_THEME_SETTINGS);
  const [themeDirty, setThemeDirty] = useState(false);
  const [themeSaving, setThemeSaving] = useState(false);
  const themeDirtyRef = useRef(false);
  const [headerSettings, setHeaderSettings] = useState<HeaderSettings>(DEFAULT_HEADER_SETTINGS);
  const [headerSyncedSettings, setHeaderSyncedSettings] = useState<HeaderSettings>(DEFAULT_HEADER_SETTINGS);
  const [headerDirty, setHeaderDirty] = useState(false);
  const [headerSaving, setHeaderSaving] = useState(false);
  const headerDirtyRef = useRef(false);
  const [dashboardContent, setDashboardContent] = useState<DashboardContentSettings>(DEFAULT_DASHBOARD_CONTENT);
  const [dashboardContentSynced, setDashboardContentSynced] = useState<DashboardContentSettings>(DEFAULT_DASHBOARD_CONTENT);
  const [dashboardContentDirty, setDashboardContentDirty] = useState(false);
  const [dashboardContentSaving, setDashboardContentSaving] = useState(false);
  const dashboardContentDirtyRef = useRef(false);


  useEffect(() => {
    themeDirtyRef.current = themeDirty;
  }, [themeDirty]);

  useEffect(() => {
    headerDirtyRef.current = headerDirty;
  }, [headerDirty]);

  const updateThemeSettings = (patch: Partial<ThemeSettings>) => {
    setThemeDirty(true);
    setThemeSettings((prev) => ({ ...prev, ...patch }));
  };

  const updateHeaderSettings = (patch: Partial<HeaderSettings>) => {
    setHeaderDirty(true);
    setHeaderSettings((prev) => ({ ...prev, ...patch }));
  };

  const updateHeaderContact = (patch: Partial<HeaderContactInfo>) => {
    setHeaderDirty(true);
    setHeaderSettings((prev) => ({
      ...prev,
      contact: { ...(prev.contact || DEFAULT_HEADER_SETTINGS.contact), ...patch }
    }));
  };

  // Subscribe to users on mount with timeout fallback
  useEffect(() => {
    let loadingTimeout: ReturnType<typeof setTimeout> | null = null;

    // Timeout after 30 seconds to prevent infinite loading (increased from 10s)
    loadingTimeout = setTimeout(() => {
      if (loading) {
        console.warn('AdminDashboard: User data loading timeout, showing empty state');
        setLoading(false);
      }
    }, 30000);

    const unsubscribe = subscribeToUsers((fetchedUsers) => {
      if (loadingTimeout) clearTimeout(loadingTimeout);
      setUsers(fetchedUsers);
      setLoading(false);
    });

    return () => {
      if (loadingTimeout) clearTimeout(loadingTimeout);
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToSubscriptionRecords((records) => {
      setTotalRevenue(calculateTotalRevenue(records));
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToRevenueShareSettings((settings) => {
      setRevenueSharePeople(settings.people || []);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToExtensionSettings((settings) => {
      setExtensionSettings(settings);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToThemeSettings((settings) => {
      setThemeSyncedSettings(settings);
      if (!themeDirtyRef.current) setThemeSettings(settings);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeToHeaderSettings((settings) => {
      setHeaderSyncedSettings(settings);
      if (!headerDirtyRef.current) setHeaderSettings(settings);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (activeTab !== 'theme') return;
    applyThemeSettings(themeSettings);
    window.dispatchEvent(new CustomEvent('texa-theme-preview', { detail: themeSettings }));
    return () => {
      window.dispatchEvent(new CustomEvent('texa-theme-preview', { detail: null }));
      applyThemeSettings(themeSyncedSettings);
    };
  }, [activeTab, themeSettings, themeSyncedSettings]);

  useEffect(() => {
    setStats(getAdminStats(users, totalRevenue));
  }, [users, totalRevenue]);

  const updateHeaderNavItem = (id: string, patch: Partial<HeaderNavItem>) => {
    setHeaderDirty(true);
    setHeaderSettings((prev) => ({
      ...prev,
      navItems: (prev.navItems || []).map((item) => (item.id === id ? { ...item, ...patch } : item))
    }));
  };

  const addHeaderNavItem = () => {
    const id = `nav-${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
    setHeaderDirty(true);
    setHeaderSettings((prev) => ({
      ...prev,
      navItems: [
        ...(prev.navItems || []),
        {
          id,
          label: 'Menu Baru',
          actionType: 'route',
          actionValue: '',
          isActive: true
        }
      ]
    }));
  };

  const removeHeaderNavItem = (id: string) => {
    setHeaderDirty(true);
    setHeaderSettings((prev) => ({
      ...prev,
      navItems: (prev.navItems || []).filter((item) => item.id !== id)
    }));
  };

  const moveHeaderNavItem = (id: string, direction: -1 | 1) => {
    setHeaderDirty(true);
    setHeaderSettings((prev) => {
      const items = [...(prev.navItems || [])];
      const idx = items.findIndex((i) => i.id === id);
      if (idx === -1) return prev;
      const nextIdx = idx + direction;
      if (nextIdx < 0 || nextIdx >= items.length) return prev;
      const temp = items[idx];
      items[idx] = items[nextIdx];
      items[nextIdx] = temp;
      return { ...prev, navItems: items };
    });
  };

  const handleSaveHeaderSettings = async () => {
    setHeaderSaving(true);
    try {
      const success = await saveHeaderSettings(headerSettings, 'admin');
      if (success) {
        setHeaderSyncedSettings(headerSettings);
        setHeaderDirty(false);
        showToast('Pengaturan Header tersimpan', 'success');
      } else {
        showToast('Gagal menyimpan pengaturan Header', 'error');
      }
    } finally {
      setHeaderSaving(false);
    }
  };

  // Subscribe to dashboard content settings
  useEffect(() => {
    dashboardContentDirtyRef.current = dashboardContentDirty;
  }, [dashboardContentDirty]);

  useEffect(() => {
    const unsubscribe = subscribeToDashboardContent((settings) => {
      setDashboardContentSynced(settings);
      if (!dashboardContentDirtyRef.current) setDashboardContent(settings);
    });
    return () => unsubscribe();
  }, []);

  const updateDashboardContent = (patch: Partial<DashboardContentSettings>) => {
    setDashboardContentDirty(true);
    setDashboardContent((prev) => ({ ...prev, ...patch }));
  };

  const handleSaveDashboardContent = async () => {
    setDashboardContentSaving(true);
    try {
      const success = await saveDashboardContentSettings(dashboardContent, 'admin');
      if (success) {
        setDashboardContentSynced(dashboardContent);
        setDashboardContentDirty(false);
        showToast('Konten Dashboard tersimpan', 'success');
      } else {
        showToast('Gagal menyimpan konten Dashboard', 'error');
      }
    } finally {
      setDashboardContentSaving(false);
    }
  };

  const handleResetDashboardContent = () => {
    setDashboardContentDirty(true);
    setDashboardContent(DEFAULT_DASHBOARD_CONTENT);
  };


  // Filter users when search or filter changes
  useEffect(() => {
    let result = users;
    result = searchUsers(result, searchTerm);
    result = filterUsersByStatus(result, statusFilter);
    setFilteredUsers(result);
  }, [users, searchTerm, statusFilter]);

  // Show toast notification
  const showToast = (message: string, type: 'success' | 'error') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedUser(null);
    setNewPassword('');
    setNewPasswordConfirm('');
    setSubscriptionDays(30);
    setManualEmail('');
    setManualName('');
    setManualRole('MEMBER');
    setManualDays(30);
    setManualIsActive(true);
    setManualPassword('');
    setManualPasswordConfirm('');
  };

  const handleSaveThemeSettings = async () => {
    setThemeSaving(true);
    try {
      const success = await saveThemeSettings(themeSettings, 'admin');
      if (success) {
        applyThemeSettings(themeSettings);
        setThemeSyncedSettings(themeSettings);
        setThemeDirty(false);
        showToast('Tema berhasil disimpan', 'success');
      } else {
        showToast('Gagal menyimpan tema', 'error');
      }
    } catch (error: any) {
      showToast(error?.message || 'Gagal menyimpan tema', 'error');
    } finally {
      setThemeSaving(false);
    }
  };

  const handleResetThemeSettings = () => {
    setThemeDirty(true);
    setThemeSettings(DEFAULT_THEME_SETTINGS);
  };

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

  // Handle actions
  const handleToggleStatus = async (user: TexaUser) => {
    setActionLoading(true);
    try {
      const success = await withTimeout(
        toggleUserStatus(user.id, !user.isActive),
        15000,
        'Timeout: proses ubah status terlalu lama'
      );
      if (success) {
        showToast(`User ${user.isActive ? 'dinonaktifkan' : 'diaktifkan'}`, 'success');
      } else {
        showToast('Gagal mengubah status user', 'error');
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal mengubah status user', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleChangeRole = async (user: TexaUser) => {
    setActionLoading(true);
    try {
      const newRole = user.role === 'ADMIN' ? 'MEMBER' : 'ADMIN';
      const success = await withTimeout(
        changeUserRole(user.id, newRole),
        15000,
        'Timeout: proses ubah role terlalu lama'
      );
      if (success) {
        showToast(`Role diubah ke ${newRole}`, 'success');
      } else {
        showToast('Gagal mengubah role', 'error');
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal mengubah role', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const openPasswordModal = (user: TexaUser) => {
    setSelectedUser(user);
    setModalType('password');
    setNewPassword('');
    setNewPasswordConfirm('');
    setShowModal(true);
  };

  const handleSetSubscription = async () => {
    if (!selectedUser) return;
    setActionLoading(true);
    try {
      const success = await withTimeout(
        setUserSubscription(selectedUser.id, subscriptionDays, 'Premium', 0, selectedUser.email),
        20000,
        'Timeout: proses set subscription terlalu lama'
      );
      if (success) {
        showToast(`Subscription aktif untuk ${subscriptionDays} hari`, 'success');
        closeModal();
      } else {
        showToast('Gagal mengatur subscription', 'error');
        closeModal();
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal mengatur subscription', 'error');
      closeModal();
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemoveSubscription = async (user: TexaUser) => {
    setActionLoading(true);
    try {
      const success = await withTimeout(
        removeUserSubscription(user.id),
        20000,
        'Timeout: proses hapus subscription terlalu lama'
      );
      if (success) {
        showToast('Subscription dihapus', 'success');
      } else {
        showToast('Gagal menghapus subscription', 'error');
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal menghapus subscription', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteUser = async () => {
    if (!selectedUser) return;
    setActionLoading(true);
    try {
      const success = await withTimeout(
        deleteUser(selectedUser.id),
        20000,
        'Timeout: proses hapus user terlalu lama'
      );
      if (success) {
        showToast('User dihapus', 'success');
        closeModal();
      } else {
        showToast('Gagal menghapus user', 'error');
        closeModal();
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal menghapus user', 'error');
      closeModal();
    } finally {
      setActionLoading(false);
    }
  };

  const openModal = (user: TexaUser, type: 'subscription' | 'edit' | 'delete') => {
    setSelectedUser(user);
    setModalType(type);
    setShowModal(true);
  };

  const openAddModal = () => {
    setSelectedUser(null);
    setModalType('add');
    setManualEmail('');
    setManualName('');
    setManualRole('MEMBER');
    setManualDays(30);
    setManualIsActive(true);
    setManualPassword('');
    setManualPasswordConfirm('');
    setShowModal(true);
  };

  const revenueShareTotalPercent = revenueSharePeople.reduce((sum, p) => sum + (Number.isFinite(p.percent) ? p.percent : 0), 0);

  const addRevenueSharePerson = () => {
    setRevenueSharePeople((prev) => [
      ...prev,
      { id: `person-${Date.now()}-${Math.random().toString(36).slice(2)}`, name: '', role: 'KARYAWAN', percent: 0 }
    ]);
  };

  const removeRevenueSharePerson = (id: string) => {
    setRevenueSharePeople((prev) => prev.filter((p) => p.id !== id));
  };

  const updateRevenueSharePerson = (id: string, updates: Partial<RevenueSharePerson>) => {
    setRevenueSharePeople((prev) => prev.map((p) => (p.id === id ? { ...p, ...updates } : p)));
  };

  const handleSaveRevenueShare = async () => {
    setActionLoading(true);
    try {
      const success = await saveRevenueShareSettings({ people: revenueSharePeople });
      if (success) showToast('Bagi hasil tersimpan', 'success');
      else showToast('Gagal menyimpan bagi hasil', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateManualMember = async () => {
    setActionLoading(true);
    try {
      const hasPassword = manualPassword.trim().length > 0;
      if (hasPassword && manualPassword !== manualPasswordConfirm) {
        showToast('Konfirmasi password tidak sama', 'error');
        return;
      }

      if (hasPassword) {
        await createAuthMemberWithPassword({
          email: manualEmail,
          password: manualPassword,
          name: manualName,
          role: manualRole,
          isActive: manualIsActive,
          subscriptionDays: manualDays
        });
        showToast('Member login dibuat/diupdate', 'success');
        closeModal();
        return;
      }

      const result = await createManualMember({
        email: manualEmail,
        name: manualName,
        role: manualRole,
        isActive: manualIsActive,
        subscriptionDays: manualDays
      });

      if (result.success) {
        showToast(result.action === 'updated' ? 'Member diperbarui' : 'Member manual ditambahkan', 'success');
        closeModal();
      } else {
        showToast('Gagal menambah member manual', 'error');
        closeModal();
      }
    } catch (err: any) {
      showToast(err.message || 'Gagal menyimpan member', 'error');
      closeModal();
    } finally {
      setActionLoading(false);
    }
  };

  const handleSetMemberPassword = async () => {
    if (!selectedUser) return;
    if (newPassword !== newPasswordConfirm) {
      showToast('Konfirmasi password tidak sama', 'error');
      return;
    }
    setActionLoading(true);
    try {
      await withTimeout(
        setMemberPassword({ uid: selectedUser.id, password: newPassword }),
        15000,
        'Timeout: proses ubah password terlalu lama'
      );
      showToast('Password berhasil diubah', 'success');
      closeModal();
    } catch (err: any) {
      showToast(err.message || 'Gagal mengubah password', 'error');
      closeModal();
    } finally {
      setActionLoading(false);
    }
  };

  const handleTestDatabase = async () => {
    setActionLoading(true);
    try {
      const result = await withTimeout(
        testDatabasePermissions(),
        15000,
        'Timeout: test koneksi database terlalu lama'
      );
      setDbStatus({ supabase: result.supabase || 'OK' });
      if (result.supabase === 'OK') {
        showToast('Koneksi Supabase Normal', 'success');
      } else {
        showToast('Terjadi Masalah Koneksi Supabase', 'error');
      }
    } catch (err: any) {
      showToast(err?.message || 'Gagal test koneksi database', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  // Render status badge
  const renderStatusBadge = (user: TexaUser) => {
    const status = getSubscriptionStatus(user.subscriptionEnd || null);
    const daysLeft = getDaysRemaining(user.subscriptionEnd || null);

    if (status === 'active') {
      return (
        <div className="flex flex-col">
          <span className="px-2 py-1 text-[10px] font-bold rounded-full bg-emerald-500/20 text-emerald-400 uppercase">
            Aktif
          </span>
          <span className="text-[9px] text-emerald-400/70 mt-0.5">{daysLeft} hari lagi</span>
        </div>
      );
    } else if (status === 'expired') {
      return (
        <span className="px-2 py-1 text-[10px] font-bold rounded-full bg-red-500/20 text-red-400 uppercase">
          Expired
        </span>
      );
    }
    return (
      <span className="px-2 py-1 text-[10px] font-bold rounded-full bg-gray-500/20 text-gray-400 uppercase">
        Free
      </span>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-slate-400">Memuat data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto py-6">
      {/* Toast Notification */}
      {toast && (
        <div className={`fixed bottom-4 right-4 z-50 px-6 py-3 rounded-xl shadow-2xl font-bold text-sm flex items-center gap-2 animate-pulse ${toast.type === 'success' ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white'
          }`}>
          {toast.type === 'success' ? '✅' : '❌'} {toast.message}
        </div>
      )}

      {/* Mini Navigation Bar */}
      <div className="glass rounded-2xl border border-white/10 px-6 py-3 mb-6 flex items-center justify-between">
        <a href="#/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
          <div className="w-10 h-10 premium-gradient rounded-xl flex items-center justify-center">
            <span className="text-white font-black text-lg">T</span>
          </div>
          <div>
            <span className="font-black text-white text-lg">TEXA</span>
            <span className="font-black text-indigo-400 text-lg">-Ai</span>
          </div>
        </a>
        <div className="flex items-center gap-3">
          <a
            href="#/"
            className="px-4 py-2 rounded-xl text-sm font-bold text-slate-400 hover:text-white hover:bg-white/5 transition-all flex items-center gap-2"
          >
            ← Kembali ke Marketplace
          </a>
          <a
            href="#/profile"
            className="px-4 py-2 rounded-xl text-sm font-bold glass border border-white/10 text-white hover:border-indigo-500/50 transition-all"
          >
            👤 Profil
          </a>
        </div>
      </div>

      {/* Header */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight flex items-center gap-3">
            <span className="text-3xl">👑</span> Admin Dashboard
          </h1>
          <p className="text-slate-400 mt-1">Kelola seluruh member, subscription, dan katalog TEXA-Ai</p>
          <div className="flex gap-2 mt-2">
            <button onClick={handleTestDatabase} disabled={actionLoading} className="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded-lg text-slate-300">
              🛠️ Test Koneksi DB
            </button>
            {dbStatus && (
              <span className="text-xs flex gap-2">
                <span className={dbStatus.supabase === 'OK' ? 'text-emerald-400' : 'text-red-400'}>Supabase: {dbStatus.supabase}</span>
              </span>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 p-1.5 glass rounded-2xl border border-white/10 flex-wrap">
          <button
            onClick={() => setActiveTab('members')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'members'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            👥 Kelola Member
          </button>
          <button
            onClick={() => setActiveTab('catalog')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'catalog'
              ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white shadow-lg shadow-purple-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🛒 Katalog AI Premium
          </button>
          <button
            onClick={() => setActiveTab('subscription')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'subscription'
              ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-lg shadow-emerald-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            💳 Pengaturan Subscription
          </button>
          <button
            onClick={() => setActiveTab('revenueShare')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'revenueShare'
              ? 'bg-gradient-to-r from-amber-600 to-orange-600 text-white shadow-lg shadow-amber-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            💸 Bagi Hasil
          </button>
          <button
            onClick={() => setActiveTab('extension')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'extension'
              ? 'bg-gradient-to-r from-rose-600 to-pink-600 text-white shadow-lg shadow-rose-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🧩 Pengaturan Extension
          </button>
          <button
            onClick={() => setActiveTab('theme')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'theme'
              ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-lg shadow-indigo-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🎨 Pengaturan Tema
          </button>
          <button
            onClick={() => setActiveTab('toket')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'toket'
              ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🗝️ Toket
          </button>
          <button
            onClick={() => setActiveTab('tokenVault')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'tokenVault'
              ? 'bg-gradient-to-r from-violet-600 to-purple-600 text-white shadow-lg shadow-violet-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🔐 Token Vault
          </button>
          <button
            onClick={() => setActiveTab('dock')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'dock'
              ? 'bg-gradient-to-r from-yellow-600 to-orange-600 text-white shadow-lg shadow-yellow-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🎯 Kelola Dock
          </button>
          <button
            onClick={() => setActiveTab('footer')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'footer'
              ? 'bg-gradient-to-r from-sky-600 to-blue-600 text-white shadow-lg shadow-sky-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            📄 Kelola Footer
          </button>
          <button
            onClick={() => setActiveTab('header')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'header'
              ? 'bg-gradient-to-r from-blue-600 to-sky-600 text-white shadow-lg shadow-blue-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            🧭 Pengaturan Header
          </button>
          <button
            onClick={() => setActiveTab('dashboardContent')}
            className={`px-5 py-2.5 rounded-xl font-bold text-sm transition-all flex items-center gap-2 ${activeTab === 'dashboardContent'
              ? 'bg-gradient-to-r from-teal-600 to-emerald-600 text-white shadow-lg shadow-teal-500/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
          >
            📝 Konten Dashboard
          </button>
        </div>
      </div>

      {/* Render Active Tab Content */}
      {activeTab === 'footer' ? (
        <FooterManager showToast={showToast} />
      ) : activeTab === 'dashboardContent' ? (
        <div className="space-y-6">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">📝 Konten Dashboard</h3>
              <p className="text-slate-400 text-sm mt-1">
                Atur semua teks dan warna yang tampil di halaman depan katalog.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleResetDashboardContent}
                className="px-4 py-2 rounded-xl text-xs font-black glass border border-white/10 text-white hover:border-amber-500/50 transition-all"
              >
                🔄 Reset Default
              </button>
              <button
                onClick={handleSaveDashboardContent}
                disabled={dashboardContentSaving}
                className="px-5 py-2.5 rounded-xl text-sm font-black bg-teal-600 text-white hover:bg-teal-500 transition-colors disabled:opacity-50"
              >
                {dashboardContentSaving ? 'Menyimpan...' : '💾 Simpan Pengaturan'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Section Katalog - Text */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">📋 Teks Section Katalog</h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Judul Section</label>
                  <input
                    type="text"
                    value={dashboardContent.catalogTitle}
                    onChange={(e) => updateDashboardContent({ catalogTitle: e.target.value })}
                    placeholder="Katalog AI Premium"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Badge Text</label>
                  <input
                    type="text"
                    value={dashboardContent.catalogBadgeText}
                    onChange={(e) => updateDashboardContent({ catalogBadgeText: e.target.value })}
                    placeholder="{count} Tools"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">Gunakan {'{count}'} untuk placeholder jumlah tools</p>
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Subtitle</label>
                  <input
                    type="text"
                    value={dashboardContent.catalogSubtitle}
                    onChange={(e) => updateDashboardContent({ catalogSubtitle: e.target.value })}
                    placeholder="Aktifkan tool favoritmu dalam hitungan detik."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>

            {/* Section Katalog - Styling */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">🎨 Warna & Styling</h4>
              <div className="space-y-4">
                <ColorPicker
                  label="Warna Judul"
                  value={dashboardContent.catalogTitleColor || '255, 255, 255'}
                  onChange={(val) => updateDashboardContent({ catalogTitleColor: `rgb(${val})` })}
                />
                <ColorPicker
                  label="Warna Subtitle"
                  value={dashboardContent.catalogSubtitleColor || '148, 163, 184'}
                  onChange={(val) => updateDashboardContent({ catalogSubtitleColor: `rgb(${val})` })}
                />
                <ColorPicker
                  label="Badge Background"
                  value={dashboardContent.catalogBadgeBgColor || '99, 102, 241'}
                  onChange={(val) => updateDashboardContent({ catalogBadgeBgColor: `rgba(${val}, 0.2)` })}
                />
                <ColorPicker
                  label="Badge Text Color"
                  value={dashboardContent.catalogBadgeTextColor || '129, 140, 248'}
                  onChange={(val) => updateDashboardContent({ catalogBadgeTextColor: `rgb(${val})` })}
                />
                <p className="text-[10px] text-slate-500">Kosongkan warna untuk menggunakan default tema.</p>
              </div>
            </div>

            {/* Empty State */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">🔍 Empty State</h4>
              <p className="text-slate-400 text-xs mb-4">Tampilan ketika tidak ada tools yang ditemukan</p>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Emoji</label>
                  <input
                    type="text"
                    value={dashboardContent.emptyStateEmoji}
                    onChange={(e) => updateDashboardContent({ emptyStateEmoji: e.target.value })}
                    placeholder="🔍"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500 text-center text-2xl"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Judul</label>
                  <input
                    type="text"
                    value={dashboardContent.emptyStateTitle}
                    onChange={(e) => updateDashboardContent({ emptyStateTitle: e.target.value })}
                    placeholder="Tidak Ada Tools"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Subtitle</label>
                  <input
                    type="text"
                    value={dashboardContent.emptyStateSubtitle}
                    onChange={(e) => updateDashboardContent({ emptyStateSubtitle: e.target.value })}
                    placeholder="Coba pilih kategori lain atau reset filter."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Tombol Text</label>
                  <input
                    type="text"
                    value={dashboardContent.emptyStateButtonText}
                    onChange={(e) => updateDashboardContent({ emptyStateButtonText: e.target.value })}
                    placeholder="Reset Filter"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-teal-500 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>

            {/* Preview */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">👁️ Preview</h4>
              <div className="bg-black/30 rounded-xl p-4 border border-white/5">
                <h2
                  className="text-xl font-black mb-2 flex items-center gap-2"
                  style={{ color: dashboardContent.catalogTitleColor || '#ffffff' }}
                >
                  {dashboardContent.catalogTitle}
                  <span
                    className="px-2 py-0.5 text-[10px] font-bold rounded-full"
                    style={{
                      backgroundColor: dashboardContent.catalogBadgeBgColor || 'rgba(99, 102, 241, 0.2)',
                      color: dashboardContent.catalogBadgeTextColor || '#818cf8'
                    }}
                  >
                    {dashboardContent.catalogBadgeText.replace('{count}', '6')}
                  </span>
                </h2>
                <p
                  className="text-sm"
                  style={{ color: dashboardContent.catalogSubtitleColor || '#94a3b8' }}
                >
                  {dashboardContent.catalogSubtitle}
                </p>
              </div>
            </div>
          </div>
        </div>
      ) : activeTab === 'header' ? (
        <div className="space-y-6">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">🧭 Pengaturan Header</h3>
              <p className="text-slate-400 text-sm mt-1">
                Atur logo, brand, menu navigasi, dan info kontak di navbar.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={addHeaderNavItem}
                className="px-4 py-2 rounded-xl text-xs font-black glass border border-white/10 text-white hover:border-blue-500/50 transition-all"
              >
                ➕ Tambah Menu
              </button>
              <button
                onClick={handleSaveHeaderSettings}
                disabled={headerSaving}
                className="px-5 py-2.5 rounded-xl text-sm font-black bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
              >
                {headerSaving ? 'Menyimpan...' : '💾 Simpan Pengaturan'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">🏷️ Brand</h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Logo URL</label>
                  <input
                    type="url"
                    value={headerSettings.logoUrl || ''}
                    onChange={(e) => updateHeaderSettings({ logoUrl: e.target.value })}
                    placeholder="https://..."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Nama Brand</label>
                  <input
                    type="text"
                    value={headerSettings.brandName || ''}
                    onChange={(e) => updateHeaderSettings({ brandName: e.target.value })}
                    placeholder="TEXA"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Tagline</label>
                  <input
                    type="text"
                    value={headerSettings.tagline || ''}
                    onChange={(e) => updateHeaderSettings({ tagline: e.target.value })}
                    placeholder="AI Digital Store"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">📞 Kontak</h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Telepon</label>
                  <input
                    type="text"
                    value={headerSettings.contact?.phone || ''}
                    onChange={(e) => updateHeaderContact({ phone: e.target.value })}
                    placeholder="+62..."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Email</label>
                  <input
                    type="email"
                    value={headerSettings.contact?.email || ''}
                    onChange={(e) => updateHeaderContact({ email: e.target.value })}
                    placeholder="support@..."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Lokasi</label>
                  <input
                    type="text"
                    value={headerSettings.contact?.location || ''}
                    onChange={(e) => updateHeaderContact({ location: e.target.value })}
                    placeholder="Indonesia"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-blue-500 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="glass rounded-2xl border border-white/10 overflow-hidden">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
              <h3 className="font-bold text-lg text-white">Menu Navigasi</h3>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest">Realtime Settings</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-white/10 text-left">
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Aktif</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Label</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Tipe</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Nilai</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest text-right">Aksi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {(headerSettings.navItems || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-10 text-center text-slate-500">
                        Belum ada menu. Klik "Tambah Menu".
                      </td>
                    </tr>
                  ) : (
                    (headerSettings.navItems || []).map((item) => (
                      <tr key={item.id} className="hover:bg-white/5 transition-colors">
                        <td className="px-6 py-4">
                          <input
                            type="checkbox"
                            checked={item.isActive !== false}
                            onChange={(e) => updateHeaderNavItem(item.id, { isActive: e.target.checked })}
                            className="h-4 w-4 accent-blue-500"
                          />
                        </td>
                        <td className="px-6 py-4">
                          <input
                            value={item.label || ''}
                            onChange={(e) => updateHeaderNavItem(item.id, { label: e.target.value })}
                            className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                            placeholder="Label"
                          />
                        </td>
                        <td className="px-6 py-4">
                          <select
                            value={item.actionType || 'route'}
                            onChange={(e) => updateHeaderNavItem(item.id, { actionType: e.target.value as any })}
                            className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                          >
                            <option value="route">route</option>
                            <option value="url">url</option>
                          </select>
                        </td>
                        <td className="px-6 py-4">
                          <input
                            value={item.actionValue || ''}
                            onChange={(e) => updateHeaderNavItem(item.id, { actionValue: e.target.value })}
                            className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                            placeholder={item.actionType === 'url' ? 'https://...' : '/profile'}
                          />
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => moveHeaderNavItem(item.id, -1)}
                              className="px-3 py-2 rounded-xl text-xs font-black glass border border-white/10 text-slate-200 hover:border-white/25 transition-all"
                            >
                              ↑
                            </button>
                            <button
                              onClick={() => moveHeaderNavItem(item.id, 1)}
                              className="px-3 py-2 rounded-xl text-xs font-black glass border border-white/10 text-slate-200 hover:border-white/25 transition-all"
                            >
                              ↓
                            </button>
                            <button
                              onClick={() => removeHeaderNavItem(item.id)}
                              className="px-3 py-2 rounded-xl text-xs font-black bg-red-600/20 text-red-400 hover:bg-red-600/30 transition-colors"
                            >
                              🗑️
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : activeTab === 'dock' ? (
        <DockManager showToast={showToast} />
      ) : activeTab === 'catalog' ? (
        <CatalogManager showToast={showToast} />
      ) : activeTab === 'subscription' ? (
        <SubscriptionSettingsManager showToast={showToast} />
      ) : activeTab === 'revenueShare' ? (
        <div className="space-y-6">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">💸 Pengaturan Bagi Hasil</h3>
              <p className="text-slate-400 text-sm mt-1">
                Total pendapatan dihitung otomatis dari transaksi berstatus paid/active.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={addRevenueSharePerson}
                className="px-4 py-2 rounded-xl text-xs font-black glass border border-white/10 text-white hover:border-amber-500/50 transition-all"
              >
                ➕ Tambah Penerima
              </button>
              <button
                onClick={handleSaveRevenueShare}
                disabled={actionLoading}
                className="px-4 py-2 rounded-xl text-xs font-black bg-amber-600 text-white hover:bg-amber-500 transition-colors disabled:opacity-50"
              >
                {actionLoading ? 'Menyimpan...' : 'Simpan'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass rounded-2xl p-5 border border-purple-500/20 bg-purple-500/5">
              <p className="text-[10px] text-purple-400 uppercase font-black tracking-widest mb-1">Total Pendapatan</p>
              <p className="text-2xl font-black text-purple-400">{formatIDR(stats?.totalRevenue || 0)}</p>
            </div>
            <div className={`glass rounded-2xl p-5 border ${Math.abs(revenueShareTotalPercent - 100) < 0.0001 ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'}`}>
              <p className={`text-[10px] uppercase font-black tracking-widest mb-1 ${Math.abs(revenueShareTotalPercent - 100) < 0.0001 ? 'text-emerald-400' : 'text-red-400'}`}>
                Total Persen
              </p>
              <p className={`text-2xl font-black ${Math.abs(revenueShareTotalPercent - 100) < 0.0001 ? 'text-emerald-400' : 'text-red-400'}`}>
                {revenueShareTotalPercent}%
              </p>
            </div>
            <div className="glass rounded-2xl p-5 border border-white/10">
              <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mb-1">Catatan</p>
              <p className="text-xs text-slate-400">
                Jika total persen tidak 100%, nominal hasil akan mengikuti persen.
              </p>
            </div>
          </div>

          <div className="glass rounded-2xl border border-white/10 overflow-hidden">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
              <h3 className="font-bold text-lg">Daftar Penerima</h3>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest">Realtime Settings</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-white/10 text-left">
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Nama</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Role</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Persen</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Nominal</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest text-right">Aksi</th>
                  </tr>
                </thead>
                <tbody>
                  {revenueSharePeople.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                        Belum ada penerima. Klik "Tambah Penerima".
                      </td>
                    </tr>
                  ) : (
                    revenueSharePeople.map((p) => {
                      const revenue = stats?.totalRevenue || 0;
                      const amount = (revenue * (Number.isFinite(p.percent) ? p.percent : 0)) / 100;
                      return (
                        <tr key={p.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                          <td className="px-6 py-4">
                            <input
                              value={p.name}
                              onChange={(e) => updateRevenueSharePerson(p.id, { name: e.target.value })}
                              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                              placeholder="Nama penerima"
                            />
                          </td>
                          <td className="px-6 py-4">
                            <select
                              value={p.role}
                              onChange={(e) => updateRevenueSharePerson(p.id, { role: e.target.value as RevenueShareRole })}
                              className="w-full px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                            >
                              <option value="OWNER">OWNER</option>
                              <option value="ADMIN">ADMIN</option>
                              <option value="KARYAWAN">KARYAWAN</option>
                            </select>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-2">
                              <input
                                type="number"
                                min="0"
                                step="0.01"
                                value={p.percent}
                                onChange={(e) => updateRevenueSharePerson(p.id, { percent: Number(e.target.value) })}
                                className="w-28 px-3 py-2 bg-black/30 border border-white/10 rounded-xl text-white text-sm"
                              />
                              <span className="text-slate-400 text-sm">%</span>
                            </div>
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-300 font-bold">
                            {formatIDR(amount)}
                          </td>
                          <td className="px-6 py-4 text-right">
                            <button
                              onClick={() => removeRevenueSharePerson(p.id)}
                              className="px-3 py-2 rounded-xl text-xs font-black bg-red-600/20 text-red-400 hover:bg-red-600/30 transition-colors"
                            >
                              🗑️ Hapus
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : activeTab === 'extension' ? (
        <div className="space-y-6">
          {/* Header */}
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">🧩 Pengaturan Extension</h3>
              <p className="text-slate-400 text-sm mt-1">
                Atur link download, video tutorial, dan pesan popup untuk pengguna yang belum memasang extension.
              </p>
            </div>
            <button
              onClick={async () => {
                setActionLoading(true);
                try {
                  const success = await saveExtensionSettings(extensionSettings);
                  if (success) showToast('Pengaturan Extension tersimpan', 'success');
                  else showToast('Gagal menyimpan pengaturan', 'error');
                } finally {
                  setActionLoading(false);
                }
              }}
              disabled={actionLoading}
              className="px-5 py-2.5 rounded-xl text-sm font-black bg-rose-600 text-white hover:bg-rose-500 transition-colors disabled:opacity-50"
            >
              {actionLoading ? 'Menyimpan...' : '💾 Simpan Pengaturan'}
            </button>
          </div>

          {/* Settings Form */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Download Settings */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                📦 Link Download Extension
              </h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    URL Download *
                  </label>
                  <input
                    type="url"
                    value={extensionSettings.downloadUrl}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, downloadUrl: e.target.value })}
                    placeholder="https://drive.google.com/... atau link lainnya"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white placeholder:text-slate-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">Link untuk download file extension (ZIP)</p>
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    Teks Tombol Download
                  </label>
                  <input
                    type="text"
                    value={extensionSettings.downloadButtonText || ''}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, downloadButtonText: e.target.value })}
                    placeholder="📦 Download Extension"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white placeholder:text-slate-500"
                  />
                </div>
              </div>
            </div>

            {/* Video Tutorial Settings */}
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                🎬 Video Tutorial
              </h4>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    URL Video Tutorial *
                  </label>
                  <input
                    type="url"
                    value={extensionSettings.tutorialVideoUrl}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, tutorialVideoUrl: e.target.value })}
                    placeholder="https://youtube.com/watch?v=... atau embed URL"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white placeholder:text-slate-500"
                  />
                  <p className="text-[10px] text-slate-500 mt-1">Mendukung format: youtube.com/watch, youtu.be, shorts, embed</p>
                </div>
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    URL Artikel Tutorial (Opsional)
                  </label>
                  <input
                    type="url"
                    value={extensionSettings.tutorialArticleUrl || ''}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, tutorialArticleUrl: e.target.value })}
                    placeholder="https://blog.example.com/..."
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white placeholder:text-slate-500"
                  />
                </div>
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    id="showTutorialVideo"
                    checked={extensionSettings.showTutorialVideo ?? true}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, showTutorialVideo: e.target.checked })}
                    className="w-5 h-5 rounded bg-black/30 border border-white/10 text-rose-600 focus:ring-rose-500"
                  />
                  <label htmlFor="showTutorialVideo" className="text-sm text-slate-300">
                    Tampilkan video tutorial di popup
                  </label>
                </div>
              </div>
            </div>

            {/* Popup Content Settings */}
            <div className="glass rounded-2xl p-6 border border-white/10 lg:col-span-2">
              <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                💬 Konten Popup
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    Icon Popup
                  </label>
                  <input
                    type="text"
                    value={extensionSettings.popupIcon || ''}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, popupIcon: e.target.value })}
                    placeholder="🧩"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white text-2xl text-center"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    Judul Popup
                  </label>
                  <input
                    type="text"
                    value={extensionSettings.popupTitle || ''}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, popupTitle: e.target.value })}
                    placeholder="Extension Belum Terpasang"
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white"
                  />
                </div>
                <div className="md:col-span-3">
                  <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">
                    Deskripsi Popup
                  </label>
                  <textarea
                    value={extensionSettings.popupDescription || ''}
                    onChange={(e) => setExtensionSettings({ ...extensionSettings, popupDescription: e.target.value })}
                    placeholder="Untuk menggunakan tools ini, Anda perlu memasang TEXA-Ai Extension terlebih dahulu..."
                    rows={3}
                    className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-rose-500 text-white placeholder:text-slate-500 resize-none"
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Preview Section */}
          <div className="glass rounded-2xl p-6 border border-white/10">
            <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              👁️ Preview Popup
            </h4>
            <div className="bg-black/50 rounded-2xl p-6 border border-white/5">
              <div className="max-w-md mx-auto glass rounded-2xl overflow-hidden border border-white/10">
                {/* Preview Header */}
                <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 p-4">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-xl bg-white/20 flex items-center justify-center text-2xl">
                      {extensionSettings.popupIcon || '🧩'}
                    </div>
                    <div>
                      <h5 className="font-bold text-white text-sm">{extensionSettings.popupTitle || 'Extension Belum Terpasang'}</h5>
                      <p className="text-white/60 text-xs">Preview popup warning</p>
                    </div>
                  </div>
                </div>
                {/* Preview Content */}
                <div className="p-4">
                  <p className="text-slate-400 text-xs mb-3">{extensionSettings.popupDescription || 'Deskripsi popup akan muncul di sini...'}</p>
                  {extensionSettings.tutorialVideoUrl && extensionSettings.showTutorialVideo && (
                    <div className="bg-slate-800 rounded-lg h-20 flex items-center justify-center mb-3">
                      <span className="text-slate-500 text-xs">🎬 Video Tutorial</span>
                    </div>
                  )}
                  <button className="w-full py-2 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-xs font-bold">
                    {extensionSettings.downloadButtonText || '📦 Download Extension'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : activeTab === 'theme' ? (
        <div className="space-y-6">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">🎨 Pengaturan Tema</h3>
              <p className="text-slate-400 text-sm mt-1">
                Atur warna aksen, material glass, dan efek global untuk semua halaman.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleResetThemeSettings}
                className="px-4 py-2 rounded-xl text-xs font-black glass border border-white/10 text-white hover:border-indigo-500/50 transition-all"
              >
                ♻️ Reset Default
              </button>
              <button
                onClick={handleSaveThemeSettings}
                disabled={themeSaving}
                className="px-4 py-2 rounded-xl text-xs font-black bg-indigo-600 text-white hover:bg-indigo-500 transition-colors disabled:opacity-50"
              >
                {themeSaving ? 'Menyimpan...' : '💾 Simpan Tema'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Developer Tools</h4>
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-bold text-white/80">Active Shader Background</span>
                <button
                  onClick={() => updateThemeSettings({ useColorBends: !themeSettings.useColorBends })}
                  className={`w-10 h-5 rounded-full relative transition-colors ${themeSettings.useColorBends ? 'bg-purple-500' : 'bg-white/20'}`}
                >
                  <span className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${themeSettings.useColorBends ? 'left-6' : 'left-1'}`} />
                </button>
              </div>

              {themeSettings.useColorBends && (
                <div className="pt-4 border-t border-white/10 space-y-4">
                  <p className="text-[10px] opacity-50 uppercase tracking-widest font-bold">Shader Params</p>
                  <AdminSlider
                    label="Warp Strength"
                    value={themeSettings.cbWarp}
                    min={0}
                    max={5}
                    step={0.1}
                    onChange={(value) => updateThemeSettings({ cbWarp: value })}
                  />
                  <AdminSlider
                    label="Speed"
                    value={themeSettings.cbSpeed}
                    min={0}
                    max={2}
                    step={0.1}
                    onChange={(value) => updateThemeSettings({ cbSpeed: value })}
                  />
                  <AdminSlider
                    label="Frequency"
                    value={themeSettings.cbFreq}
                    min={0}
                    max={5}
                    step={0.1}
                    onChange={(value) => updateThemeSettings({ cbFreq: value })}
                  />
                  <AdminSlider
                    label="Rotation"
                    value={themeSettings.cbRotation}
                    min={0}
                    max={360}
                    step={1}
                    suffix="°"
                    onChange={(value) => updateThemeSettings({ cbRotation: value })}
                  />
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold opacity-60">Transparent</span>
                    <button
                      onClick={() => updateThemeSettings({ cbTransparent: !themeSettings.cbTransparent })}
                      className={`w-10 h-5 rounded-full relative transition-colors ${themeSettings.cbTransparent ? 'bg-purple-500' : 'bg-white/20'}`}
                    >
                      <span className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${themeSettings.cbTransparent ? 'left-6' : 'left-1'}`} />
                    </button>
                  </div>
                  <AdminSlider
                    label="Auto Rotate"
                    value={themeSettings.cbAutoRotate}
                    min={0}
                    max={180}
                    step={1}
                    suffix="°/s"
                    onChange={(value) => updateThemeSettings({ cbAutoRotate: value })}
                  />
                  <AdminSlider
                    label="Scale"
                    value={themeSettings.cbScale}
                    min={0.1}
                    max={4}
                    step={0.05}
                    onChange={(value) => updateThemeSettings({ cbScale: value })}
                  />
                  <AdminSlider
                    label="Mouse Influence"
                    value={themeSettings.cbMouseInfluence}
                    min={0}
                    max={5}
                    step={0.1}
                    onChange={(value) => updateThemeSettings({ cbMouseInfluence: value })}
                  />
                  <AdminSlider
                    label="Parallax"
                    value={themeSettings.cbParallax}
                    min={0}
                    max={2}
                    step={0.05}
                    onChange={(value) => updateThemeSettings({ cbParallax: value })}
                  />
                  <AdminSlider
                    label="Noise"
                    value={themeSettings.cbNoise}
                    min={0}
                    max={0.5}
                    step={0.01}
                    onChange={(value) => updateThemeSettings({ cbNoise: value })}
                  />
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-[10px] uppercase font-bold opacity-60">
                      <span>Colors</span>
                      <button
                        onClick={() =>
                          updateThemeSettings({
                            cbColors: [...(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : []), '#ffffff'].slice(0, 8)
                          })
                        }
                        className="px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 text-white/80 transition-colors"
                        type="button"
                      >
                        + Add
                      </button>
                    </div>
                    <div className="space-y-2">
                      {(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : []).map((hex, index) => {
                        const safeHex = /^#([0-9a-fA-F]{6})$/.test(hex) ? hex : '#000000';
                        return (
                          <div key={`${hex}-${index}`} className="flex items-center gap-2">
                            <input
                              type="color"
                              value={safeHex}
                              onChange={(event) => {
                                const next = [...(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : [])];
                                next[index] = event.target.value;
                                updateThemeSettings({ cbColors: next });
                              }}
                              className="w-7 h-7 rounded cursor-pointer bg-transparent border-none p-0"
                            />
                            <input
                              type="text"
                              value={hex}
                              onChange={(event) => {
                                const next = [...(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : [])];
                                next[index] = event.target.value;
                                updateThemeSettings({ cbColors: next });
                              }}
                              className="flex-1 bg-black/30 border border-white/10 rounded-lg px-2 py-1 text-xs font-mono text-white/80 outline-none focus:border-white/30"
                              placeholder="#rrggbb"
                            />
                            <button
                              onClick={() => {
                                const next = [...(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : [])];
                                next.splice(index, 1);
                                updateThemeSettings({ cbColors: next });
                              }}
                              className="px-2 py-1 rounded-lg bg-red-600/20 text-red-300 hover:bg-red-600/30 transition-colors"
                              type="button"
                            >
                              ✕
                            </button>
                          </div>
                        );
                      })}
                      {(Array.isArray(themeSettings.cbColors) ? themeSettings.cbColors : []).length === 0 && (
                        <div className="text-[10px] text-white/40">Kosong, akan fallback ke accent.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Environment</h4>
              {!themeSettings.useColorBends && (
                <div className="space-y-1 mb-4">
                  <label className="text-[10px] uppercase font-bold opacity-60">Background Image URL</label>
                  <input
                    type="text"
                    value={themeSettings.bgUrl}
                    onChange={(e) => updateThemeSettings({ bgUrl: e.target.value })}
                    className="w-full bg-white/5 border border-white/10 rounded-lg p-2 text-xs outline-none focus:border-white/30 text-white"
                  />
                </div>
              )}
              <div className="space-y-4">
                <AdminSlider
                  label="Background Blur"
                  value={themeSettings.bgBlur}
                  min={0}
                  max={100}
                  step={1}
                  suffix="px"
                  onChange={(value) => updateThemeSettings({ bgBlur: value })}
                />
                <AdminSlider
                  label="Parallax Speed"
                  value={themeSettings.parallaxSpeed}
                  min={0}
                  max={1}
                  step={0.05}
                  onChange={(value) => updateThemeSettings({ parallaxSpeed: value })}
                />
              </div>
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Warna</h4>
              <ColorPicker
                label="Accent Color"
                value={themeSettings.accentColor}
                onChange={(value) => updateThemeSettings({ accentColor: value })}
              />
              <ColorPicker
                label="Text Color (Light)"
                value={themeSettings.textColorLight}
                onChange={(value) => updateThemeSettings({ textColorLight: value })}
              />
              <ColorPicker
                label="Text Color (Dark)"
                value={themeSettings.textColorDark}
                onChange={(value) => updateThemeSettings({ textColorDark: value })}
              />
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Typography</h4>
              <div className="space-y-1">
                <label className="text-[10px] uppercase font-bold opacity-60">Font Family</label>
                <input
                  type="text"
                  value={themeSettings.fontFamily}
                  onChange={(e) => updateThemeSettings({ fontFamily: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-lg p-2 text-xs outline-none focus:border-white/30 text-white"
                />
              </div>
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Glass</h4>
              <ColorPicker
                label="Glass Base"
                value={themeSettings.glassBg}
                onChange={(value) => updateThemeSettings({ glassBg: value })}
              />
              <ColorPicker
                label="Glass Border"
                value={themeSettings.glassBorder}
                onChange={(value) => updateThemeSettings({ glassBorder: value })}
              />
              <AdminSlider
                label="Glass Opacity"
                value={themeSettings.glassOpacity}
                min={0}
                max={0.4}
                step={0.01}
                onChange={(value) => updateThemeSettings({ glassOpacity: value })}
              />
              <AdminSlider
                label="Glass Blur"
                value={themeSettings.blur}
                min={0}
                max={80}
                step={1}
                suffix="px"
                onChange={(value) => updateThemeSettings({ blur: value })}
              />
              <AdminSlider
                label="Corner Radius"
                value={themeSettings.radius}
                min={0}
                max={60}
                step={1}
                suffix="px"
                onChange={(value) => updateThemeSettings({ radius: value })}
              />
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Glass (Dark)</h4>
              <ColorPicker
                label="Glass Base (Dark)"
                value={themeSettings.glassBgDark}
                onChange={(value) => updateThemeSettings({ glassBgDark: value })}
              />
              <ColorPicker
                label="Glass Border (Dark)"
                value={themeSettings.glassBorderDark}
                onChange={(value) => updateThemeSettings({ glassBorderDark: value })}
              />
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10">
              <h4 className="text-lg font-bold text-white mb-4">Advanced</h4>
              <AdminSlider
                label="Border Width"
                value={themeSettings.borderWidth}
                min={0}
                max={6}
                step={1}
                suffix="px"
                onChange={(value) => updateThemeSettings({ borderWidth: value })}
              />
              <AdminSlider
                label="Saturate"
                value={themeSettings.saturate}
                min={0}
                max={300}
                step={10}
                suffix="%"
                onChange={(value) => updateThemeSettings({ saturate: value })}
              />
              <AdminSlider
                label="Shadow Opacity"
                value={themeSettings.shadowOpacity}
                min={0}
                max={1}
                step={0.05}
                onChange={(value) => updateThemeSettings({ shadowOpacity: value })}
              />
              <AdminSlider
                label="Transition Speed"
                value={themeSettings.transitionSpeed}
                min={0}
                max={1200}
                step={50}
                suffix="ms"
                onChange={(value) => updateThemeSettings({ transitionSpeed: value })}
              />
              <AdminSlider
                label="Hover Scale"
                value={themeSettings.hoverScale}
                min={1}
                max={1.2}
                step={0.01}
                onChange={(value) => updateThemeSettings({ hoverScale: value })}
              />
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10 lg:col-span-2">
              <h4 className="text-lg font-bold text-white mb-4">Custom CSS</h4>
              <textarea
                value={themeSettings.customCSS}
                onChange={(e) => updateThemeSettings({ customCSS: e.target.value })}
                className="w-full min-h-[140px] bg-black/30 border border-white/10 rounded-xl p-3 text-xs font-mono text-white/80 outline-none focus:border-white/30 resize-y"
                spellCheck={false}
              />
            </div>

            <div className="glass rounded-2xl p-6 border border-white/10 lg:col-span-2">
              <h4 className="text-lg font-bold text-white mb-4">ColorBends (Usage / Code / CSS)</h4>
              <div className="space-y-5">
                <div className="space-y-2">
                  <label className="block text-[10px] uppercase font-bold opacity-60">Usage</label>
                  <textarea
                    value={themeSettings.cbUsage || ''}
                    onChange={(e) => updateThemeSettings({ cbUsage: e.target.value })}
                    className="w-full min-h-[120px] bg-black/30 border border-white/10 rounded-xl p-3 text-xs font-mono text-white/80 outline-none focus:border-white/30 resize-y"
                    spellCheck={false}
                  />
                </div>
                <div className="space-y-2">
                  <label className="block text-[10px] uppercase font-bold opacity-60">Code</label>
                  <textarea
                    value={themeSettings.cbCode || ''}
                    onChange={(e) => updateThemeSettings({ cbCode: e.target.value })}
                    className="w-full min-h-[160px] bg-black/30 border border-white/10 rounded-xl p-3 text-xs font-mono text-white/80 outline-none focus:border-white/30 resize-y"
                    spellCheck={false}
                  />
                </div>
                <div className="space-y-2">
                  <label className="block text-[10px] uppercase font-bold opacity-60">CSS</label>
                  <textarea
                    value={themeSettings.cbCss || ''}
                    onChange={(e) => updateThemeSettings({ cbCss: e.target.value })}
                    className="w-full min-h-[160px] bg-black/30 border border-white/10 rounded-xl p-3 text-xs font-mono text-white/80 outline-none focus:border-white/30 resize-y"
                    spellCheck={false}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : activeTab === 'toket' ? (
        <div className="space-y-4">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">🗝️ Toket Vault</h3>
              <p className="text-slate-400 text-sm mt-1">Halaman HTML ini bisa dibuka publik via #/toket.</p>
            </div>
            <div className="flex items-center gap-3">
              <a
                href="#/toket"
                target="_blank"
                rel="noreferrer"
                className="px-4 py-2 rounded-xl text-xs font-black bg-cyan-600 text-white hover:bg-cyan-500 transition-colors"
              >
                🌐 Buka URL Publik
              </a>
            </div>
          </div>
          <div className="glass rounded-2xl border border-white/10 overflow-hidden">
            <iframe title="Toket" srcDoc={toketHtml} className="w-full h-[80vh] bg-white" />
          </div>
        </div>
      ) : activeTab === 'tokenVault' ? (
        <div className="space-y-4">
          <div className="glass rounded-2xl p-6 border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-black text-white flex items-center gap-2">🔐 Token Vault - Extension</h3>
              <p className="text-slate-400 text-sm mt-1">Supabase Token Storage untuk integrasi dengan Chrome Extension.</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="px-3 py-1.5 rounded-lg text-[10px] font-bold bg-violet-500/20 text-violet-400 border border-violet-500/30">
                🔗 Terintegrasi dengan Extension
              </span>
            </div>
          </div>
          <div className="glass rounded-2xl border border-white/10 overflow-hidden">
            <iframe title="Token Vault" srcDoc={toketExtHtml} className="w-full h-[80vh] bg-slate-950" />
          </div>
        </div>
      ) : (
        <>
          {/* Stats Cards */}
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-4 mb-8">
              <div className="glass rounded-2xl p-5 border border-white/10">
                <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mb-1">Total User</p>
                <p className="text-3xl font-black text-white">{stats.totalUsers}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-emerald-500/20 bg-emerald-500/5">
                <p className="text-[10px] text-emerald-400 uppercase font-black tracking-widest mb-1">Aktif</p>
                <p className="text-3xl font-black text-emerald-400">{stats.activeSubscriptions}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-red-500/20 bg-red-500/5">
                <p className="text-[10px] text-red-400 uppercase font-black tracking-widest mb-1">Expired</p>
                <p className="text-3xl font-black text-red-400">{stats.expiredSubscriptions}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-purple-500/20 bg-purple-500/5">
                <p className="text-[10px] text-purple-400 uppercase font-black tracking-widest mb-1">Pendapatan</p>
                <p className="text-xl font-black text-purple-400">{formatIDR(stats.totalRevenue)}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-amber-500/20 bg-amber-500/5">
                <p className="text-[10px] text-amber-400 uppercase font-black tracking-widest mb-1">Admin</p>
                <p className="text-3xl font-black text-amber-400">{stats.adminCount}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-indigo-500/20 bg-indigo-500/5">
                <p className="text-[10px] text-indigo-400 uppercase font-black tracking-widest mb-1">Member</p>
                <p className="text-3xl font-black text-indigo-400">{stats.totalUsers - stats.adminCount}</p>
              </div>
              <div className="glass rounded-2xl p-5 border border-purple-500/20 bg-purple-500/5">
                <p className="text-[10px] text-purple-400 uppercase font-black tracking-widest mb-1">Hari Ini</p>
                <p className="text-3xl font-black text-purple-400">+{stats.newUsersToday}</p>
              </div>
            </div>
          )}

          {/* Search and Filter */}
          <div className="glass rounded-2xl p-6 border border-white/10 mb-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-grow relative">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">🔍</span>
                <input
                  type="text"
                  placeholder="Cari berdasarkan nama, email, atau ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-black/30 border border-white/10 rounded-xl focus:outline-none focus:border-indigo-500 text-white placeholder:text-slate-500"
                />
              </div>
              <div className="flex gap-2 flex-wrap">
                {['all', 'active', 'expired', 'admin', 'member'].map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setStatusFilter(filter as any)}
                    className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${statusFilter === filter
                      ? 'bg-indigo-600 text-white'
                      : 'glass border border-white/10 text-slate-400 hover:text-white'
                      }`}
                  >
                    {filter === 'all' ? 'Semua' : filter}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Users Table */}
          <div className="glass rounded-2xl border border-white/10 overflow-hidden">
            <div className="px-6 py-4 border-b border-white/10 flex justify-between items-center">
              <h3 className="font-bold text-lg">Daftar Member ({filteredUsers.length})</h3>
              <div className="flex items-center gap-3">
                <button
                  onClick={openAddModal}
                  className="px-4 py-2 rounded-xl text-xs font-black bg-indigo-600 text-white hover:bg-indigo-500 transition-colors"
                >
                  ➕ Tambah Member Manual
                </button>
                <span className="text-[10px] text-slate-500 uppercase tracking-widest">Realtime Updates</span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-white/10 text-left">
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">User</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Role</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Status</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Subscription</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Terdaftar</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest">Login Terakhir</th>
                    <th className="px-6 py-4 text-[10px] text-slate-500 uppercase font-black tracking-widest text-right">Aksi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredUsers.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-12 text-center text-slate-500">
                        {searchTerm ? 'Tidak ada hasil pencarian' : 'Belum ada user terdaftar'}
                      </td>
                    </tr>
                  ) : (
                    filteredUsers.map((user) => (
                      <tr key={user.id} className="hover:bg-white/5 transition-colors group">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            {user.photoURL ? (
                              <img src={user.photoURL} alt={user.name} className="w-10 h-10 rounded-full object-cover" />
                            ) : (
                              <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-indigo-500 to-purple-500 flex items-center justify-center text-white font-bold">
                                {user.name[0].toUpperCase()}
                              </div>
                            )}
                            <div>
                              <p className="font-bold text-white">{user.name}</p>
                              <p className="text-xs text-slate-500">{user.email}</p>
                              <p className="text-[9px] text-slate-600 font-mono">{user.id.slice(0, 12)}...</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase ${user.role === 'ADMIN'
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'bg-indigo-500/20 text-indigo-400'
                            }`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${user.isActive
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : 'bg-red-500/20 text-red-400'
                            }`}>
                            {user.isActive ? '● Online' : '○ Offline'}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          {renderStatusBadge(user)}
                        </td>
                        <td className="px-6 py-4 text-xs text-slate-400">
                          {formatDate(user.createdAt)}
                        </td>
                        <td className="px-6 py-4 text-xs text-slate-400">
                          {formatDate(user.lastLogin)}
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-2 opacity-50 group-hover:opacity-100 transition-opacity">
                            {/* Subscription Button */}
                            <button
                              onClick={() => openModal(user, 'subscription')}
                              className="p-2 rounded-lg hover:bg-emerald-500/20 text-emerald-400 transition-colors"
                              title="Atur Subscription"
                            >
                              💎
                            </button>
                            {/* Toggle Status */}
                            <button
                              onClick={() => handleToggleStatus(user)}
                              disabled={actionLoading}
                              className={`p-2 rounded-lg transition-colors ${user.isActive ? 'hover:bg-red-500/20 text-red-400' : 'hover:bg-emerald-500/20 text-emerald-400'
                                }`}
                              title={user.isActive ? 'Nonaktifkan' : 'Aktifkan'}
                            >
                              {user.isActive ? '🔒' : '🔓'}
                            </button>
                            {/* Change Role */}
                            <button
                              onClick={() => handleChangeRole(user)}
                              disabled={actionLoading}
                              className="p-2 rounded-lg hover:bg-amber-500/20 text-amber-400 transition-colors"
                              title="Ubah Role"
                            >
                              👑
                            </button>
                            {/* Edit Password */}
                            <button
                              onClick={() => openPasswordModal(user)}
                              disabled={actionLoading}
                              className="p-2 rounded-lg hover:bg-indigo-500/20 text-indigo-400 transition-colors"
                              title="Edit Password"
                            >
                              🔑
                            </button>
                            {/* Delete */}
                            <button
                              onClick={() => openModal(user, 'delete')}
                              className="p-2 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors"
                              title="Hapus User"
                            >
                              🗑️
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Modal */}
          {showModal && (modalType === 'add' || selectedUser) && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
              <div className="glass rounded-3xl p-8 max-w-md w-full border border-white/20 shadow-2xl">
                {modalType === 'add' && (
                  <>
                    <h3 className="text-2xl font-black mb-2">➕ Tambah Member Manual</h3>
                    <p className="text-slate-400 text-sm mb-6">Buat/upgrade member berdasarkan email</p>

                    <div className="space-y-4">
                      <div>
                        <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Email *</label>
                        <input
                          type="email"
                          value={manualEmail}
                          onChange={(e) => setManualEmail(e.target.value)}
                          className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          placeholder="contoh@email.com"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Nama</label>
                        <input
                          type="text"
                          value={manualName}
                          onChange={(e) => setManualName(e.target.value)}
                          className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          placeholder="Nama lengkap (opsional)"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Password</label>
                          <input
                            type="password"
                            value={manualPassword}
                            onChange={(e) => setManualPassword(e.target.value)}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                            placeholder="Minimal 6 karakter"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Konfirmasi</label>
                          <input
                            type="password"
                            value={manualPasswordConfirm}
                            onChange={(e) => setManualPasswordConfirm(e.target.value)}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                            placeholder="Ulangi password"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Role</label>
                          <select
                            value={manualRole}
                            onChange={(e) => setManualRole(e.target.value as any)}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          >
                            <option value="MEMBER">MEMBER</option>
                            <option value="ADMIN">ADMIN</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Status</label>
                          <select
                            value={manualIsActive ? 'active' : 'inactive'}
                            onChange={(e) => setManualIsActive(e.target.value === 'active')}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          >
                            <option value="active">Aktif</option>
                            <option value="inactive">Nonaktif</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Durasi (Hari)</label>
                        <div className="flex gap-2 flex-wrap mb-4">
                          {[7, 30, 90, 180, 365].map((days) => (
                            <button
                              key={days}
                              onClick={() => setManualDays(days)}
                              className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${manualDays === days
                                ? 'bg-emerald-600 text-white'
                                : 'glass border border-white/10 text-slate-400 hover:text-white'
                                }`}
                            >
                              {days} Hari
                            </button>
                          ))}
                        </div>
                        <input
                          type="number"
                          value={manualDays}
                          onChange={(e) => setManualDays(parseInt(e.target.value) || 0)}
                          className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          placeholder="Custom hari..."
                        />
                      </div>

                      <div className="flex gap-3 mt-6">
                        <button
                          onClick={() => setShowModal(false)}
                          className="flex-1 py-3 rounded-xl glass border border-white/10 text-slate-400 font-bold hover:text-white transition-colors"
                        >
                          Batal
                        </button>
                        <button
                          onClick={handleCreateManualMember}
                          disabled={actionLoading}
                          className="flex-1 py-3 rounded-xl bg-indigo-600 text-white font-bold hover:bg-indigo-500 transition-colors disabled:opacity-50"
                        >
                          {actionLoading ? 'Menyimpan...' : 'Simpan'}
                        </button>
                      </div>
                    </div>
                  </>
                )}
                {modalType === 'password' && selectedUser && (
                  <>
                    <h3 className="text-2xl font-black mb-2">🔑 Edit Password</h3>
                    <p className="text-slate-400 text-sm mb-6">User: {selectedUser.email}</p>

                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Password Baru</label>
                          <input
                            type="password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                            placeholder="Minimal 6 karakter"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Konfirmasi</label>
                          <input
                            type="password"
                            value={newPasswordConfirm}
                            onChange={(e) => setNewPasswordConfirm(e.target.value)}
                            className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                            placeholder="Ulangi password"
                          />
                        </div>
                      </div>

                      <div className="flex gap-3 mt-6">
                        <button
                          onClick={() => setShowModal(false)}
                          className="flex-1 py-3 rounded-xl glass border border-white/10 text-slate-400 font-bold hover:text-white transition-colors"
                        >
                          Batal
                        </button>
                        <button
                          onClick={handleSetMemberPassword}
                          disabled={actionLoading}
                          className="flex-1 py-3 rounded-xl bg-indigo-600 text-white font-bold hover:bg-indigo-500 transition-colors disabled:opacity-50"
                        >
                          {actionLoading ? 'Menyimpan...' : 'Simpan'}
                        </button>
                      </div>
                    </div>
                  </>
                )}
                {modalType === 'subscription' && (
                  <>
                    <h3 className="text-2xl font-black mb-2">💎 Atur Subscription</h3>
                    <p className="text-slate-400 text-sm mb-6">User: {selectedUser.email}</p>

                    <div className="space-y-4">
                      <div>
                        <label className="block text-xs font-bold text-slate-400 mb-2 uppercase">Durasi (Hari)</label>
                        <div className="flex gap-2 flex-wrap mb-4">
                          {[7, 30, 90, 180, 365].map((days) => (
                            <button
                              key={days}
                              onClick={() => setSubscriptionDays(days)}
                              className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${subscriptionDays === days
                                ? 'bg-emerald-600 text-white'
                                : 'glass border border-white/10 text-slate-400 hover:text-white'
                                }`}
                            >
                              {days} Hari
                            </button>
                          ))}
                        </div>
                        <input
                          type="number"
                          value={subscriptionDays}
                          onChange={(e) => setSubscriptionDays(parseInt(e.target.value) || 0)}
                          className="w-full px-4 py-3 bg-black/30 border border-white/10 rounded-xl text-white"
                          placeholder="Custom hari..."
                        />
                      </div>

                      <div className="flex gap-3 mt-6">
                        <button
                          onClick={() => setShowModal(false)}
                          className="flex-1 py-3 rounded-xl glass border border-white/10 text-slate-400 font-bold hover:text-white transition-colors"
                        >
                          Batal
                        </button>
                        <button
                          onClick={handleSetSubscription}
                          disabled={actionLoading}
                          className="flex-1 py-3 rounded-xl bg-emerald-600 text-white font-bold hover:bg-emerald-500 transition-colors disabled:opacity-50"
                        >
                          {actionLoading ? 'Memproses...' : 'Aktifkan'}
                        </button>
                      </div>

                      {selectedUser.subscriptionEnd && (
                        <button
                          onClick={() => handleRemoveSubscription(selectedUser)}
                          disabled={actionLoading}
                          className="w-full py-3 rounded-xl border border-red-500/30 text-red-400 font-bold hover:bg-red-500/10 transition-colors"
                        >
                          Hapus Subscription
                        </button>
                      )}
                    </div>
                  </>
                )}

                {modalType === 'delete' && (
                  <>
                    <h3 className="text-2xl font-black mb-2 text-red-400">⚠️ Hapus User</h3>
                    <p className="text-slate-400 text-sm mb-6">
                      Apakah Anda yakin ingin menghapus user <strong>{selectedUser.email}</strong>?
                      Tindakan ini tidak dapat dibatalkan.
                    </p>

                    <div className="flex gap-3">
                      <button
                        onClick={() => setShowModal(false)}
                        className="flex-1 py-3 rounded-xl glass border border-white/10 text-slate-400 font-bold hover:text-white transition-colors"
                      >
                        Batal
                      </button>
                      <button
                        onClick={handleDeleteUser}
                        disabled={actionLoading}
                        className="flex-1 py-3 rounded-xl bg-red-600 text-white font-bold hover:bg-red-500 transition-colors disabled:opacity-50"
                      >
                        {actionLoading ? 'Menghapus...' : 'Hapus'}
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default AdminDashboard;
