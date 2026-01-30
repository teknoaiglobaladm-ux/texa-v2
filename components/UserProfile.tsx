
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { TexaUser } from '../services/supabaseAuthService';

interface UserProfileProps {
  user: TexaUser;
  onLogout: () => void;
}

const UserProfile: React.FC<UserProfileProps> = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleUpgrade = () => {
    // Navigate to marketplace where subscription packages are shown
    navigate('/');
  };

  const handleLogout = () => {
    onLogout();
    // Navigate to home after logout
    navigate('/');
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Tidak ada';
    return new Date(dateString).toLocaleDateString('id-ID', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });
  };

  return (
    <div className="max-w-5xl mx-auto py-8 md:py-12">
      <div className="glass rounded-[28px] sm:rounded-[34px] md:rounded-[40px] p-5 sm:p-7 md:p-10 border border-white/10 mb-6 md:mb-10 overflow-hidden relative shadow-2xl">
        <div className="absolute top-0 right-0 w-80 h-80 bg-indigo-600/10 blur-[100px] -mr-40 -mt-40"></div>

        <div className="flex flex-col md:flex-row items-center gap-6 md:gap-10 relative z-10">
          {user.photoURL ? (
            <img
              src={user.photoURL}
              alt={user.name}
              className="w-24 h-24 sm:w-28 sm:h-28 md:w-32 md:h-32 rounded-3xl object-cover shadow-2xl rotate-3 border-4 border-indigo-500/30"
            />
          ) : (
            <div className="w-24 h-24 sm:w-28 sm:h-28 md:w-32 md:h-32 rounded-3xl premium-gradient flex items-center justify-center text-4xl sm:text-5xl font-black shadow-2xl rotate-3">
              {user.name[0].toUpperCase()}
            </div>
          )}

          <div className="text-center md:text-left">
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-black mb-2 tracking-tight">{user.name}</h2>
            <p className="text-slate-400 font-medium mb-5 md:mb-6 break-all">{user.email}</p>
            <div className="flex flex-wrap justify-center md:justify-start gap-4">
              <span className={`px-5 py-2 border rounded-full text-xs font-black uppercase tracking-widest ${user.role === 'ADMIN'
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                }`}>
                {user.role === 'ADMIN' ? 'Administrator' : 'Premium Member'}
              </span>
              <span className={`px-5 py-2 border rounded-full text-xs font-black uppercase tracking-widest ${user.subscriptionEnd
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : 'bg-red-500/10 text-red-400 border-red-500/20'
                }`}>
                {user.subscriptionEnd ? 'Status: Aktif' : 'Status: Free'}
              </span>
              {user.role === 'ADMIN' && (
                <Link
                  to="/admin"
                  className="px-5 py-2 rounded-full text-xs font-black uppercase tracking-widest bg-indigo-600 text-white hover:bg-indigo-500 transition-colors"
                >
                  Admin Dashboard
                </Link>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-10">
        <div className="glass rounded-[28px] sm:rounded-[32px] p-5 sm:p-7 md:p-10 border border-white/10 shadow-xl">
          <h3 className="text-xl sm:text-2xl font-black mb-6 md:mb-8 tracking-tight">Status Berlangganan</h3>
          {user.subscriptionEnd ? (
            <div className="space-y-6">
              <div className="p-6 bg-slate-900/50 rounded-2xl border border-white/5">
                <p className="text-xs text-slate-500 font-black uppercase tracking-widest mb-2">Paket Saat Ini</p>
                <p className="text-xl font-black text-white">Texa All-Access Premium</p>
              </div>
              <div className="p-6 bg-slate-900/50 rounded-2xl border border-white/5">
                <p className="text-xs text-slate-500 font-black uppercase tracking-widest mb-2">Masa Berlaku Sampai</p>
                <p className="text-xl font-black text-amber-400">{formatDate(user.subscriptionEnd)}</p>
              </div>
              <button className="w-full py-4 rounded-2xl border border-red-500/20 text-red-400 text-sm font-black hover:bg-red-500/10 transition-all uppercase tracking-widest">
                Berhenti Langganan
              </button>
            </div>
          ) : (
            <div className="text-center py-12">
              <p className="text-slate-400 mb-8 font-medium italic">Kamu belum memiliki paket aktif.</p>
              <button
                onClick={handleUpgrade}
                className="px-10 py-4 premium-gradient rounded-2xl font-black text-lg shadow-xl hover:scale-105 transition-transform"
              >
                Upgrade ke Premium
              </button>
            </div>
          )}
        </div>

        <div className="glass rounded-[28px] sm:rounded-[32px] p-5 sm:p-7 md:p-10 border border-white/10 shadow-xl">
          <h3 className="text-xl sm:text-2xl font-black mb-6 md:mb-8 tracking-tight">Informasi Akun</h3>
          <div className="space-y-4">
            <div className="p-5 bg-slate-900/50 border border-white/5 rounded-2xl">
              <p className="text-xs text-slate-500 font-black uppercase tracking-widest mb-2">User ID</p>
              <p className="text-sm font-mono text-slate-300 break-all">{user.id}</p>
            </div>
            <div className="p-5 bg-slate-900/50 border border-white/5 rounded-2xl">
              <p className="text-xs text-slate-500 font-black uppercase tracking-widest mb-2">Terdaftar Sejak</p>
              <p className="text-sm font-medium text-slate-300">{formatDate(user.createdAt || null)}</p>
            </div>
            <div className="p-5 bg-slate-900/50 border border-white/5 rounded-2xl">
              <p className="text-xs text-slate-500 font-black uppercase tracking-widest mb-2">Login Terakhir</p>
              <p className="text-sm font-medium text-slate-300">{formatDate(user.lastLogin || null)}</p>
            </div>
          </div>

          <div className="mt-8 p-5 bg-emerald-500/5 border border-emerald-500/10 rounded-2xl flex items-center justify-between">
            <div className="flex items-center gap-4">
              <span className="text-2xl">✅</span>
              <span className="text-sm font-black text-white">Akun Terverifikasi</span>
            </div>
            <span className="text-[10px] font-black text-emerald-400 bg-emerald-400/10 px-2 py-1 rounded">Supabase Auth</span>
          </div>

          <div className="mt-6">
            <button
              type="button"
              onClick={handleLogout}
              className="w-full py-4 rounded-2xl border border-red-500/20 text-red-400 text-sm font-black hover:bg-red-500/10 transition-all uppercase tracking-widest"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserProfile;
