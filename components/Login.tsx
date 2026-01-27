
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Prism from './Prism';
import {
  signIn,
  signUp,
  signInWithGoogle,
  TexaUser
} from '../services/supabaseAuthService';

interface LoginProps {
  onLogin: (user: TexaUser) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [authMethod, setAuthMethod] = useState<'email' | 'google' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const isCoarsePointer = typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches;
  const prefersReducedMotion = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const showPrism = !(isCoarsePointer || prefersReducedMotion);

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setAuthMethod('email');
    setError(null);

    try {
      if (isRegister) {
        // Sign Up
        if (!name.trim()) {
          throw new Error('Nama lengkap wajib diisi');
        }
        if (password.length < 6) {
          throw new Error('Password minimal 6 karakter');
        }
        const { user, error: signUpError } = await signUp(email, password, name);
        if (signUpError) throw new Error(signUpError);
        if (user) {
          onLogin(user);
          navigate('/', { replace: true });
        }
      } else {
        // Sign In
        const { user, error: signInError } = await signIn(email, password);
        if (signInError) throw new Error(signInError);
        if (user) {
          onLogin(user);
          navigate('/', { replace: true });
        }
      }
    } catch (err: any) {
      setError(err.message || 'Terjadi kesalahan');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setLoading(true);
    setAuthMethod('google');
    setError(null);

    try {
      const { error: googleError } = await signInWithGoogle();
      if (googleError) throw new Error(googleError);
      // Google OAuth will redirect, so we don't need to call onLogin here
    } catch (err: any) {
      setError(err.message || 'Gagal login dengan Google');
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
      {/* Dynamic Background Effect */}
      <div className="absolute inset-0 z-0">
        {showPrism ? (
          <Prism
            animationType="rotate"
            timeScale={0.5}
            height={3.5}
            baseWidth={5.5}
            scale={3.6}
            hueShift={0}
            colorFrequency={1}
            noise={0.5}
            glow={1}
          />
        ) : (
          <div className="absolute inset-0 premium-gradient opacity-30" />
        )}
        {/* Dark overlay to ensure contrast */}
        <div className="absolute inset-0 bg-black/40 backdrop-blur-sm"></div>
      </div>

      {/* Auth Card with 50% Semi-Transparent Blur */}
      <div className="relative z-10 w-full max-w-md">
        {/* Back to Home Link */}
        <a
          href="#/"
          className="flex items-center gap-2 mb-6 text-white/70 hover:text-white transition-colors w-fit group"
        >
          <span className="text-lg group-hover:-translate-x-1 transition-transform">←</span>
          <span className="text-sm font-medium">Kembali ke Beranda</span>
        </a>

        <div className="bg-white/10 backdrop-blur-[50px] rounded-[40px] p-8 md:p-10 border border-white/20 shadow-[0_25px_50px_-12px_rgba(0,0,0,0.5)] overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1.5 premium-gradient"></div>

          <div className="text-center mb-8">
            <div className="w-16 h-16 premium-gradient rounded-2xl mx-auto mb-4 flex items-center justify-center text-white text-3xl font-black shadow-xl">
              T
            </div>
            <h2 className="text-3xl font-[900] mb-2 tracking-tight text-white drop-shadow-md">
              {isRegister ? 'Buat Akun' : 'Selamat Datang'}
            </h2>
            <p className="text-slate-300 text-sm font-medium">
              {isRegister ? 'Mulai perjalanan AI kamu hari ini.' : 'Masuk untuk akses katalog premium.'}
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-6 p-4 bg-red-500/20 border border-red-500/30 rounded-xl text-red-300 text-sm text-center animate-pulse">
              ⚠️ {error}
            </div>
          )}

          {/* Tab Switcher */}
          <div className="flex bg-black/40 p-1 rounded-2xl mb-8 border border-white/10">
            <button
              onClick={() => { setIsRegister(false); setError(null); }}
              className={`flex-1 py-2.5 rounded-xl text-xs font-bold transition-all ${!isRegister ? 'bg-white/20 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Masuk
            </button>
            <button
              onClick={() => { setIsRegister(true); setError(null); }}
              className={`flex-1 py-2.5 rounded-xl text-xs font-bold transition-all ${isRegister ? 'bg-white/20 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Daftar
            </button>
          </div>

          {/* Google Auth Button */}
          <button
            onClick={handleGoogleLogin}
            disabled={loading}
            className="w-full py-4 px-6 bg-white text-black rounded-2xl font-black text-sm mb-6 flex items-center justify-center gap-3 hover:scale-[1.02] active:scale-[0.98] transition-all shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading && authMethod === 'google' ? (
              <div className="w-5 h-5 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <>
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05" />
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                </svg>
                <span>Lanjut dengan Google</span>
              </>
            )}
          </button>

          <div className="flex items-center gap-4 mb-6">
            <div className="h-[1px] flex-grow bg-white/20"></div>
            <span className="text-[10px] text-slate-300 uppercase font-black tracking-widest">Atau Email</span>
            <div className="h-[1px] flex-grow bg-white/20"></div>
          </div>

          <form className="space-y-4" onSubmit={handleEmailAuth}>
            {isRegister && (
              <div>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Nama Lengkap"
                  className="w-full px-5 py-3.5 bg-black/20 border border-white/10 rounded-xl focus:outline-none focus:border-indigo-400 transition-all font-medium text-sm text-white placeholder:text-slate-500"
                />
              </div>
            )}

            <div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Alamat Email"
                className="w-full px-5 py-3.5 bg-black/20 border border-white/10 rounded-xl focus:outline-none focus:border-indigo-400 transition-all font-medium text-sm text-white placeholder:text-slate-500"
              />
            </div>

            <div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Kata Sandi (min. 6 karakter)"
                minLength={6}
                className="w-full px-5 py-3.5 bg-black/20 border border-white/10 rounded-xl focus:outline-none focus:border-indigo-400 transition-all font-medium text-sm text-white placeholder:text-slate-500"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-4 rounded-2xl premium-gradient font-black text-base shadow-xl hover:brightness-110 active:scale-[0.98] transition-all flex items-center justify-center gap-3 mt-4 text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading && authMethod === 'email' ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              ) : isRegister ? 'Buat Akun ⚡' : 'Masuk ⚡'}
            </button>
          </form>

          <p className="mt-8 text-center text-xs text-slate-300 font-medium">
            {isRegister ? 'Sudah punya akun?' : 'Belum punya akun?'} {' '}
            <button
              onClick={() => { setIsRegister(!isRegister); setError(null); }}
              className="text-white font-black hover:underline"
            >
              {isRegister ? 'Masuk Saja' : 'Daftar Sekarang'}
            </button>
          </p>

          {/* Supabase Badge */}
          <div className="mt-6 flex items-center justify-center gap-2 text-[10px] text-slate-500">
            <svg className="w-4 h-4" viewBox="0 0 109 113" fill="currentColor">
              <path d="M63.7076 110.284C60.8481 113.885 55.0502 111.912 54.9813 107.314L53.9738 40.0627L99.1935 40.0627C107.384 40.0627 111.952 49.5228 106.859 55.9374L63.7076 110.284Z" />
              <path d="M45.317 2.07103C48.1765 -1.53037 53.9745 0.442937 54.0434 5.041L54.4849 72.2922H9.83113C1.64038 72.2922 -2.92775 62.8321 2.1655 56.4175L45.317 2.07103Z" />
            </svg>
            <span>Powered by Supabase</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
