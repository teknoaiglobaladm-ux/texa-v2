// Payment Page Component - Show payment methods and redirect to TokoPay
import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PAYMENT_METHODS, generateRefId, formatIDR } from '../services/tokopayService';
import { getSession } from '../services/supabaseAuthService';

interface PaymentMethod {
    code: string;
    name: string;
    icon: string;
    category: string;
}

const PaymentPage: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedMethod, setSelectedMethod] = useState<string>('QRISREALTIME');
    const [paymentResult, setPaymentResult] = useState<any>(null);
    const [session, setSession] = useState<any>(null);
    const [paymentStatus, setPaymentStatus] = useState<'pending' | 'paid' | 'checking'>('pending');

    // Parse search params from hash URL (works with HashRouter)
    const searchParams = useMemo(() => {
        // location.search for HashRouter is after the ?
        const search = location.search || '';
        return new URLSearchParams(search);
    }, [location.search]);

    // Get params from URL
    const type = (searchParams.get('type') || 'subscription') as 'subscription' | 'individual';
    const itemId = searchParams.get('itemId') || '';
    const itemName = decodeURIComponent(searchParams.get('itemName') || '');
    const amount = parseInt(searchParams.get('amount') || '0');
    const duration = parseInt(searchParams.get('duration') || '30');

    // Dev mode detection
    const isDev = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const apiBaseUrl = isDev ? 'http://127.0.0.1:8787' : '';

    // Check if user is logged in
    useEffect(() => {
        const checkSession = async () => {
            const currentSession = await getSession();
            setSession(currentSession);
            // Always require login for checkout
            if (!currentSession) {
                navigate('/?login=true');
            }
        };
        checkSession();
    }, [navigate]);

    // Poll for payment status when paymentResult is set
    useEffect(() => {
        if (!paymentResult?.refId) {
            console.log('[Payment] No refId yet, skipping poll');
            return;
        }
        if (paymentStatus === 'paid') {
            console.log('[Payment] Already paid, skipping poll');
            return;
        }

        console.log('[Payment] Starting polling for refId:', paymentResult.refId);
        setPaymentStatus('checking');
        let pollCount = 0;
        const maxPolls = 120; // Poll for up to 6 minutes (3s * 120)

        const pollInterval = setInterval(async () => {
            pollCount++;
            console.log('[Payment] Polling attempt', pollCount, 'of', maxPolls);

            if (pollCount > maxPolls) {
                console.log('[Payment] Max polls reached, stopping');
                clearInterval(pollInterval);
                return;
            }

            try {
                const url = `${apiBaseUrl}/api/tokopay/check-status?refId=${paymentResult.refId}`;
                console.log('[Payment] Fetching:', url);
                const resp = await fetch(url);
                const data = await resp.json();
                console.log('[Payment] Response:', data);

                if (data.status === 'paid') {
                    console.log('[Payment] PAID! Clearing interval');
                    clearInterval(pollInterval);
                    setPaymentStatus('paid');

                    // Clear pending payment from localStorage
                    localStorage.removeItem('pendingPayment');

                    // Redirect to home with tool auto-open after showing success
                    setTimeout(() => {
                        console.log('[Payment] Redirecting to home with tool:', itemId);
                        // Navigate to home with openTool parameter to auto-open the purchased tool
                        if (type === 'individual' && itemId) {
                            navigate(`/?openTool=${itemId}`);
                        } else {
                            navigate('/');
                        }
                    }, 2500);
                }
            } catch (e) {
                console.log('[Payment] Poll error:', e);
            }
        }, 3000); // Poll every 3 seconds

        return () => {
            console.log('[Payment] Cleanup - clearing interval');
            clearInterval(pollInterval);
        };
    }, [paymentResult?.refId, paymentStatus, apiBaseUrl, navigate]);

    const handlePayment = async () => {
        if (!session?.user) {
            setError('Silakan login terlebih dahulu');
            navigate('/?login=true');
            return;
        }

        setLoading(true);
        setError(null);

        try {
            const refId = generateRefId(type, itemId);

            const userId = session.user.id;
            const userEmail = session.user.email;

            // Call our API to create TokoPay order
            const response = await fetch(`${apiBaseUrl}/api/tokopay/create-order`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    refId,
                    nominal: amount,
                    metode: selectedMethod,
                    userId,
                    userEmail,
                    type,
                    itemId,
                    itemName,
                    duration
                })
            });

            const result = await response.json();

            if (result.success) {
                // Save order info to localStorage for success page
                localStorage.setItem('pendingPayment', JSON.stringify({
                    refId: result.data.refId,
                    type,
                    itemId,
                    itemName,
                    duration,
                    amount,
                    payUrl: result.data.payUrl,
                    createdAt: new Date().toISOString()
                }));

                // Set payment result to show QR/VA in page with auto polling
                setPaymentResult({
                    refId: result.data.refId,
                    payUrl: result.data.payUrl,
                    trxId: result.data.trxId,
                    totalBayar: result.data.totalBayar,
                    qrLink: result.data.qrLink,
                    qrString: result.data.qrString,
                    nomorVa: result.data.nomorVa,
                    checkoutUrl: result.data.checkoutUrl
                });

                // Open Tokopay payment page in new tab for convenience
                window.open(result.data.payUrl, '_blank');
            } else {
                setError(result.error || 'Gagal membuat pembayaran');
            }
        } catch (err: any) {
            console.error('Payment error:', err);
            setError(err.message || 'Terjadi kesalahan');
        } finally {
            setLoading(false);
        }
    };

    const openPayUrl = () => {
        if (paymentResult?.payUrl) {
            window.open(paymentResult.payUrl, '_blank');
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center p-4">
            <div className="w-full max-w-lg">
                {/* Back Button */}
                <button
                    onClick={() => navigate(-1)}
                    className="mb-4 text-slate-400 hover:text-white flex items-center gap-2 transition-colors"
                >
                    ← Kembali
                </button>

                {/* Main Card */}
                <div className="bg-slate-800/50 backdrop-blur-xl rounded-3xl border border-white/10 overflow-hidden shadow-2xl">
                    {/* Header */}
                    <div className="p-6 border-b border-white/10 bg-gradient-to-r from-indigo-600/20 to-purple-600/20">
                        <h1 className="text-2xl font-black text-white mb-1">💳 Pembayaran</h1>
                        <p className="text-slate-400 text-sm">{itemName}</p>
                    </div>

                    {/* Order Summary */}
                    <div className="p-6 border-b border-white/10">
                        <div className="flex justify-between items-center mb-2">
                            <span className="text-slate-400">Jenis</span>
                            <span className="text-white font-bold">
                                {type === 'subscription' ? '💎 Paket Langganan' : '🛒 Beli Satuan'}
                            </span>
                        </div>
                        <div className="flex justify-between items-center mb-2">
                            <span className="text-slate-400">Durasi</span>
                            <span className="text-white font-bold">{duration} Hari</span>
                        </div>
                        <div className="flex justify-between items-center pt-2 border-t border-white/10">
                            <span className="text-slate-400">Total Bayar</span>
                            <span className="text-2xl font-black text-emerald-400">{formatIDR(amount)}</span>
                        </div>
                    </div>

                    {/* Payment Methods */}
                    {!paymentResult && (
                        <div className="p-6">
                            <h2 className="text-white font-bold mb-4">Pilih Metode Pembayaran</h2>

                            {/* QRIS */}
                            <div className="mb-4">
                                <h3 className="text-slate-400 text-xs font-bold uppercase mb-2">📱 QRIS (Recommended)</h3>
                                <div className="space-y-2">
                                    {PAYMENT_METHODS.QRIS.map(method => (
                                        <button
                                            key={method.code}
                                            onClick={() => setSelectedMethod(method.code)}
                                            className={`w-full p-3 rounded-xl flex items-center gap-3 transition-all ${selectedMethod === method.code
                                                ? 'bg-emerald-500/20 border-2 border-emerald-500'
                                                : 'bg-white/5 border border-white/10 hover:bg-white/10'
                                                }`}
                                        >
                                            <span className="text-2xl">{method.icon}</span>
                                            <span className="text-white font-bold">{method.name}</span>
                                            {selectedMethod === method.code && (
                                                <span className="ml-auto text-emerald-400">✓</span>
                                            )}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* E-Wallet */}
                            <div className="mb-4">
                                <h3 className="text-slate-400 text-xs font-bold uppercase mb-2">💳 E-Wallet</h3>
                                <div className="grid grid-cols-2 gap-2">
                                    {PAYMENT_METHODS.EWALLET.map(method => (
                                        <button
                                            key={method.code}
                                            onClick={() => setSelectedMethod(method.code)}
                                            className={`p-3 rounded-xl flex items-center gap-2 transition-all ${selectedMethod === method.code
                                                ? 'bg-emerald-500/20 border-2 border-emerald-500'
                                                : 'bg-white/5 border border-white/10 hover:bg-white/10'
                                                }`}
                                        >
                                            <span className="text-xl">{method.icon}</span>
                                            <span className="text-white text-sm font-bold">{method.name}</span>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Bank Transfer */}
                            <div className="mb-6">
                                <h3 className="text-slate-400 text-xs font-bold uppercase mb-2">🏦 Bank Transfer</h3>
                                <div className="grid grid-cols-2 gap-2">
                                    {PAYMENT_METHODS.BANK.slice(0, 4).map(method => (
                                        <button
                                            key={method.code}
                                            onClick={() => setSelectedMethod(method.code)}
                                            className={`p-3 rounded-xl flex items-center gap-2 transition-all ${selectedMethod === method.code
                                                ? 'bg-emerald-500/20 border-2 border-emerald-500'
                                                : 'bg-white/5 border border-white/10 hover:bg-white/10'
                                                }`}
                                        >
                                            <span className="text-xl">{method.icon}</span>
                                            <span className="text-white text-xs font-bold">{method.name.replace(' Virtual Account', '')}</span>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Error Message */}
                            {error && (
                                <div className="mb-4 p-3 rounded-xl bg-red-500/20 border border-red-500/50 text-red-400 text-sm">
                                    ⚠️ {error}
                                </div>
                            )}

                            {/* Pay Button */}
                            <button
                                onClick={handlePayment}
                                disabled={loading || !selectedMethod}
                                className="w-full py-4 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-black text-lg transition-all shadow-lg shadow-emerald-500/30 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                            >
                                {loading ? (
                                    <>
                                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                        Memproses...
                                    </>
                                ) : (
                                    <>💳 Bayar {formatIDR(amount)}</>
                                )}
                            </button>
                        </div>
                    )}

                    {/* Payment Result */}
                    {paymentResult && (
                        <div className="p-6">
                            {/* Success State - Payment Confirmed */}
                            {paymentStatus === 'paid' ? (
                                <div className="text-center py-8">
                                    <div className="text-7xl mb-4 animate-bounce">🎉</div>
                                    <h2 className="text-2xl font-black text-emerald-400 mb-2">Pembayaran Berhasil!</h2>
                                    <p className="text-white font-bold mb-2">{itemName}</p>
                                    <p className="text-slate-400 text-sm mb-4">Paket Anda sudah aktif selama {duration} hari</p>
                                    <div className="flex items-center justify-center gap-2 text-slate-500 text-sm">
                                        <div className="w-4 h-4 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin"></div>
                                        Mengalihkan ke dashboard...
                                    </div>
                                </div>
                            ) : (
                                <>
                                    {/* Waiting for Payment State */}
                                    <div className="text-center mb-6">
                                        <div className="text-6xl mb-4">✅</div>
                                        <h2 className="text-xl font-black text-white mb-2">Pembayaran Dibuat!</h2>
                                        <p className="text-slate-400 text-sm">Silakan selesaikan pembayaran Anda</p>
                                        {paymentStatus === 'checking' && (
                                            <div className="flex items-center justify-center gap-2 mt-3 text-amber-400 text-xs">
                                                <div className="w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></div>
                                                Menunggu konfirmasi pembayaran...
                                            </div>
                                        )}
                                    </div>

                                    {/* QR Code for QRIS */}
                                    {paymentResult.qrLink && (
                                        <div className="text-center mb-6">
                                            <img
                                                src={paymentResult.qrLink}
                                                alt="QRIS Code"
                                                className="w-48 h-48 mx-auto rounded-xl bg-white p-2"
                                            />
                                            <p className="text-slate-400 text-xs mt-2">Scan QR dengan aplikasi e-wallet/banking Anda</p>
                                        </div>
                                    )}

                                    {/* Virtual Account Number */}
                                    {paymentResult.nomorVa && (
                                        <div className="bg-white/5 rounded-xl p-4 mb-4">
                                            <p className="text-slate-400 text-xs mb-1">Nomor Virtual Account</p>
                                            <p className="text-2xl font-mono font-bold text-white">{paymentResult.nomorVa}</p>
                                        </div>
                                    )}

                                    {/* Amount */}
                                    <div className="bg-white/5 rounded-xl p-4 mb-6">
                                        <p className="text-slate-400 text-xs mb-1">Total Bayar</p>
                                        <p className="text-2xl font-black text-emerald-400">{formatIDR(paymentResult.totalBayar)}</p>
                                    </div>

                                    {/* Open Payment Page Button */}
                                    <button
                                        onClick={openPayUrl}
                                        className="w-full py-4 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-black transition-all shadow-lg"
                                    >
                                        🔗 Buka Halaman Pembayaran
                                    </button>

                                    <p className="text-center text-slate-500 text-xs mt-4">
                                        Ref ID: {paymentResult.refId}
                                    </p>
                                </>
                            )}
                        </div>
                    )}

                    {/* Security Badge */}
                    <p className="text-center text-slate-500 text-xs mt-4 mb-4">
                        🔒 Pembayaran diproses secara aman oleh TokoPay
                    </p>
                </div>
            </div>
        </div>
    );
};

export default PaymentPage;
