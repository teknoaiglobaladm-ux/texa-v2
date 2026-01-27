// CheckoutPopup Component - Popup untuk beli satuan atau langganan
import React, { useState, useEffect } from 'react';
import { AITool } from '../types';
import {
    SubscriptionSettings,
    PerToolDurationTier,
    subscribeToSettings,
    formatIDR,
    DEFAULT_SETTINGS
} from '../services/supabaseSubscriptionService';

interface CheckoutPopupProps {
    tool: AITool;
    isOpen: boolean;
    onClose: () => void;
}

const CheckoutPopup: React.FC<CheckoutPopupProps> = ({ tool, isOpen, onClose }) => {
    const [settings, setSettings] = useState<SubscriptionSettings>(DEFAULT_SETTINGS);
    const [selectedPackage, setSelectedPackage] = useState<string>('');
    const [selectedTier, setSelectedTier] = useState<string>('');
    const [purchaseType, setPurchaseType] = useState<'individual' | 'subscription'>('individual');

    useEffect(() => {
        const unsubscribe = subscribeToSettings((s) => setSettings(s));
        return () => unsubscribe();
    }, []);

    // Set default selected package to the popular one
    useEffect(() => {
        const popularPkg = settings.packages.find(p => p.popular && p.active);
        if (popularPkg) {
            setSelectedPackage(popularPkg.id);
        } else if (settings.packages.length > 0) {
            const activePkg = settings.packages.find(p => p.active);
            if (activePkg) setSelectedPackage(activePkg.id);
        }
    }, [settings.packages]);

    // Set default selected tier to the popular one
    useEffect(() => {
        const tiers = settings.perToolDurationTiers || [];
        const popularTier = tiers.find(t => t.popular && t.active);
        if (popularTier) {
            setSelectedTier(popularTier.id);
        } else if (tiers.length > 0) {
            const activeTier = tiers.find(t => t.active);
            if (activeTier) setSelectedTier(activeTier.id);
        }
    }, [settings.perToolDurationTiers]);

    if (!isOpen) return null;

    // Get active duration tiers
    const activeTiers = (settings.perToolDurationTiers || []).filter(t => t.active);

    // Get active packages
    const activePackages = settings.packages.filter(p => p.active);

    // Get selected tier details
    const currentTier = activeTiers.find(t => t.id === selectedTier);

    const handleIndividualPurchase = () => {
        if (!currentTier) return;

        // Redirect to internal payment page with TokoPay integration
        const params = new URLSearchParams({
            type: 'individual',
            itemId: tool.id,
            itemName: tool.name,
            amount: String(currentTier.discountPrice || currentTier.price),
            duration: String(currentTier.duration),
            tierId: currentTier.id,
            tierName: currentTier.name
        });

        window.location.hash = `/payment?${params.toString()}`;
        onClose();
    };

    const handleSubscriptionPurchase = () => {
        const pkg = settings.packages.find(p => p.id === selectedPackage);
        if (!pkg) return;

        // Redirect to internal payment page with TokoPay integration
        const params = new URLSearchParams({
            type: 'subscription',
            itemId: pkg.id,
            itemName: pkg.name,
            amount: String(pkg.discountPrice || pkg.price),
            duration: String(pkg.duration),
            packageId: pkg.id
        });

        window.location.hash = `/payment?${params.toString()}`;
        onClose();
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/70 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal */}
            <div className="relative w-full max-w-lg bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 rounded-3xl border border-white/10 shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-300 max-h-[90vh] overflow-y-auto">
                {/* Header */}
                <div className="relative p-6 pb-4 border-b border-white/10">
                    <button
                        onClick={onClose}
                        className="absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full bg-white/10 hover:bg-white/20 transition-colors"
                    >
                        <span className="text-white text-lg">×</span>
                    </button>

                    <div className="flex items-center gap-4">
                        {tool.imageUrl && (
                            <img
                                src={tool.imageUrl}
                                alt={tool.name}
                                className="w-14 h-14 rounded-xl object-cover border border-white/10"
                            />
                        )}
                        <div>
                            <h3 className="text-xl font-black text-white">{tool.name}</h3>
                            <p className="text-slate-400 text-sm">{tool.category}</p>
                        </div>
                    </div>
                </div>

                {/* Content */}
                <div className="p-6 space-y-5">
                    {/* Individual Purchase Option with Duration Tiers */}
                    {settings.enablePerToolPurchase !== false && activeTiers.length > 0 && (
                        <div
                            className={`p-4 rounded-2xl border-2 cursor-pointer transition-all ${purchaseType === 'individual'
                                ? 'border-emerald-500 bg-emerald-500/10'
                                : 'border-white/10 hover:border-white/30 bg-white/5'
                                }`}
                            onClick={() => setPurchaseType('individual')}
                        >
                            <div className="flex items-center gap-2 mb-4">
                                <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${purchaseType === 'individual' ? 'border-emerald-500 bg-emerald-500' : 'border-white/30'
                                    }`}>
                                    {purchaseType === 'individual' && <span className="text-white text-xs">✓</span>}
                                </div>
                                <span className="font-bold text-white">🛒 Beli Satuan</span>
                                <span className="text-slate-400 text-sm">- Hanya {tool.name}</span>
                            </div>

                            {/* Duration Tier Options */}
                            <div className="grid grid-cols-3 gap-2 mb-4">
                                {activeTiers.map(tier => {
                                    const isSelected = selectedTier === tier.id && purchaseType === 'individual';
                                    const finalPrice = tier.discountPrice || tier.price;
                                    return (
                                        <div
                                            key={tier.id}
                                            className={`p-3 rounded-xl text-center transition-all cursor-pointer relative ${isSelected
                                                ? 'bg-emerald-500/30 border-2 border-emerald-500 shadow-lg shadow-emerald-500/20'
                                                : 'bg-white/5 border border-white/10 hover:bg-white/10'
                                                }`}
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                setSelectedTier(tier.id);
                                                setPurchaseType('individual');
                                            }}
                                        >
                                            {tier.popular && (
                                                <span className="absolute -top-2 left-1/2 -translate-x-1/2 px-2 py-0.5 bg-amber-500 text-white text-[8px] font-bold rounded-full shadow-lg">
                                                    BEST
                                                </span>
                                            )}
                                            <p className={`font-bold text-sm ${isSelected ? 'text-white' : 'text-slate-300'}`}>
                                                {tier.name}
                                            </p>
                                            <p className="text-emerald-400 font-black text-lg mt-1">
                                                {formatIDR(finalPrice)}
                                            </p>
                                            {tier.discountPrice && (
                                                <p className="text-slate-500 line-through text-[10px]">
                                                    {formatIDR(tier.price)}
                                                </p>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>

                            {purchaseType === 'individual' && currentTier && (
                                <>
                                    <div className="flex items-center gap-2 text-slate-400 text-sm mb-4">
                                        <span>⏱️</span>
                                        <span>Akses <strong className="text-emerald-400">{currentTier.duration} hari</strong> untuk {tool.name}</span>
                                    </div>
                                    <button
                                        onClick={handleIndividualPurchase}
                                        className="w-full py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-emerald-500/30 flex items-center justify-center gap-2"
                                    >
                                        🛒 Beli Sekarang - {formatIDR(currentTier.discountPrice || currentTier.price)}
                                    </button>
                                </>
                            )}
                        </div>
                    )}

                    {/* Divider */}
                    <div className="flex items-center gap-3">
                        <div className="flex-1 h-px bg-white/10" />
                        <span className="text-slate-500 text-xs font-bold uppercase">atau</span>
                        <div className="flex-1 h-px bg-white/10" />
                    </div>

                    {/* Subscription Option */}
                    <div
                        className={`p-4 rounded-2xl border-2 cursor-pointer transition-all ${purchaseType === 'subscription'
                            ? 'border-indigo-500 bg-indigo-500/10'
                            : 'border-white/10 hover:border-white/30 bg-white/5'
                            }`}
                        onClick={() => setPurchaseType('subscription')}
                    >
                        <div className="flex items-center gap-2 mb-3">
                            <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${purchaseType === 'subscription' ? 'border-indigo-500 bg-indigo-500' : 'border-white/30'
                                }`}>
                                {purchaseType === 'subscription' && <span className="text-white text-xs">✓</span>}
                            </div>
                            <span className="font-bold text-white">💎 Paket Langganan</span>
                            <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 text-[10px] font-bold rounded-full">HEMAT</span>
                        </div>

                        <p className="text-slate-400 text-sm mb-3">Akses SEMUA tools dengan satu langganan</p>

                        {/* Package Options */}
                        <div className="space-y-2">
                            {activePackages.map(pkg => {
                                const finalPrice = pkg.discountPrice || pkg.price;
                                return (
                                    <div
                                        key={pkg.id}
                                        className={`p-3 rounded-xl flex items-center justify-between transition-all ${selectedPackage === pkg.id && purchaseType === 'subscription'
                                            ? 'bg-indigo-500/20 border border-indigo-500/50'
                                            : 'bg-white/5 border border-transparent hover:bg-white/10'
                                            }`}
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            setSelectedPackage(pkg.id);
                                            setPurchaseType('subscription');
                                        }}
                                    >
                                        <div className="flex items-center gap-3">
                                            <div className={`w-4 h-4 rounded-full border-2 ${selectedPackage === pkg.id && purchaseType === 'subscription'
                                                ? 'border-indigo-400 bg-indigo-400'
                                                : 'border-white/30'
                                                }`} />
                                            <div>
                                                <span className="font-bold text-white text-sm">{pkg.name}</span>
                                                {pkg.popular && (
                                                    <span className="ml-2 px-1.5 py-0.5 bg-indigo-500 text-white text-[8px] font-bold rounded">POPULER</span>
                                                )}
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            {pkg.discountPrice && (
                                                <span className="text-slate-500 line-through text-xs mr-1">
                                                    {formatIDR(pkg.price)}
                                                </span>
                                            )}
                                            <span className="text-indigo-400 font-bold">
                                                {formatIDR(finalPrice)}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>

                        {purchaseType === 'subscription' && (
                            <button
                                onClick={handleSubscriptionPurchase}
                                className="w-full mt-4 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-indigo-500/30"
                            >
                                💎 Langganan Sekarang
                            </button>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <div className="px-6 py-4 border-t border-white/10 bg-white/5">
                    <p className="text-slate-500 text-xs text-center">
                        🔒 Pembayaran aman & terenkripsi
                    </p>
                </div>
            </div>
        </div>
    );
};

export default CheckoutPopup;
