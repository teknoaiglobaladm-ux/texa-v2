
import React, { useState, useEffect } from 'react';
import { AITool } from '../types';
import { formatIDR, subscribeToSettings, SubscriptionSettings, DEFAULT_SETTINGS } from '../services/supabaseSubscriptionService';
import { useNavigate } from 'react-router-dom';
import { auth } from '../services/firebase';
import { isUrlIframeAllowed } from '../utils/iframePolicy';
import { checkExtensionInstalled } from '../services/extensionService';
import { usePopupState } from '../services/popupContext';
import ExtensionWarningPopup from './ExtensionWarningPopup';
import CheckoutPopup from './CheckoutPopup';

interface CompactToolCardProps {
    tool: AITool;
    hasAccess: boolean;
}

const CompactToolCard: React.FC<CompactToolCardProps> = ({ tool, hasAccess }) => {
    const navigate = useNavigate();
    const [injecting, setInjecting] = useState(false);
    const [status, setStatus] = useState<string | null>(null);
    const [showCheckoutPopup, setShowCheckoutPopup] = useState(false);
    const [showExtensionWarning, setShowExtensionWarning] = useState(false);
    const [settings, setSettings] = useState<SubscriptionSettings>(DEFAULT_SETTINGS);

    // Register popup states
    usePopupState(showCheckoutPopup || showExtensionWarning);

    // Subscribe to settings
    useEffect(() => {
        const unsubscribe = subscribeToSettings((fetchedSettings) => {
            setSettings(fetchedSettings);
        });
        return () => unsubscribe();
    }, []);

    const tryOpenViaExtension = async (): Promise<boolean> => {
        if (window.TEXAExtension && window.TEXAExtension.ready) {
            try {
                window.TEXAExtension.openTool(tool.id, tool.targetUrl, tool.apiUrl);
                return true;
            } catch (error) {
                return false;
            }
        }

        const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const idToken = auth.currentUser ? await auth.currentUser.getIdToken() : null;

        return await new Promise<boolean>((resolve) => {
            const timeoutId = window.setTimeout(() => {
                window.removeEventListener('message', onAck);
                resolve(false);
            }, 800);

            const onAck = (event: MessageEvent) => {
                if (event.origin !== window.location.origin) return;
                const data = (event.data || {}) as any;
                if (data.type !== 'TEXA_OPEN_TOOL_ACK') return;
                if (data.requestId !== requestId) return;
                window.clearTimeout(timeoutId);
                window.removeEventListener('message', onAck);
                resolve(Boolean(data.ok));
            };

            window.addEventListener('message', onAck);
            window.postMessage({
                type: 'TEXA_OPEN_TOOL',
                requestId,
                toolId: tool.id,
                idToken,
                targetUrl: tool.targetUrl,
                cookiesData: tool.cookiesData || null,
                apiUrl: tool.apiUrl || null
            }, window.location.origin);
        });
    };

    const handleClick = async () => {
        if (!hasAccess) {
            setShowCheckoutPopup(true);
            return;
        }

        const canIframe = tool.openMode === 'iframe' && isUrlIframeAllowed(tool.targetUrl);
        if (canIframe) {
            navigate(`/tool/${tool.id}`);
            return;
        }

        setInjecting(true);
        setStatus("Memeriksa Extension...");

        const isExtensionInstalled = await checkExtensionInstalled();
        if (!isExtensionInstalled) {
            setInjecting(false);
            setStatus(null);
            setShowExtensionWarning(true);
            return;
        }

        setStatus("Syncing Sesi...");
        setTimeout(() => {
            setStatus("Menyiapkan Akses...");
            setTimeout(async () => {
                setInjecting(false);
                setStatus("Berhasil!");
                const openedByExtension = await tryOpenViaExtension();
                if (!openedByExtension) window.open(tool.targetUrl, '_blank');
                setTimeout(() => setStatus(null), 2000);
            }, 1000);
        }, 800);
    };

    return (
        <>
            {/* Card - Silver Doff Metal Plate (light) / Dark Glass (dark) */}
            <div
                onClick={handleClick}
                className="group rounded-2xl overflow-hidden transition-all duration-300 cursor-pointer flex flex-col h-full relative bg-gradient-to-br from-slate-300 via-gray-200 to-zinc-300 dark:from-slate-900 dark:via-slate-800 dark:to-zinc-900 border border-slate-400/50 dark:border-slate-600/40 shadow-[inset_0_1px_0_rgba(255,255,255,0.7),0_4px_12px_rgba(0,0,0,0.15)] dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.1),0_4px_12px_rgba(0,0,0,0.4)] hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_8px_24px_rgba(0,0,0,0.2)] dark:hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.15),0_8px_24px_rgba(0,0,0,0.5)] hover:border-indigo-500/60 dark:hover:border-indigo-400/60"
            >
                {/* Image Container */}
                <div className="relative h-28 sm:h-32 overflow-hidden bg-slate-400 dark:bg-slate-700">
                    <img
                        src={tool.imageUrl}
                        alt={tool.name}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                        loading="lazy"
                    />

                    {/* Category Badge */}
                    <div className="absolute top-2 left-2 px-2 py-0.5 bg-indigo-600/95 dark:bg-indigo-700/95 backdrop-blur-sm rounded-md text-[8px] md:text-[9px] font-bold text-white uppercase tracking-wide shadow-lg">
                        {tool.category}
                    </div>

                    {/* Status Badge */}
                    {hasAccess && (
                        <div className="absolute top-2 right-2 px-2 py-0.5 bg-emerald-500/95 backdrop-blur-sm rounded-md text-[8px] font-bold text-white shadow-lg">
                            ✓ Aktif
                        </div>
                    )}
                </div>

                {/* Content */}
                <div className="p-3 sm:p-4 flex-grow flex flex-col">
                    {/* Title - Dark text on light / Light text on dark */}
                    <h3 className="text-sm sm:text-base font-bold text-zinc-800 dark:text-zinc-100 mb-1 line-clamp-1 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                        {tool.name}
                    </h3>

                    <p className="text-[10px] sm:text-xs text-zinc-600 dark:text-zinc-400 line-clamp-2 mb-3 leading-relaxed">
                        {tool.description}
                    </p>

                    <div className="mt-auto flex items-center justify-between pt-2 border-t border-slate-400/40 dark:border-zinc-600/30">
                        <div>
                            <span className="text-[8px] text-zinc-500 dark:text-zinc-500 uppercase tracking-widest font-medium">Mulai</span>
                            {(() => {
                                const price = tool.individualPrice || settings.defaultToolPrice || 15000;
                                const discount = tool.individualDiscount;
                                const duration = tool.individualDuration || settings.defaultToolDuration || 7;
                                return (
                                    <>
                                        <div className="flex items-baseline gap-1">
                                            {discount ? (
                                                <>
                                                    <span className="text-sm sm:text-base font-bold text-emerald-500">{formatIDR(discount)}</span>
                                                    <span className="text-[9px] text-slate-500 line-through">{formatIDR(price)}</span>
                                                </>
                                            ) : (
                                                <span className="text-sm sm:text-base font-bold text-zinc-800 dark:text-zinc-100">{formatIDR(price)}</span>
                                            )}
                                        </div>
                                        <span className="text-[8px] text-zinc-500">/{duration} hari</span>
                                    </>
                                );
                            })()}
                        </div>

                        <button
                            disabled={injecting}
                            className={`px-3 py-1.5 rounded-lg text-[10px] sm:text-xs font-bold transition-all active:scale-95 ${injecting
                                ? 'bg-amber-500/20 text-amber-400'
                                : hasAccess
                                    ? 'bg-emerald-500 hover:bg-emerald-600 text-white shadow-lg shadow-emerald-500/30'
                                    : 'bg-indigo-500 hover:bg-indigo-600 text-white shadow-lg shadow-indigo-500/30'
                                }`}
                        >
                            {injecting ? '⏳' : hasAccess ? '🚀 Buka' : '🛒 Beli'}
                        </button>
                    </div>
                </div>

                {/* Loading Overlay */}
                {status && (
                    <div className="absolute inset-0 flex items-center justify-center bg-slate-300/95 dark:bg-slate-900/95 backdrop-blur-sm z-10">
                        <div className="text-center">
                            <div className="w-10 h-10 border-3 border-indigo-600 dark:border-indigo-400 border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                            <p className="text-zinc-800 dark:text-zinc-100 text-xs font-bold">{status}</p>
                        </div>
                    </div>
                )}
            </div>

            {/* Checkout Popup */}
            <CheckoutPopup
                tool={tool}
                isOpen={showCheckoutPopup}
                onClose={() => setShowCheckoutPopup(false)}
            />

            {/* Extension Warning Popup */}
            <ExtensionWarningPopup
                isOpen={showExtensionWarning}
                onClose={() => setShowExtensionWarning(false)}
                toolName={tool.name}
            />
        </>
    );
};

export default CompactToolCard;

