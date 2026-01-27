
import React, { useState, useEffect } from 'react';
import { AITool } from '../types';
import { auth } from '../services/firebase';
import { useNavigate } from 'react-router-dom';
import { isUrlIframeAllowed } from '../utils/iframePolicy';
import {
  subscribeToSettings,
  SubscriptionSettings,
  formatIDR,
  DEFAULT_SETTINGS
} from '../services/supabaseSubscriptionService';
import { checkExtensionInstalled } from '../services/extensionService';
import { usePopupState } from '../services/popupContext';
import ExtensionWarningPopup from './ExtensionWarningPopup';
import CheckoutPopup from './CheckoutPopup';

interface ToolCardProps {
  tool: AITool;
  hasAccess: boolean;
  onBuyClick?: () => void;
}

// Parse various YouTube URL formats and convert to embed URL
const parseYouTubeUrl = (url: string): string | null => {
  if (!url) return null;

  try {
    let videoId: string | null = null;

    // Pattern 1: youtube.com/shorts/VIDEO_ID
    const shortsMatch = url.match(/youtube\.com\/shorts\/([a-zA-Z0-9_-]+)/);
    if (shortsMatch) {
      videoId = shortsMatch[1];
    }

    // Pattern 2: youtube.com/watch?v=VIDEO_ID
    const watchMatch = url.match(/youtube\.com\/watch\?v=([a-zA-Z0-9_-]+)/);
    if (watchMatch) {
      videoId = watchMatch[1];
    }

    // Pattern 3: youtu.be/VIDEO_ID
    const shortMatch = url.match(/youtu\.be\/([a-zA-Z0-9_-]+)/);
    if (shortMatch) {
      videoId = shortMatch[1];
    }

    // Pattern 4: youtube.com/embed/VIDEO_ID (already embed)
    const embedMatch = url.match(/youtube\.com\/embed\/([a-zA-Z0-9_-]+)/);
    if (embedMatch) {
      videoId = embedMatch[1];
    }

    // Pattern 5: youtube.com/v/VIDEO_ID
    const vMatch = url.match(/youtube\.com\/v\/([a-zA-Z0-9_-]+)/);
    if (vMatch) {
      videoId = vMatch[1];
    }

    if (videoId) {
      // Remove any query params from video ID
      videoId = videoId.split('?')[0].split('&')[0];
      return `https://www.youtube.com/embed/${videoId}?autoplay=1&rel=0`;
    }

    return null;
  } catch {
    return null;
  }
};

const ToolCard: React.FC<ToolCardProps> = ({ tool, hasAccess, onBuyClick }) => {
  const navigate = useNavigate();
  const [injecting, setInjecting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [showCheckoutPopup, setShowCheckoutPopup] = useState(false);
  const [showVideoPopup, setShowVideoPopup] = useState(false);
  const [showExtensionWarning, setShowExtensionWarning] = useState(false);
  const [settings, setSettings] = useState<SubscriptionSettings>(DEFAULT_SETTINGS);

  // Get embed URL from video URL
  const embedUrl = parseYouTubeUrl(tool.embedVideoUrl || '');

  // Register popup states to hide/show header/footer
  usePopupState(showCheckoutPopup || showVideoPopup || showExtensionWarning);

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
        console.error('Extension open tool failed:', error);
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
      window.postMessage(
        {
          type: 'TEXA_OPEN_TOOL',
          requestId,
          toolId: tool.id,
          idToken,
          targetUrl: tool.targetUrl,
          // Kirim cookiesData langsung dari tool jika ada
          cookiesData: tool.cookiesData || null,
          // Kirim apiUrl untuk fetch cookies dinamis
          apiUrl: tool.apiUrl || null
        },
        window.location.origin
      );
    });
  };

  const handleOpenTool = async () => {
    if (!hasAccess) {
      setShowCheckoutPopup(true);
      return;
    }

    const canIframe = tool.openMode === 'iframe' && isUrlIframeAllowed(tool.targetUrl);

    if (canIframe) {
      navigate(`/tool/${tool.id}`);
      return;
    }

    // Check if extension is installed first
    setInjecting(true);
    setStatus("Memeriksa Extension...");

    const isExtensionInstalled = await checkExtensionInstalled();

    if (!isExtensionInstalled) {
      // Extension not installed, show warning popup
      setInjecting(false);
      setStatus(null);
      setShowExtensionWarning(true);
      return;
    }

    // Extension is installed, proceed with opening tool
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
      <div className="glass-card group rounded-[24px] md:rounded-[32px] overflow-hidden hover:border-indigo-500/40 transition-all duration-500 flex flex-col h-full relative smooth-animate">
        <div className="relative h-48 md:h-56 overflow-hidden">
          <img
            src={tool.imageUrl}
            alt={tool.name}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700"
            loading="lazy"
          />
          <div className="absolute top-3 left-3 md:top-4 md:left-4 px-3 py-1 bg-black/60 backdrop-blur-xl rounded-full text-[8px] md:text-[10px] font-black uppercase tracking-widest text-indigo-300 border border-white/10">
            {tool.category}
          </div>

          {/* Play Button - Minimal & Transparent (only visible on hover) */}
          {embedUrl && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowVideoPopup(true);
              }}
              className="absolute inset-0 flex items-center justify-center group/play cursor-pointer"
            >
              {/* Very Subtle Overlay - only visible on hover */}
              <div className="absolute inset-0 bg-black/0 group-hover/play:bg-black/30 transition-all duration-300" />

              {/* Play Button - Very Small & Transparent by default, visible on hover */}
              <div className="relative w-10 h-10 md:w-12 md:h-12 rounded-full bg-black/10 border border-white/10 flex items-center justify-center transition-all duration-300 opacity-40 group-hover/play:opacity-100 group-hover/play:scale-110 group-hover/play:bg-black/50 group-hover/play:border-white/40 group-hover/play:shadow-xl">
                {/* Play Icon - Subtle */}
                <svg
                  className="w-4 h-4 md:w-5 md:h-5 text-white/80 ml-0.5 group-hover/play:text-white transition-all"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M8 5v14l11-7z" />
                </svg>
              </div>

              {/* Small Video Badge at corner instead of pulse animation */}
              <div className="absolute bottom-3 right-3 px-2 py-1 bg-black/50 backdrop-blur-sm rounded-md text-[9px] font-bold text-white/70 flex items-center gap-1 opacity-60 group-hover/play:opacity-100 transition-all">
                <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M8 5v14l11-7z" />
                </svg>
                Video
              </div>
            </button>
          )}

          {/* Video Badge - Only show if no play button */}
          {tool.embedVideoUrl && !embedUrl && (
            <div className="absolute top-3 right-3 md:top-4 md:right-4 px-2 py-1 bg-purple-600/80 backdrop-blur-xl rounded-full text-[8px] font-bold text-white flex items-center gap-1">
              🎬 Video
            </div>
          )}
        </div>

        <div className="p-5 md:p-7 flex-grow flex flex-col relative">
          <h3 className="text-xl md:text-2xl font-black mb-2 md:mb-3 group-hover:text-indigo-400 transition-colors tracking-tight text-theme-primary">{tool.name}</h3>
          <p className="text-theme-secondary text-xs md:text-sm mb-6 line-clamp-2 font-medium leading-relaxed">
            {tool.description}
          </p>

          <div className="mt-auto pt-4 md:pt-6 border-t border-[var(--glass-border)] flex items-center justify-between">
            <div className="flex flex-col">
              {(() => {
                const price = tool.individualPrice || settings.defaultToolPrice || 15000;
                const discount = tool.individualDiscount;
                const duration = tool.individualDuration || settings.defaultToolDuration || 7;
                return (
                  <>
                    <span className="text-[8px] md:text-[10px] text-theme-muted uppercase font-black tracking-widest">Mulai</span>
                    <div className="flex items-baseline gap-1">
                      {discount ? (
                        <>
                          <span className="text-sm md:text-lg font-black text-emerald-400 leading-none">{formatIDR(discount)}</span>
                          <span className="text-[10px] text-slate-500 line-through">{formatIDR(price)}</span>
                        </>
                      ) : (
                        <span className="text-sm md:text-lg font-black text-theme-primary leading-none">{formatIDR(price)}</span>
                      )}
                    </div>
                    <span className="text-[8px] text-slate-500">/{duration} hari</span>
                  </>
                );
              })()}
            </div>

            <button
              disabled={injecting}
              onClick={handleOpenTool}
              className={`px-4 md:px-6 py-2.5 md:py-3 rounded-xl md:rounded-2xl font-black text-[10px] md:text-sm transition-all flex items-center gap-2 active:scale-95 smooth-animate ${injecting
                ? 'bg-amber-500/20 text-amber-400'
                : hasAccess
                  ? 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-900/40'
                  : 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-xl shadow-indigo-900/40'
                }`}
            >
              {injecting ? (
                <>
                  <div className="w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></div>
                  Proses...
                </>
              ) : hasAccess ? (
                <>🚀 Open Tools</>
              ) : (
                <>🛒 Beli</>
              )}
            </button>
          </div>
        </div>

        {status && (
          <div className="absolute inset-0 flex items-center justify-center glass backdrop-blur-2xl z-20 transition-opacity duration-300">
            <div className="text-center p-6">
              <div className="w-16 h-16 premium-gradient rounded-2xl mx-auto mb-4 flex items-center justify-center animate-bounce">
                <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <p className="text-white text-lg font-black tracking-tight">{status}</p>
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

      {/* Video Popup Modal */}
      {showVideoPopup && embedUrl && (
        <div
          className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/90 backdrop-blur-md"
          onClick={() => setShowVideoPopup(false)}
        >
          <div
            className="relative w-full max-w-4xl aspect-video rounded-2xl overflow-hidden shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close button */}
            <button
              onClick={() => setShowVideoPopup(false)}
              className="absolute -top-12 right-0 w-10 h-10 rounded-full bg-white/10 backdrop-blur-xl border border-white/20 flex items-center justify-center text-white hover:bg-white/20 transition-all z-10"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>

            {/* Video Title */}
            <div className="absolute -top-12 left-0 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg overflow-hidden">
                <img src={tool.imageUrl} alt={tool.name} className="w-full h-full object-cover" />
              </div>
              <div>
                <h3 className="text-white font-bold text-sm">{tool.name}</h3>
                <p className="text-slate-400 text-xs">Preview Video</p>
              </div>
            </div>

            {/* YouTube iframe */}
            <iframe
              src={embedUrl}
              title={`${tool.name} - Preview Video`}
              className="w-full h-full bg-black"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
              allowFullScreen
            />
          </div>
        </div>
      )}

      {/* Extension Warning Popup */}
      <ExtensionWarningPopup
        isOpen={showExtensionWarning}
        onClose={() => setShowExtensionWarning(false)}
        toolName={tool.name}
      />
    </>
  );
};

export default ToolCard;
