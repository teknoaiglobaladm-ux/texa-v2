
import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AITool } from '../types';
import { TexaUser } from '../services/supabaseAuthService';
import ToolCard from './ToolCard';
import CompactToolCard from './CompactToolCard';
import { subscribeToCatalog, CatalogItem } from '../services/supabaseCatalogService';
import {
  DashboardContentSettings,
  DEFAULT_DASHBOARD_CONTENT,
  subscribeToDashboardContent
} from '../services/supabaseDashboardService';
import { getUserToolAccesses, UserToolAccess } from '../services/userToolsService';
import { checkExtensionInstalled } from '../services/extensionService';


// Fallback mock tools (used when Firestore is empty)
const MOCK_TOOLS: AITool[] = [
  {
    id: '1',
    name: 'ChatGPT Plus (Shared)',
    description: 'Akses penuh ke GPT-4o, DALL·E 3, dan fitur analisis data tercanggih.',
    category: 'Menulis & Riset',
    imageUrl: 'https://images.unsplash.com/photo-1677442136019-21780ecad995?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://chat.openai.com',
    status: 'active',
    priceMonthly: 45000
  },
  {
    id: '2',
    name: 'Midjourney Pro',
    description: 'Generate gambar AI kualitas tinggi tanpa batas dengan mode cepat.',
    category: 'Desain & Art',
    imageUrl: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://midjourney.com',
    status: 'active',
    priceMonthly: 75000
  },
  {
    id: '3',
    name: 'Canva Pro Teams',
    description: 'Buka jutaan aset premium dan hapus background otomatis.',
    category: 'Desain Grafis',
    imageUrl: 'https://images.unsplash.com/photo-1626785774573-4b799315345d?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://canva.com',
    status: 'active',
    priceMonthly: 15000
  },
  {
    id: '4',
    name: 'Jasper AI Business',
    description: 'Bikin konten sosmed dan iklan 10x lebih cepat dengan AI.',
    category: 'Marketing',
    imageUrl: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://jasper.ai',
    status: 'active',
    priceMonthly: 99000
  },
  {
    id: '5',
    name: 'Claude 3.5 Sonnet',
    description: 'AI cerdas untuk coding dan penulisan kreatif dengan konteks luas.',
    category: 'Coding & Teks',
    imageUrl: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://claude.ai',
    status: 'active',
    priceMonthly: 55000
  },
  {
    id: '6',
    name: 'Grammarly Premium',
    description: 'Cek tata bahasa Inggris otomatis dan kirim email tanpa typo.',
    category: 'Produktivitas',
    imageUrl: 'https://images.unsplash.com/photo-1455390582262-044cdead277a?auto=format&fit=crop&q=80&w=400',
    targetUrl: 'https://grammarly.com',
    status: 'active',
    priceMonthly: 25000
  }
];

interface MarketplaceProps {
  user: TexaUser | null;
}

type ViewMode = 'grid' | 'compact';

const Marketplace: React.FC<MarketplaceProps> = ({ user }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [filter, setFilter] = useState('Semua');
  const [tools, setTools] = useState<AITool[]>(MOCK_TOOLS);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<ViewMode>('compact');
  const [content, setContent] = useState<DashboardContentSettings>(DEFAULT_DASHBOARD_CONTENT);
  const [userToolAccesses, setUserToolAccesses] = useState<UserToolAccess[]>([]);
  const [autoOpenToolId, setAutoOpenToolId] = useState<string | null>(null);
  const autoOpenProcessed = useRef(false);

  // Detect openTool parameter from URL (e.g., after successful payment)
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const openToolId = searchParams.get('openTool');

    if (openToolId && !autoOpenProcessed.current) {
      console.log('[Marketplace] Auto-open tool detected:', openToolId);
      setAutoOpenToolId(openToolId);

      // Clear the URL parameter to prevent re-opening on refresh
      const newUrl = location.pathname;
      window.history.replaceState({}, '', `#${newUrl}`);
    }
  }, [location.search, location.pathname]);

  // Auto-open tool when detected and tools are loaded
  useEffect(() => {
    if (!autoOpenToolId || loading || autoOpenProcessed.current) return;

    const tool = tools.find(t => t.id === autoOpenToolId);
    if (!tool) {
      console.log('[Marketplace] Tool not found:', autoOpenToolId);
      return;
    }

    // Mark as processed to prevent multiple opens
    autoOpenProcessed.current = true;
    console.log('[Marketplace] Auto-opening tool:', tool.name);

    // Open the tool via extension or new tab
    const openTool = async () => {
      const isExtensionInstalled = await checkExtensionInstalled();

      if (isExtensionInstalled && window.TEXAExtension?.openTool) {
        // Open via extension
        window.TEXAExtension.openTool(tool.id, tool.targetUrl, tool.apiUrl);
      } else if (tool.targetUrl) {
        // Fallback: open in new tab
        window.open(tool.targetUrl, '_blank');
      }

      // Clear autoOpenToolId
      setAutoOpenToolId(null);
    };

    // Small delay to ensure UI is ready
    setTimeout(openTool, 500);
  }, [autoOpenToolId, tools, loading]);

  // Subscribe to dashboard content settings
  useEffect(() => {
    const unsubscribe = subscribeToDashboardContent((settings) => {
      setContent(settings);
    });
    return () => unsubscribe();
  }, []);

  // Fetch user's individual tool accesses
  useEffect(() => {
    if (!user?.id) {
      setUserToolAccesses([]);
      return;
    }

    const fetchAccesses = async () => {
      const accesses = await getUserToolAccesses(user.id);
      setUserToolAccesses(accesses);
    };

    fetchAccesses();

    // Refresh every 5 seconds for faster payment detection
    const intervalId = setInterval(fetchAccesses, 5000);

    // Also refresh when window regains focus (user comes back from payment page)
    const handleFocus = () => {
      console.log('[Marketplace] Window focused - refreshing tool accesses');
      fetchAccesses();
    };
    window.addEventListener('focus', handleFocus);

    // Listen for storage event (when payment completes)
    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'pendingPayment' && e.newValue === null) {
        console.log('[Marketplace] Payment completed - refreshing tool accesses');
        fetchAccesses();
      }
    };
    window.addEventListener('storage', handleStorage);

    return () => {
      clearInterval(intervalId);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('storage', handleStorage);
    };
  }, [user?.id]);

  // Subscribe to catalog from Firestore
  useEffect(() => {
    const unsubscribe = subscribeToCatalog((items: CatalogItem[]) => {
      const activeItems = items.filter(item => item.status === 'active');
      if (activeItems.length > 0) {
        setTools(activeItems);
      } else {
        setTools(MOCK_TOOLS);
      }
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  const categories = ['Semua', ...new Set(tools.map(t => t.category))];

  const filteredTools = filter === 'Semua'
    ? tools
    : tools.filter(t => t.category === filter);

  // Check if user has active subscription
  const hasActiveSubscription = user?.subscriptionEnd
    ? new Date(user.subscriptionEnd) > new Date()
    : false;

  // Helper function to check access for a specific tool
  const hasAccessToTool = (toolId: string): boolean => {
    // Has subscription = access to all tools
    if (hasActiveSubscription) return true;

    // Check individual tool purchase
    return userToolAccesses.some(access => access.tool_id === toolId);
  };

  return (
    <section id="marketplace" className="py-4 md:py-8 scroll-mt-24">
      {/* Header with View Toggle */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-6 md:mb-8 gap-4 md:gap-6 px-2">
        <div className="max-w-xl">
          <h2
            className="text-xl md:text-3xl font-black mb-1 md:mb-2 tracking-tight text-theme-primary flex items-center gap-2"
            style={content?.catalogTitleColor ? { color: content.catalogTitleColor } : undefined}
          >
            {content?.catalogTitle || 'Katalog AI Premium'}
            <span
              className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 text-[10px] font-bold rounded-full"
              style={{
                ...(content?.catalogBadgeBgColor ? { backgroundColor: content.catalogBadgeBgColor } : {}),
                ...(content?.catalogBadgeTextColor ? { color: content.catalogBadgeTextColor } : {})
              }}
            >
              {(content?.catalogBadgeText || '{count} Tools').replace('{count}', String(filteredTools.length))}
            </span>
          </h2>
          <p
            className="text-xs md:text-base text-theme-secondary font-medium"
            style={content?.catalogSubtitleColor ? { color: content.catalogSubtitleColor } : undefined}
          >
            {content?.catalogSubtitle || 'Akses berbagai AI tools premium dengan satu langganan.'}
          </p>
        </div>

        <div className="flex items-center gap-3 w-full lg:w-auto">
          {/* View Mode Toggle */}
          <div className="flex items-center gap-1 p-1 glass rounded-xl border border-white/10">
            <button
              onClick={() => setViewMode('compact')}
              className={`p-2 rounded-lg transition-all ${viewMode === 'compact'
                ? 'bg-indigo-500 text-white shadow-lg'
                : 'text-slate-400 hover:text-white'
                }`}
              title="Compact View"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M4 4h4v4H4V4zm0 6h4v4H4v-4zm0 6h4v4H4v-4zm6-12h4v4h-4V4zm0 6h4v4h-4v-4zm0 6h4v4h-4v-4zm6-12h4v4h-4V4zm0 6h4v4h-4v-4zm0 6h4v4h-4v-4z" />
              </svg>
            </button>
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded-lg transition-all ${viewMode === 'grid'
                ? 'bg-indigo-500 text-white shadow-lg'
                : 'text-slate-400 hover:text-white'
                }`}
              title="Grid View"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M4 4h6v6H4V4zm0 10h6v6H4v-6zm10-10h6v6h-6V4zm0 10h6v6h-6v-6z" />
              </svg>
            </button>
          </div>

          {/* Category Filters */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 flex-1 lg:flex-none no-scrollbar mask-fade-right">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setFilter(cat)}
                className={`px-4 md:px-5 py-1.5 md:py-2 rounded-lg md:rounded-xl text-[10px] md:text-xs font-bold transition-all whitespace-nowrap smooth-animate ${filter === cat
                  ? 'bg-indigo-600 border border-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                  : 'glass-chip text-theme-secondary hover:text-theme-primary'
                  }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Compact Grid View - More columns, smaller cards */}
      {viewMode === 'compact' && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-3 md:gap-4 px-2">
          {filteredTools.map(tool => (
            <CompactToolCard
              key={tool.id}
              tool={tool}
              hasAccess={hasAccessToTool(tool.id)}
            />
          ))}
        </div>
      )}

      {/* Standard Grid View - Original larger cards */}
      {viewMode === 'grid' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 md:gap-6 px-2">
          {filteredTools.map(tool => (
            <ToolCard
              key={tool.id}
              tool={tool}
              hasAccess={hasAccessToTool(tool.id)}
            />
          ))}
        </div>
      )}

      {/* Empty State */}
      {filteredTools.length === 0 && !loading && (
        <div className="text-center py-16">
          <div className="text-6xl mb-4">{content?.emptyStateEmoji || '🔍'}</div>
          <h3 className="text-xl font-bold text-theme-primary mb-2">{content?.emptyStateTitle || 'Tidak ada tools'}</h3>
          <p className="text-theme-secondary text-sm">{content?.emptyStateSubtitle || 'Coba filter lain'}</p>
          <button
            onClick={() => setFilter('Semua')}
            className="mt-4 px-6 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-xl font-bold text-sm transition-all"
          >
            {content?.emptyStateButtonText || 'Lihat Semua'}
          </button>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-3 md:gap-4 px-2">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-slate-800/50 rounded-2xl overflow-hidden animate-pulse">
              <div className="h-32 bg-slate-700/50" />
              <div className="p-4 space-y-3">
                <div className="h-4 bg-slate-700/50 rounded w-3/4" />
                <div className="h-3 bg-slate-700/50 rounded w-full" />
                <div className="h-3 bg-slate-700/50 rounded w-1/2" />
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
};

export default Marketplace;

