import React, { useEffect, useMemo, useState } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { TexaUser } from '../services/firebase';
import { getCatalogItem, CatalogItem } from '../services/supabaseCatalogService';
import { isUrlIframeAllowed } from '../utils/iframePolicy';

const hasActiveSubscription = (user: TexaUser | null) => {
  if (!user?.subscriptionEnd) return false;
  return new Date(user.subscriptionEnd) > new Date();
};

const ToolIframePage: React.FC<{ user: TexaUser | null }> = ({ user }) => {
  const { toolId } = useParams();
  const [tool, setTool] = useState<CatalogItem | null>(null);
  const [loading, setLoading] = useState(true);

  const allowed = useMemo(() => hasActiveSubscription(user), [user]);

  useEffect(() => {
    let stopped = false;
    const run = async () => {
      if (!toolId) return;
      setLoading(true);
      const found = await getCatalogItem(toolId);
      if (stopped) return;
      setTool(found);
      setLoading(false);
    };
    void run();
    return () => {
      stopped = true;
    };
  }, [toolId]);

  if (!user) return <Navigate to="/login" replace />;
  if (!allowed) return <Navigate to="/" replace />;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-slate-400">Memuat tool...</p>
        </div>
      </div>
    );
  }

  if (!tool) {
    return (
      <div className="max-w-3xl mx-auto py-10">
        <div className="glass rounded-2xl border border-white/10 p-8 text-center">
          <div className="text-5xl mb-3">📭</div>
          <h1 className="text-2xl font-black text-white mb-2">Tool tidak ditemukan</h1>
          <a href="#/" className="inline-flex mt-4 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold">
            Kembali
          </a>
        </div>
      </div>
    );
  }

  const iframeOk = tool.openMode === 'iframe' && isUrlIframeAllowed(tool.targetUrl);
  if (!iframeOk) return <Navigate to="/" replace />;

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl premium-gradient flex items-center justify-center text-white font-black">
            T
          </div>
          <div>
            <div className="text-white font-black leading-tight">{tool.name}</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a href="#/" className="px-4 py-2 rounded-xl text-xs font-black glass border border-white/10 text-white hover:border-indigo-500/50 transition-all">
            ← Kembali
          </a>
        </div>
      </div>

      <iframe
        title={tool.name}
        src={tool.targetUrl}
        className="w-full h-[86vh] rounded-2xl border border-white/10 bg-white"
      />
    </div>
  );
};

export default ToolIframePage;
