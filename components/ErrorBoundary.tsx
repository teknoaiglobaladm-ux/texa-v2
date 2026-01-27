// ErrorBoundary Component - Catches React errors and displays fallback UI
import React, { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
    children: ReactNode;
    fallback?: ReactNode;
}

interface ErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return { hasError: true, error };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }

            return (
                <div className="min-h-[50vh] flex items-center justify-center">
                    <div className="text-center glass rounded-3xl p-8 border border-white/10 max-w-md mx-4">
                        <div className="text-6xl mb-4">⚠️</div>
                        <h2 className="text-xl font-bold text-white mb-2">Oops! Ada yang salah</h2>
                        <p className="text-slate-400 text-sm mb-4">
                            Terjadi kesalahan saat memuat konten. Silakan refresh halaman.
                        </p>
                        <button
                            onClick={() => window.location.reload()}
                            className="px-6 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-bold text-sm transition-all"
                        >
                            🔄 Refresh Halaman
                        </button>
                        {this.state.error && (
                            <details className="mt-4 text-left">
                                <summary className="text-xs text-slate-500 cursor-pointer">Detail Error</summary>
                                <pre className="mt-2 p-2 bg-black/30 rounded text-xs text-red-400 overflow-auto max-h-32">
                                    {this.state.error.message}
                                </pre>
                            </details>
                        )}
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
