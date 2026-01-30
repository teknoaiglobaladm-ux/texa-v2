
// Re-export TexaUser from Supabase auth service
export type { TexaUser as User } from './services/supabaseAuthService';

// UserRole type definition
export type UserRole = 'ADMIN' | 'MEMBER';

export interface AITool {
  id: string;
  name: string;
  description: string;
  category: string;
  imageUrl: string;
  targetUrl: string;
  openMode?: 'new_tab' | 'iframe';
  status: 'active' | 'inactive';
  priceMonthly: number;
  // New fields for extension integration
  embedVideoUrl?: string;      // URL untuk embedded video (YouTube, dll)
  cookiesData?: string;        // JSON string cookies untuk inject oleh extension
  apiUrl?: string;             // API URL untuk fetch data oleh extension
  // Multi-tier pricing (7 hari, 14 hari, 30 hari)
  price7Days?: number;
  price14Days?: number;
  price30Days?: number;
}

export interface AuthState {
  user: import('./services/supabaseAuthService').TexaUser | null;
  isAuthenticated: boolean;
}

export interface ToolCookie {
  id: string;
  toolId: string;
  data: string; // Encrypted simulation
  lastUpdated: string;
}

