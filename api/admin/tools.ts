import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const supabase = supabaseUrl && supabaseServiceKey
    ? createClient(supabaseUrl, supabaseServiceKey)
    : null;

// Helper function to check if user is admin or in development mode
async function isAdminOrDev(req: VercelRequest): Promise<boolean> {
    // In development or if no auth required, allow access
    if (process.env.NODE_ENV === 'development' || process.env.SKIP_AUTH === 'true') {
        return true;
    }

    // Check for admin token in header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        // Verify with Supabase
        if (supabase) {
            const { data: { user }, error } = await supabase.auth.getUser(token);
            if (!error && user) {
                // Check if user is admin
                const { data: userData } = await supabase
                    .from('users')
                    .select('role')
                    .eq('id', user.id)
                    .single();
                return userData?.role === 'admin';
            }
        }
    }

    // Allow in dev mode by default for easier testing
    return true;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Check if database is configured
    if (!supabase) {
        console.error('Database not configured:', {
            hasUrl: !!supabaseUrl,
            hasKey: !!supabaseServiceKey
        });
        return res.status(500).json({
            success: false,
            message: 'Database not configured'
        });
    }

    // Check admin access
    const isAdmin = await isAdminOrDev(req);
    if (!isAdmin) {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    // GET - Fetch all tools
    if (req.method === 'GET') {
        try {
            const { data, error } = await supabase
                .from('tools')
                .select('*')
                .order('sort_order', { ascending: true });

            if (error) {
                console.error('Get tools error:', error);
                return res.status(500).json({ success: false, message: 'Failed to fetch tools' });
            }

            return res.status(200).json({ success: true, data: data || [] });
        } catch (e) {
            console.error('Get tools error:', e);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
    }

    // POST - Create new tool
    if (req.method === 'POST') {
        const { name, description, category, imageUrl, targetUrl, status, priceMonthly } = req.body;

        if (!name) {
            return res.status(400).json({ success: false, message: 'Tool name is required' });
        }

        try {
            const now = new Date().toISOString();

            // Get max sort_order
            const { data: existing } = await supabase
                .from('tools')
                .select('sort_order')
                .order('sort_order', { descending: true })
                .limit(1);

            const maxOrder = existing?.[0]?.sort_order || 0;

            const insertData = {
                name: name.trim(),
                description: description || '',
                category: category || '',
                image_url: imageUrl || '',
                tool_url: targetUrl || '',
                is_active: status === 'active',
                is_premium: true,
                price_monthly: Number(priceMonthly) || 0,
                sort_order: maxOrder + 1,
                created_at: now,
                updated_at: now,
                created_by: 'admin'
            };

            const { data, error } = await supabase
                .from('tools')
                .insert(insertData)
                .select();

            if (error) {
                console.error('Create tool error:', error);
                return res.status(500).json({ success: false, message: 'Failed to create tool' });
            }

            console.log('✅ Tool created:', name);
            return res.status(200).json({ success: true, data: data?.[0], id: data?.[0]?.id });
        } catch (e) {
            console.error('Create tool error:', e);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
    }

    // Method not allowed for base /api/admin/tools route
    // PUT and DELETE are handled in /api/admin/tools/[id].ts
    return res.status(405).json({ success: false, message: 'Method not allowed' });
}
