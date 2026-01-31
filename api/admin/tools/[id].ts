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
    if (process.env.NODE_ENV === 'development' || process.env.SKIP_AUTH === 'true') {
        return true;
    }

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        if (supabase) {
            const { data: { user }, error } = await supabase.auth.getUser(token);
            if (!error && user) {
                const { data: userData } = await supabase
                    .from('users')
                    .select('role')
                    .eq('id', user.id)
                    .single();
                return userData?.role === 'admin';
            }
        }
    }

    return true;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (!supabase) {
        return res.status(500).json({ success: false, message: 'Database not configured' });
    }

    const isAdmin = await isAdminOrDev(req);
    if (!isAdmin) {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    // Get tool ID from URL
    const { id } = req.query;
    if (!id || typeof id !== 'string') {
        return res.status(400).json({ success: false, message: 'Tool ID is required' });
    }

    // PUT - Update tool
    if (req.method === 'PUT') {
        const body = req.body;
        const updateData: Record<string, any> = {
            updated_at: new Date().toISOString()
        };

        if (body.name !== undefined) updateData.name = body.name.trim();
        if (body.description !== undefined) updateData.description = body.description;
        if (body.category !== undefined) updateData.category = body.category;
        if (body.imageUrl !== undefined) updateData.image_url = body.imageUrl;
        if (body.targetUrl !== undefined) updateData.tool_url = body.targetUrl;
        if (body.status !== undefined) updateData.is_active = body.status === 'active';
        if (body.priceMonthly !== undefined) updateData.price_monthly = Number(body.priceMonthly) || 0;
        if (body.order !== undefined) updateData.sort_order = Number(body.order) || 0;
        // Multi-tier pricing fields
        if (body.price7Days !== undefined) updateData.price_7_days = Number(body.price7Days) || 0;
        if (body.price14Days !== undefined) updateData.price_14_days = Number(body.price14Days) || 0;
        if (body.price30Days !== undefined) updateData.price_30_days = Number(body.price30Days) || 0;

        try {
            const { error } = await supabase
                .from('tools')
                .update(updateData)
                .eq('id', id);

            if (error) {
                console.error('Update tool error:', error);
                return res.status(500).json({ success: false, message: 'Failed to update tool' });
            }

            console.log('✅ Tool updated:', id);
            return res.status(200).json({ success: true });
        } catch (e) {
            console.error('Update tool error:', e);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
    }

    // DELETE - Delete tool
    if (req.method === 'DELETE') {
        try {
            const { error } = await supabase
                .from('tools')
                .delete()
                .eq('id', id);

            if (error) {
                console.error('Delete tool error:', error);
                return res.status(500).json({ success: false, message: 'Failed to delete tool' });
            }

            console.log('✅ Tool deleted:', id);
            return res.status(200).json({ success: true });
        } catch (e) {
            console.error('Delete tool error:', e);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
    }

    return res.status(405).json({ success: false, message: 'Method not allowed' });
}
