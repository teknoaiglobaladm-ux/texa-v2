// Supabase Auth Service - Complete authentication with Supabase
import { supabase } from './supabaseService';
import type { User, Session, AuthChangeEvent } from '@supabase/supabase-js';

// User type matching existing TexaUser structure
export interface TexaUser {
    id: string;
    email: string;
    name?: string;
    photoURL?: string;
    role: 'ADMIN' | 'MEMBER';
    isActive: boolean;
    subscriptionEnd?: string;
    createdAt?: string;
    lastLogin?: string;
}

// Auth state callback type
type AuthCallback = (user: TexaUser | null) => void;

// Convert Supabase user to TexaUser
const mapSupabaseUser = async (user: User | null): Promise<TexaUser | null> => {
    if (!user) return null;

    try {
        // Get user profile from users table
        const { data: profile, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', user.id)
            .single();

        if (error || !profile) {
            // Create default profile if not exists
            return {
                id: user.id,
                email: user.email || '',
                name: user.user_metadata?.full_name || user.email?.split('@')[0] || '',
                photoURL: user.user_metadata?.avatar_url || '',
                role: 'MEMBER',
                isActive: true,
                createdAt: user.created_at,
                lastLogin: new Date().toISOString()
            };
        }

        return {
            id: profile.id,
            email: profile.email || user.email || '',
            name: profile.name || user.user_metadata?.full_name || '',
            photoURL: profile.photo_url || user.user_metadata?.avatar_url || '',
            role: profile.role || 'MEMBER',
            isActive: profile.is_active ?? true,
            subscriptionEnd: profile.subscription_end,
            createdAt: profile.created_at,
            lastLogin: profile.last_login || new Date().toISOString()
        };
    } catch (error) {
        console.error('Error mapping Supabase user:', error);
        return {
            id: user.id,
            email: user.email || '',
            name: user.user_metadata?.full_name || '',
            photoURL: user.user_metadata?.avatar_url || '',
            role: 'MEMBER',
            isActive: true
        };
    }
};

// Sign up with email and password
export const signUp = async (email: string, password: string, name?: string): Promise<{ user: TexaUser | null; error: string | null }> => {
    try {
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    full_name: name || email.split('@')[0]
                }
            }
        });

        if (error) {
            return { user: null, error: error.message };
        }

        if (data.user) {
            // Create user profile in users table
            await supabase.from('users').upsert({
                id: data.user.id,
                email: data.user.email,
                name: name || email.split('@')[0],
                role: 'MEMBER',
                is_active: true,
                created_at: new Date().toISOString(),
                last_login: new Date().toISOString()
            });

            const texaUser = await mapSupabaseUser(data.user);
            return { user: texaUser, error: null };
        }

        return { user: null, error: 'Sign up failed' };
    } catch (error: any) {
        return { user: null, error: error.message || 'Sign up failed' };
    }
};

// Sign in with email and password
export const signIn = async (email: string, password: string): Promise<{ user: TexaUser | null; error: string | null }> => {
    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (error) {
            return { user: null, error: error.message };
        }

        if (data.user) {
            // Update last login
            await supabase.from('users').update({
                last_login: new Date().toISOString()
            }).eq('id', data.user.id);

            const texaUser = await mapSupabaseUser(data.user);
            return { user: texaUser, error: null };
        }

        return { user: null, error: 'Sign in failed' };
    } catch (error: any) {
        return { user: null, error: error.message || 'Sign in failed' };
    }
};

// Sign in with Google OAuth
export const signInWithGoogle = async (): Promise<{ error: string | null }> => {
    try {
        const { error } = await supabase.auth.signInWithOAuth({
            provider: 'google',
            options: {
                redirectTo: window.location.origin
            }
        });

        if (error) {
            return { error: error.message };
        }

        return { error: null };
    } catch (error: any) {
        return { error: error.message || 'Google sign in failed' };
    }
};

// Sign out
export const signOut = async (): Promise<{ error: string | null }> => {
    try {
        const { error } = await supabase.auth.signOut();
        if (error) {
            return { error: error.message };
        }
        return { error: null };
    } catch (error: any) {
        return { error: error.message || 'Sign out failed' };
    }
};

// Get current session
export const getSession = async (): Promise<Session | null> => {
    try {
        const { data: { session } } = await supabase.auth.getSession();
        return session;
    } catch (error) {
        console.error('Error getting session:', error);
        return null;
    }
};

// Get current user
export const getCurrentUser = async (): Promise<TexaUser | null> => {
    try {
        const { data: { user } } = await supabase.auth.getUser();
        return await mapSupabaseUser(user);
    } catch (error) {
        console.error('Error getting current user:', error);
        return null;
    }
};

// Listen to auth state changes
export const onAuthChange = (callback: AuthCallback): (() => void) => {
    // Get initial user
    getCurrentUser().then(user => {
        callback(user);
    });

    // Subscribe to auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
        async (event: AuthChangeEvent, session: Session | null) => {
            if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
                const user = await mapSupabaseUser(session?.user || null);

                // Ensure user profile exists
                if (session?.user) {
                    await supabase.from('users').upsert({
                        id: session.user.id,
                        email: session.user.email,
                        name: session.user.user_metadata?.full_name || session.user.email?.split('@')[0],
                        photo_url: session.user.user_metadata?.avatar_url,
                        last_login: new Date().toISOString()
                    }, { onConflict: 'id' });
                }

                callback(user);
            } else if (event === 'SIGNED_OUT') {
                callback(null);
            }
        }
    );

    return () => {
        subscription.unsubscribe();
    };
};

// Update user profile
export const updateUserProfile = async (userId: string, updates: Partial<TexaUser>): Promise<boolean> => {
    try {
        const updateData: any = {};
        if (updates.name !== undefined) updateData.name = updates.name;
        if (updates.photoURL !== undefined) updateData.photo_url = updates.photoURL;
        if (updates.role !== undefined) updateData.role = updates.role;
        if (updates.isActive !== undefined) updateData.is_active = updates.isActive;
        if (updates.subscriptionEnd !== undefined) updateData.subscription_end = updates.subscriptionEnd;

        const { error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', userId);

        if (error) {
            console.error('Error updating user profile:', error);
            return false;
        }
        return true;
    } catch (error) {
        console.error('Error updating user profile:', error);
        return false;
    }
};

// Check if user is admin
export const isAdmin = async (userId: string): Promise<boolean> => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('role')
            .eq('id', userId)
            .single();

        if (error || !data) return false;
        return data.role === 'ADMIN';
    } catch (error) {
        return false;
    }
};

// Get user by ID
export const getUserById = async (userId: string): Promise<TexaUser | null> => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (error || !data) return null;

        return {
            id: data.id,
            email: data.email,
            name: data.name,
            photoURL: data.photo_url,
            role: data.role || 'MEMBER',
            isActive: data.is_active ?? true,
            subscriptionEnd: data.subscription_end,
            createdAt: data.created_at,
            lastLogin: data.last_login
        };
    } catch (error) {
        console.error('Error getting user by ID:', error);
        return null;
    }
};

// Export for compatibility
export { supabase };
