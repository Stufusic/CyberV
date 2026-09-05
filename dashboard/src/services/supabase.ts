import { createClient, SupabaseClient } from '@supabase/supabase-js';

// Environment variables can be provided via .env.local or window globals
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isLiveConfigured = (): boolean => {
  return Boolean(supabaseUrl && supabaseAnonKey && supabaseUrl.startsWith('http'));
};

export const supabase: SupabaseClient | null = isLiveConfigured()
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;
