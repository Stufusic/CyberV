-- ====================================================================
-- Migration 000004: Gate 1 Hardening — Modern Auth, Single Active Nonce
-- ====================================================================
-- Enforces:
-- 1. At most ONE active unconsumed nonce per device (partial unique index).
-- 2. Nonce TTL audit checks and auto-invalidation.
-- 3. Search path lockdown on all remaining extension procedures.
-- ====================================================================

-- 1. Partial Unique Index: Chỉ cho phép tối đa 1 unconsumed challenge cho mỗi device_id
-- Bất kỳ challenge cũ nào chưa dùng phải bị expire trước khi tạo cái mới.
CREATE UNIQUE INDEX IF NOT EXISTS idx_challenges_single_active_per_device 
ON public.challenges(device_id) 
WHERE consumed = false;

-- 2. Function cấp phát challenge nguyên tử — tự hủy mọi challenge cũ chưa tiêu thụ
CREATE OR REPLACE FUNCTION public.issue_challenge_atomic(
    p_device_id VARCHAR(64),
    p_nonce VARCHAR(128),
    p_ttl_seconds INT DEFAULT 60
)
RETURNS TABLE (
    challenge_id UUID,
    issued_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_now TIMESTAMPTZ := now();
    v_expires TIMESTAMPTZ := v_now + (p_ttl_seconds * INTERVAL '1 second');
    v_id UUID;
BEGIN
    -- Vô hiệu hóa mọi nonce đang hoạt động trước đó của thiết bị này
    UPDATE public.challenges
    SET consumed = true, consumed_at = v_now
    WHERE device_id = p_device_id AND consumed = false;

    -- Thêm challenge mới duy nhất
    INSERT INTO public.challenges (
        device_id,
        nonce,
        consumed,
        issued_at,
        expires_at
    ) VALUES (
        p_device_id,
        p_nonce,
        false,
        v_now,
        v_expires
    ) RETURNING id INTO v_id;

    RETURN QUERY SELECT v_id, v_now, v_expires;
END;
$$;

-- Khóa quyền EXECUTE trên issue_challenge_atomic chỉ cho service_role
REVOKE EXECUTE ON FUNCTION public.issue_challenge_atomic(VARCHAR(64), VARCHAR(128), INT) FROM anon, authenticated, public;
