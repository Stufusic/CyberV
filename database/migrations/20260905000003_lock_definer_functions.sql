-- ============================================================================
-- CyberV - Stufusic
-- Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
--
-- PROPRIETARY & SOURCE CODE LICENSE NOTICE
-- This software is protected by international copyright laws and treaties.
-- Unauthorized reproduction, reverse engineering, or distribution of this code,
-- or any portion of it, is strictly prohibited without explicit written consent.
--
-- DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
-- THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
-- THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
-- OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
-- ============================================================================
-- ====================================================================
-- Migration 000003: Khóa cổng RPC SECURITY DEFINER (FIX C16 / HIGH)
-- ====================================================================
-- Vấn đề: Supabase mặc định cấp EXECUTE trên public functions cho vai trò
-- anon + authenticated. Cả hai hàm SECURITY DEFINER dưới đây không kiểm tra
-- ownership trong thân hàm, nên BẤT KỲ user đã đăng nhập nào cũng có thể:
--   - promote_device_state_atomic: ghi current_graph_hash/state/version
--     cho thiết bị CỦA NGƯỜI KHÁC (cross-user device-state injection).
--   - consume_challenge_atomic: đốt challenge của người khác (DoS xác thực).
-- Kênh hợp lệ duy nhất là Edge Functions chạy bằng service role
-- (auth.uid() IS NULL). Khóa EXECUTE khỏi client roles.

REVOKE EXECUTE ON FUNCTION public.promote_device_state_atomic(
    VARCHAR(64), VARCHAR(128), VARCHAR(128), INT, JSONB, VARCHAR(20)
) FROM anon, authenticated, public;

REVOKE EXECUTE ON FUNCTION public.consume_challenge_atomic(
    VARCHAR(64), VARCHAR(128)
) FROM anon, authenticated, public;

-- ====================================================================
-- Defense-in-depth: thêm kiểm tra caller vào thân hàm promote (giữ hành vi
-- service role: auth.uid() IS NULL). Nếu Supabase vì lý do nào đó cấp lại
-- EXECUTE cho client roles, hàm vẫn từ chối caller không sở hữu thiết bị.
-- ====================================================================
CREATE OR REPLACE FUNCTION public.promote_device_state_atomic(
    p_device_id VARCHAR(64),
    p_new_graph_hash VARCHAR(128),
    p_new_state_hash VARCHAR(128),
    p_new_graph_version INT,
    p_new_graph_json JSONB,
    p_risk_level VARCHAR(20)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_current_version INT;
    v_device_status VARCHAR(20);
    v_owner_user_id UUID;
BEGIN
    -- 0. Ownership gate: service role (Edge Function) có auth.uid() IS NULL;
    --    mọi JWT client khác PHẢI sở hữu thiết bị.
    SELECT user_id INTO v_owner_user_id
    FROM public.devices
    WHERE device_id = p_device_id;

    IF v_owner_user_id IS NULL THEN
        RAISE EXCEPTION 'Device % not found', p_device_id;
    END IF;

    IF auth.uid() IS NOT NULL AND auth.uid() <> v_owner_user_id THEN
        RAISE EXCEPTION 'Caller does not own device %', p_device_id;
    END IF;

    -- 1. Khóa hàng thiết bị để kiểm soát tương tranh nguyên tử
    SELECT current_graph_version, status
    INTO v_current_version, v_device_status
    FROM public.devices
    WHERE device_id = p_device_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device % not found', p_device_id;
    END IF;

    -- 2. Kiểm tra điều kiện tăng phiên bản đơn điệu nghiêm ngặt (Chống Rollback Attack)
    IF p_new_graph_version <= v_current_version THEN
        RAISE EXCEPTION 'Rollback attack detected: new version % <= current version %',
            p_new_graph_version, v_current_version;
    END IF;

    -- 3. Cập nhật bảng devices sang trạng thái hoạt động mới
    UPDATE public.devices
    SET current_graph_hash = p_new_graph_hash,
        current_state_hash = p_new_state_hash,
        current_graph_version = p_new_graph_version,
        risk_level = p_risk_level,
        status = 'ACTIVE',
        updated_at = now()
    WHERE device_id = p_device_id;

    -- 4. Lưu vết lịch sử đồ thị vào device_graphs (Append-only)
    INSERT INTO public.device_graphs (
        device_id,
        graph_version,
        graph_hash,
        canonical_graph_json,
        created_at
    ) VALUES (
        p_device_id,
        p_new_graph_version,
        p_new_graph_hash,
        p_new_graph_json,
        now()
    );

    RETURN TRUE;
END;
$$;
