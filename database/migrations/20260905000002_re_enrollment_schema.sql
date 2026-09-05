-- ====================================================================
-- CyberV Device-Binding Security Protocol: Migration 000002
-- Re-enrollment Requests, Atomic State Promotion & Decision Matrix
-- Ref: Pipeline.md Section 22-24, Rule.md Điều 8, 15, 17
-- ====================================================================

-- 1. Bảng Yêu Cầu Tái Cấp Quyền Thiết Bị (re_enrollment_requests)
CREATE TABLE IF NOT EXISTS public.re_enrollment_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL REFERENCES public.devices(device_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    previous_state_hash VARCHAR(128) NOT NULL,
    new_state_hash VARCHAR(128) NOT NULL,
    new_graph_hash VARCHAR(128) NOT NULL,
    new_graph_version INT NOT NULL,
    new_graph_json JSONB NOT NULL,
    risk_score INT NOT NULL,                        -- Điểm số nguyên 0 - 10000 (0.00% - 100.00%)
    risk_level VARCHAR(20) NOT NULL,                -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    decision VARCHAR(32) NOT NULL,                  -- 'TRUSTED', 'AUTO_PROMOTE', 'REQUIRES_USER_APPROVAL', 'REJECTED'
    reason TEXT,
    proof_signature VARCHAR(128) NOT NULL,          -- Chữ ký Ed25519 (128 ký tự hex)
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',  -- 'PENDING', 'APPROVED', 'REJECTED'
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    CONSTRAINT chk_reenroll_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    CONSTRAINT chk_reenroll_risk_level CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_reenroll_decision CHECK (decision IN ('TRUSTED', 'AUTO_PROMOTE', 'REQUIRES_USER_APPROVAL', 'REJECTED'))
);

-- Index tra cứu yêu cầu re-enrollment
CREATE INDEX IF NOT EXISTS idx_reenroll_device_id ON public.re_enrollment_requests(device_id);
CREATE INDEX IF NOT EXISTS idx_reenroll_user_id ON public.re_enrollment_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_reenroll_status ON public.re_enrollment_requests(status);

-- ====================================================================
-- PHÂN QUYỀN GRANTS (LỚP BẢO VỆ 1 - Rule.md Điều 8)
-- ====================================================================
-- Khóa toàn quyền ghi đối với Client anon và authenticated
REVOKE INSERT, UPDATE, DELETE ON public.re_enrollment_requests FROM anon, authenticated;
GRANT SELECT ON public.re_enrollment_requests TO authenticated;

-- ====================================================================
-- ROW LEVEL SECURITY (LỚP BẢO VỆ 2 - Rule.md Điều 8)
-- ====================================================================
ALTER TABLE public.re_enrollment_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can only view own re-enrollment requests"
    ON public.re_enrollment_requests FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- ====================================================================
-- HÀM RPC NGUYÊN TỬ CHUYỂN ĐỔI TRẠNG THÁI THIẾT BỊ
-- promote_device_state_atomic (Rule.md Điều 15, 17)
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
BEGIN
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
