-- ====================================================================
-- CyberV Device-Binding Security Protocol: Migration 000001
-- Initial Schema, Strict Grants & RLS Policies
-- Cryptographic Standard: SHA-512 (NSA CNSA Suite / FIPS 180-4)
-- Ref: rv.md #5, #7, #8, #15 and Rule.md Điều 8, 26
-- ====================================================================

-- 1. Bảng Thiết Bị (devices)
-- Quản lý định danh và trạng thái thiết bị của người dùng
CREATE TABLE IF NOT EXISTS public.devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL UNIQUE,          -- Random UUID v4 CSPRNG
    public_key VARCHAR(128) NOT NULL,               -- Ed25519 Public Key (Hex encoded)
    current_graph_hash VARCHAR(128) NOT NULL,       -- SHA-512 của cấu trúc đồ thị hiện tại (128 hex chars)
    current_state_hash VARCHAR(128) NOT NULL,       -- SHA-512 State Hash (Final Hash) hiện tại (128 hex chars)
    current_graph_version INT NOT NULL DEFAULT 1,   -- Phiên bản đồ thị đơn điệu tăng
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',   -- 'ACTIVE', 'PENDING', 'REVOKED', 'REJECTED'
    risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',  -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_device_status CHECK (status IN ('ACTIVE', 'PENDING', 'REVOKED', 'REJECTED')),
    CONSTRAINT chk_risk_level CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

-- 2. Bảng Lịch Sử Đồ Thị Phần Cứng (device_graphs)
-- Lưu lại các phiên bản đồ thị phần cứng qua từng lần thay linh kiện
CREATE TABLE IF NOT EXISTS public.device_graphs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL REFERENCES public.devices(device_id) ON DELETE CASCADE,
    graph_version INT NOT NULL,
    graph_hash VARCHAR(128) NOT NULL,               -- SHA-512 Graph Hash (128 hex chars)
    canonical_graph_json JSONB NOT NULL,            -- Lưu biểu diễn JSON để hiển thị/debug
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(device_id, graph_version)
);

-- 3. Bảng Linh Kiện Phần Cứng (device_components)
CREATE TABLE IF NOT EXISTS public.device_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    graph_id UUID NOT NULL REFERENCES public.device_graphs(id) ON DELETE CASCADE,
    component_type VARCHAR(32) NOT NULL,            -- 'CPU', 'RAM', 'STORAGE', 'MOTHERBOARD'
    component_hash VARCHAR(128) NOT NULL,           -- SHA-512 Component Hash (128 hex chars)
    schema_version INT NOT NULL DEFAULT 1,
    confidence NUMERIC(3, 2) NOT NULL DEFAULT 1.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. Bảng Thử Thách Xác Thực (challenges)
-- Bảng nội bộ: Chống Replay Attack. Khóa hoàn toàn với client Data API.
CREATE TABLE IF NOT EXISTS public.challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL REFERENCES public.devices(device_id) ON DELETE CASCADE,
    nonce VARCHAR(128) NOT NULL UNIQUE,             -- CSPRNG hex string
    consumed BOOLEAN NOT NULL DEFAULT false,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

-- 5. Bảng Nhật Ký Kiểm Toán An Ninh (device_events)
-- Append-only audit log
CREATE TABLE IF NOT EXISTS public.device_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    event_version INT NOT NULL DEFAULT 1,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ====================================================================
-- INDEXES CHO HIỆU NĂNG VÀ TÌM KIẾM
-- ====================================================================
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON public.devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_device_id ON public.devices(device_id);
CREATE INDEX IF NOT EXISTS idx_challenges_nonce ON public.challenges(nonce);
CREATE INDEX IF NOT EXISTS idx_challenges_device_id ON public.challenges(device_id);
CREATE INDEX IF NOT EXISTS idx_device_events_device_id ON public.device_events(device_id);
CREATE INDEX IF NOT EXISTS idx_device_graphs_device_id ON public.device_graphs(device_id);

-- ====================================================================
-- PHÂN QUYỀN GRANTS (LỚP BẢO VỆ 1 - rv.md #8)
-- ====================================================================
-- Bảng challenges: KHÔNG EXPOSE cho client anon hoặc authenticated
REVOKE ALL ON public.challenges FROM anon, authenticated;

-- Bảng devices: Client chỉ được SELECT hàng của mình, cấm INSERT/UPDATE/DELETE
REVOKE INSERT, UPDATE, DELETE ON public.devices FROM anon, authenticated;
GRANT SELECT ON public.devices TO authenticated;

-- Bảng device_graphs & device_components: Client chỉ được SELECT
REVOKE INSERT, UPDATE, DELETE ON public.device_graphs FROM anon, authenticated;
GRANT SELECT ON public.device_graphs TO authenticated;

REVOKE INSERT, UPDATE, DELETE ON public.device_components FROM anon, authenticated;
GRANT SELECT ON public.device_components TO authenticated;

-- Bảng device_events: Client chỉ được SELECT
REVOKE INSERT, UPDATE, DELETE ON public.device_events FROM anon, authenticated;
GRANT SELECT ON public.device_events TO authenticated;

-- ====================================================================
-- ROW LEVEL SECURITY (LỚP BẢO VỆ 2 - rv.md #8, Rule.md Điều 8, 26)
-- ====================================================================
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_graphs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_events ENABLE ROW LEVEL SECURITY;

-- 1. Devices Policies
CREATE POLICY "Users can only select own devices" 
    ON public.devices FOR SELECT 
    TO authenticated
    USING (auth.uid() = user_id);

-- 2. Device Graphs Policies
CREATE POLICY "Users can view own device graphs"
    ON public.device_graphs FOR SELECT
    TO authenticated
    USING (EXISTS (
        SELECT 1 FROM public.devices 
        WHERE public.devices.device_id = public.device_graphs.device_id 
        AND public.devices.user_id = auth.uid()
    ));

-- 3. Device Components Policies
CREATE POLICY "Users can view own device components"
    ON public.device_components FOR SELECT
    TO authenticated
    USING (EXISTS (
        SELECT 1 FROM public.device_graphs
        JOIN public.devices ON public.devices.device_id = public.device_graphs.device_id
        WHERE public.device_graphs.id = public.device_components.graph_id
        AND public.devices.user_id = auth.uid()
    ));

-- 4. Device Events Policies
CREATE POLICY "Users can view own device events"
    ON public.device_events FOR SELECT
    TO authenticated
    USING (EXISTS (
        SELECT 1 FROM public.devices 
        WHERE public.devices.device_id = public.device_events.device_id 
        AND public.devices.user_id = auth.uid()
    ));

-- ====================================================================
-- STORED PROCEDURES / FUNCTIONS ATOMIC TRANSACTIONS (rv.md #5, #7)
-- ====================================================================

-- Function tiêu thụ Nonce thử thách nguyên tử (Atomic Challenge Consumption)
-- Chống tấn công đua tranh (Race Condition) và DoS challenge
CREATE OR REPLACE FUNCTION public.consume_challenge_atomic(
    p_device_id VARCHAR(64),
    p_nonce VARCHAR(128)
)
RETURNS TABLE (
    success BOOLEAN,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_challenge public.challenges%ROWTYPE;
BEGIN
    -- Khóa bản ghi với FOR UPDATE để chống race condition
    SELECT * INTO v_challenge
    FROM public.challenges
    WHERE device_id = p_device_id AND nonce = p_nonce
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT false, 'CHALLENGE_NOT_FOUND'::TEXT;
        RETURN;
    END IF;

    IF v_challenge.consumed THEN
        RETURN QUERY SELECT false, 'CHALLENGE_ALREADY_CONSUMED'::TEXT;
        RETURN;
    END IF;

    IF v_challenge.expires_at < now() THEN
        RETURN QUERY SELECT false, 'CHALLENGE_EXPIRED'::TEXT;
        RETURN;
    END IF;

    -- Đánh dấu đã tiêu thụ thành công
    UPDATE public.challenges
    SET consumed = true, consumed_at = now()
    WHERE id = v_challenge.id;

    RETURN QUERY SELECT true, NULL::TEXT;
END;
$$;
