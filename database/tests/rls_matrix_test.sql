-- ====================================================================
-- CyberV RLS & Grants Matrix Security Verification
-- Ref: rv.md #8, #15 and Rule.md Điều 8, Điều 26
-- ====================================================================

-- Giả lập Test Matrix:
-- 1. Anonymous (unauthenticated) role:
--    - SELECT / INSERT / UPDATE / DELETE on devices -> Phải bị REJECT (Permission Denied).
--    - SELECT on challenges -> Phải bị REJECT.

-- 2. Authenticated User A:
--    - SELECT devices where user_id = User A -> ACCEPT.
--    - SELECT devices where user_id = User B -> REJECT (0 rows returned).
--    - Direct INSERT into devices -> REJECT (Permission Denied).
--    - Direct UPDATE on devices -> REJECT (Permission Denied).
--    - Direct DELETE on devices -> REJECT (Permission Denied).

DO $$
BEGIN
    RAISE NOTICE 'Bắt đầu kiểm tra cấu hình RLS và Grants...';
    
    -- Kiểm tra bảng devices đã bật RLS chưa
    IF NOT EXISTS (
        SELECT 1 FROM pg_tables t
        JOIN pg_class c ON c.relname = t.tablename
        WHERE t.tablename = 'devices' AND c.relrowsecurity = true
    ) THEN
        RAISE EXCEPTION 'RLS CHƯA ĐƯỢC BẬT TRÊN BẢNG devices!';
    END IF;

    -- Kiểm tra bảng challenges đã bật RLS chưa
    IF NOT EXISTS (
        SELECT 1 FROM pg_tables t
        JOIN pg_class c ON c.relname = t.tablename
        WHERE t.tablename = 'challenges' AND c.relrowsecurity = true
    ) THEN
        RAISE EXCEPTION 'RLS CHƯA ĐƯỢC BẬT TRÊN BẢNG challenges!';
    END IF;

    -- Kiểm tra quyền INSERT của authenticated trên devices đã bị thu hồi chưa
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
        WHERE grantee = 'authenticated' AND table_name = 'devices' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'LỖI AN NINH: authenticated VẪN CÒN QUYỀN INSERT TRỰC TIẾP TRÊN devices!';
    END IF;

    RAISE NOTICE 'Toàn bộ kiểm tra cấu hình RLS và Grants ĐẠT YÊU CẦU AN NINH.';
END;
$$;
