-- Seed initial admin organization and user
-- Default credentials: admin@example.com / Admin123!@#ChangeMe

-- These will be created by the application on first startup if not already present.
-- This seed file is a fallback for direct database initialization.

DO $$
DECLARE
    v_org_id UUID;
    v_user_id UUID;
BEGIN
    -- Only seed if no organizations exist
    IF NOT EXISTS (SELECT 1 FROM organizations LIMIT 1) THEN
        v_org_id := gen_random_uuid();

        INSERT INTO organizations (id, name, settings)
        VALUES (v_org_id, 'Default Organization', '{"defaultRole": "viewer", "mfaRequired": false}'::jsonb);

        v_user_id := gen_random_uuid();

        -- Password: Admin123!@#ChangeMe (bcrypt hash with cost 14)
        INSERT INTO users (id, org_id, email, password_hash, name, role, created_at, updated_at)
        VALUES (
            v_user_id,
            v_org_id,
            'admin@example.com',
            '$2b$14$InitialHashWillBeReplacedByApplicationOnFirstBoot',
            'System Administrator',
            'super_admin',
            NOW(),
            NOW()
        );

        RAISE NOTICE 'Default organization and admin user seeded. Change the password on first login.';
    ELSE
        RAISE NOTICE 'Organizations already exist, skipping seed.';
    END IF;
END $$;
