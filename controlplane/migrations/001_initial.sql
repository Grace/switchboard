-- Run as migration owner, never as the runtime login. Transaction managed by migrate.py.
CREATE ROLE switchboard_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE tenants (id text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE principals (
 id uuid PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id),
 token_hash text NOT NULL UNIQUE CHECK(length(token_hash)=64),
 role text NOT NULL CHECK(role IN ('admin','publisher','viewer','agent')),
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE policies (
 tenant_id text NOT NULL REFERENCES tenants(id), version bigint NOT NULL,
 envelope jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,version)
);
CREATE TABLE telemetry (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 event jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX telemetry_received_at ON telemetry(received_at);
CREATE TABLE audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id text NOT NULL REFERENCES tenants(id), principal_id uuid NOT NULL,
 action text NOT NULL, detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION authenticate(token text) RETURNS TABLE(id uuid,tenant_id text,role text)
 LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
 SELECT p.id,p.tenant_id,p.role FROM public.principals p
 WHERE p.token_hash=token AND NOT p.revoked AND p.expires_at>now()
 $$;
REVOKE ALL ON FUNCTION authenticate(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION authenticate(text) TO switchboard_app;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
ALTER TABLE telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry FORCE ROW LEVEL SECURITY;
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_tenant ON policies USING (tenant_id=current_setting('app.tenant',true)) WITH CHECK (tenant_id=current_setting('app.tenant',true));
CREATE POLICY telemetry_tenant ON telemetry USING (tenant_id=current_setting('app.tenant',true)) WITH CHECK (tenant_id=current_setting('app.tenant',true));
CREATE POLICY audit_tenant ON audit USING (tenant_id=current_setting('app.tenant',true)) WITH CHECK (tenant_id=current_setting('app.tenant',true));
GRANT SELECT,INSERT ON policies,telemetry,audit TO switchboard_app;
GRANT USAGE ON SEQUENCE audit_id_seq TO switchboard_app;
-- Principal writes are restricted to the current tenant and admin role in SQL too.
CREATE FUNCTION add_principal(pid uuid, digest text, new_role text, expiry timestamptz) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 BEGIN
 IF current_setting('app.role',true) IS DISTINCT FROM 'admin' THEN RAISE EXCEPTION 'forbidden'; END IF;
 INSERT INTO public.principals(id,tenant_id,token_hash,role,expires_at)
 VALUES(pid,current_setting('app.tenant'),digest,new_role,expiry);
 END $$;
CREATE FUNCTION revoke_principal(pid uuid) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 BEGIN
 IF current_setting('app.role',true) IS DISTINCT FROM 'admin' THEN RAISE EXCEPTION 'forbidden'; END IF;
 UPDATE public.principals SET revoked=true WHERE id=pid AND tenant_id=current_setting('app.tenant');
 END $$;
REVOKE ALL ON FUNCTION add_principal(uuid,text,text,timestamptz),revoke_principal(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION add_principal(uuid,text,text,timestamptz),revoke_principal(uuid) TO switchboard_app;
