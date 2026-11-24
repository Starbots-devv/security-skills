CREATE TABLE tenant_objects (id text PRIMARY KEY, tenant text NOT NULL, value text NOT NULL);
INSERT INTO tenant_objects VALUES ('a','a','A'), ('a2','a','A2'), ('b','b','B');
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_objects TO {role_a}, {role_b}, {role_service};
-- Deliberate negative fixture: grants exist, but RLS is absent.
