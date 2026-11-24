CREATE TABLE tenant_objects (id text PRIMARY KEY, tenant text NOT NULL, value text NOT NULL);
INSERT INTO tenant_objects VALUES ('a','a','A'), ('a2','a','A2'), ('b','b','B');
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_objects TO {role_a}, {role_b}, {role_service};
ALTER TABLE tenant_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_objects
USING (tenant = current_setting('app.tenant_id', true)
       AND ((current_user = '{role_a}' AND tenant = 'a')
         OR (current_user = '{role_b}' AND tenant = 'b')))
WITH CHECK (tenant = current_setting('app.tenant_id', true)
       AND ((current_user = '{role_a}' AND tenant = 'a')
         OR (current_user = '{role_b}' AND tenant = 'b')));
