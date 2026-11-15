-- FortiGate deliveries name their connection in the URL; before the token is checked the workspace is not known.
-- Returns the one active FortiGate connection with that id (its workspace and sealed secret), nothing else —
-- the same bounded lookup GitHub deliveries use (0014), because integration_connections is under row-level security.
CREATE OR REPLACE FUNCTION legion_fortigate_connection(p_id uuid)
RETURNS TABLE (id uuid, tenant_id uuid, secrets_enc text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT id, tenant_id, secrets_enc FROM integration_connections WHERE id = p_id AND kind = 'fortigate' AND status = 'active'
$$;
