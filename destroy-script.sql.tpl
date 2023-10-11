DO $do$
DECLARE
  each_schema text;
  affected_schema text := '${affected_schema}';
  affected_sequences text := '${affected_sequences}';
  granted_privileges text := '${granted_privileges}';
BEGIN
  IF ${make_admin_own} THEN
    GRANT "${db_owner}" TO "${admin_user}";
    RAISE NOTICE 'DB owner role granted to admin user.';
  END IF;

  IF affected_schema = 'ALL' THEN
    FOR each_schema IN SELECT nspname FROM pg_namespace where nspname != 'pg_toast' 
      and nspname != 'pg_statistic' 
      and nspname != 'pg_catalog' 
      and nspname != 'information_schema'
    LOOP
      EXECUTE FORMAT('REVOKE %s ON ALL SEQUENCES IN SCHEMA "%s" FROM "${group_role}"', granted_privileges, each_schema);
      RAISE NOTICE '% privileges were granted on all sequences in %.', granted_privileges, each_schema;
    END LOOP;
  ELSEIF affected_sequences = 'ALL' THEN
    EXECUTE FORMAT('REVOKE %s ON ALL SEQUENCES IN SCHEMA "%s" FROM "${group_role}"', granted_privileges, affected_schema);
    RAISE NOTICE '% privileges were granted on all sequences in %.', granted_privileges, affected_schema;
  ELSE
    EXECUTE FORMAT('REVOKE %s ON %s FROM "${group_role}"', granted_privileges, affected_sequences);
    RAISE NOTICE '% privileges were granted on sequences %.', granted_privileges, affected_sequences;
  END IF;

  IF ${make_admin_own} THEN
    REVOKE "${db_owner}" FROM "${admin_user}";
    RAISE NOTICE 'DB owner role revoked from admin user.';
  END IF;
END
$do$;
