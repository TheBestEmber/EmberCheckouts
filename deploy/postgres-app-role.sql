-- Least-privilege grants for the EmberCheckouts API role. Run as the schema
-- owner after the migrations. The role itself is created in the database console.
--   psql "$OWNER_DATABASE_URL" -v ON_ERROR_STOP=1 -f deploy/postgres-app-role.sql

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ember_checkouts_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ember_checkouts_app;
GRANT USAGE ON SCHEMA public TO ember_checkouts_app;

GRANT SELECT, INSERT, UPDATE ON checkouts TO ember_checkouts_app;
GRANT SELECT, INSERT ON checkout_events TO ember_checkouts_app;
GRANT USAGE, SELECT ON SEQUENCE checkout_events_id_seq TO ember_checkouts_app;
