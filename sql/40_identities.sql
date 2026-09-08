-- AIRLOCK identities: the privilege boundary.
--
-- Until this file existed, AIRLOCK ran as `sys`. That made one of its own
-- policies circular: `protect-airlock` says an agent must not edit the rules or
-- erase the ledger that bind it, but it was enforced only by the thing it
-- protects. A superuser gateway asks the database for nothing it could not
-- simply take.
--
-- These three identities move that enforcement into Exasol, where it holds
-- whether or not AIRLOCK's own code is correct:
--
--   AIRLOCK_SVC       the gateway. Reads the rules, appends to the ledger, and
--                     can do neither the other way round. Owns the snapshot
--                     schema so pre-image capture works without giving it any
--                     rights over AIRLOCK itself.
--   AIRLOCK_CONSOLE   the read-only observer behind the console API. Selects
--                     from everything, writes to nothing.
--   DEMO_AGENT        the agent's own database identity. Reaches the policy-
--                     derived safe views and nothing else -- so an agent that
--                     connects *around* the airlock is refused by Exasol rather
--                     than by us.
--
-- It constrains and detects. It does not make bypass impossible for someone
-- holding sys credentials; see the bypass monitor in the console for that half.
--
-- Run as sys, after 00_schema, 20_udfs and 10_policies:
--   uv run python scripts/apply_sql.py sql/40_identities.sql
--   uv run python -m airlock.identities --apply     -- the safe views
--
-- Re-running this drops and recreates the users. AIRLOCK_SVC owns AIRLOCK_SNAP,
-- so CASCADE takes the pre-image snapshots with it. That is correct for a
-- bootstrap and wrong in the middle of a demo.

-------------------------------------------------------------------------------
-- Passwords. Local-only demo defaults, matching config.py, so a fresh clone
-- works with no .env. Override AIRLOCK_PASSWORD / AIRLOCK_CONSOLE_PASSWORD /
-- AIRLOCK_DEMO_AGENT_PASSWORD and edit the three literals below together.
-- Exasol requires double quotes here; single quotes are a syntax error.
-------------------------------------------------------------------------------

DROP USER IF EXISTS AIRLOCK_SVC CASCADE;
DROP USER IF EXISTS AIRLOCK_CONSOLE CASCADE;
DROP USER IF EXISTS DEMO_AGENT CASCADE;

-------------------------------------------------------------------------------
-- The snapshot schema.
--
-- Pre-image capture creates a table per allowed write. Exasol has no object
-- privilege for creating a table inside someone else's schema short of CREATE
-- ANY TABLE, and making the gateway the owner of AIRLOCK would hand it the
-- power to drop the ledger. So snapshots get their own schema, owned by the
-- gateway, and AIRLOCK stays owned by sys.
-------------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS AIRLOCK_SNAP;

-------------------------------------------------------------------------------
-- 1. AIRLOCK_SVC -- the gateway
-------------------------------------------------------------------------------

CREATE USER AIRLOCK_SVC IDENTIFIED BY "airlock-svc";
GRANT CREATE SESSION TO AIRLOCK_SVC;
GRANT CREATE TABLE TO AIRLOCK_SVC;
ALTER SCHEMA AIRLOCK_SNAP CHANGE OWNER AIRLOCK_SVC;

-- The rule set is readable and nothing more. An agent that talks the gateway
-- into running DDL against AIRLOCK.POLICY gets an insufficient-privileges error
-- from Exasol, not a rewritten rule.
GRANT SELECT ON AIRLOCK.POLICY TO AIRLOCK_SVC;

-- The ledger is append-only at the privilege level, not just by convention.
-- No UPDATE, no DELETE, no DROP: the hash chain detects tampering, and this
-- makes the tampering impossible to attempt from the gateway in the first place.
GRANT SELECT, INSERT ON AIRLOCK.LEDGER TO AIRLOCK_SVC;

-- A view needs its own grant; SELECT on the table underneath does not reach it.
GRANT SELECT ON AIRLOCK.LEDGER_CHECK TO AIRLOCK_SVC;
GRANT SELECT ON AIRLOCK.LEDGER_BREAKS TO AIRLOCK_SVC;

GRANT SELECT, INSERT ON AIRLOCK.AGENT_SESSION TO AIRLOCK_SVC;
GRANT SELECT, INSERT, DELETE ON AIRLOCK.TAINT TO AIRLOCK_SVC;
GRANT SELECT, INSERT ON AIRLOCK.REPLAY_RESULT TO AIRLOCK_SVC;

-- A script needs an explicit EXECUTE grant. SCAN_TAINT is on the hot path --
-- preflight builds every taint probe around it -- so without this each scan
-- fails and each scanned statement is held at TAINT_UNMEASURED.
GRANT EXECUTE ON SCRIPT AIRLOCK.SCAN_TAINT TO AIRLOCK_SVC;

-- The governed data. The gateway needs SELECT on every table it governs, and
-- not only to serve queries: SYS.EXA_ALL_COLUMNS is privilege-filtered, so a
-- table the gateway cannot select from is a table whose text columns it cannot
-- see -- and a taint scan over columns it cannot see silently finds nothing.
-- Column-level protection comes from the policy engine and the safe views, not
-- from withholding these.
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.CUSTOMER TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.LINEITEM TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.NATION   TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.ORDERS   TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.PART     TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.PARTSUPP TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.REGION   TO AIRLOCK_SVC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TPCH.SUPPLIER TO AIRLOCK_SVC;

-------------------------------------------------------------------------------
-- 2. AIRLOCK_CONSOLE -- the read-only observer
--
-- Deliberately NOT granted SELECT ANY DICTIONARY. SYS.EXA_ALL_SESSIONS is
-- readable by any user, so the bypass monitor needs no dictionary privilege --
-- and the console should not hold one it does not need.
-------------------------------------------------------------------------------

CREATE USER AIRLOCK_CONSOLE IDENTIFIED BY "airlock-console";
GRANT CREATE SESSION TO AIRLOCK_CONSOLE;
GRANT SELECT ON SCHEMA AIRLOCK TO AIRLOCK_CONSOLE;
GRANT SELECT ON SCHEMA AIRLOCK_SNAP TO AIRLOCK_CONSOLE;

-------------------------------------------------------------------------------
-- 3. DEMO_AGENT -- the agent's own identity
--
-- This is the one to run on camera. Connected directly, bypassing the gateway
-- entirely, it is refused on TPCH.CUSTOMER, on AIRLOCK.LEDGER and on
-- AIRLOCK.POLICY -- by Exasol, with no AIRLOCK code in the path.
--
-- Its SELECT grants on the safe views are issued by `airlock.identities`, which
-- derives both the views and the grants from the COLUMN_ACCESS rules in
-- AIRLOCK.POLICY. There is no second column list to keep in step here.
-------------------------------------------------------------------------------

CREATE USER DEMO_AGENT IDENTIFIED BY "demo-agent";
GRANT CREATE SESSION TO DEMO_AGENT;

COMMIT;
