-- Seed policy set. These are the rules the demo argues about.
OPEN SCHEMA AIRLOCK;

DELETE FROM POLICY;

-- 1. Agents may never read raw customer contact details, at any aggregation.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, TARGET_TABLE, TARGET_COLUMN, NOTE)
VALUES ('no-raw-pii-phone', 'COLUMN_ACCESS', 'DENY', 'TPCH', 'CUSTOMER', 'C_PHONE',
        'Direct contact details are never exposed to an autonomous agent.');

INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, TARGET_TABLE, TARGET_COLUMN, NOTE)
VALUES ('no-raw-pii-addr', 'COLUMN_ACCESS', 'DENY', 'TPCH', 'CUSTOMER', 'C_ADDRESS',
        'Direct contact details are never exposed to an autonomous agent.');

-- 2. k-anonymity: account balance readable only in aggregates over >= 20 rows.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, TARGET_TABLE, TARGET_COLUMN, THRESHOLD, NOTE)
VALUES ('acctbal-k-anon', 'MIN_AGGREGATION', 'DENY', 'TPCH', 'CUSTOMER', 'C_ACCTBAL', 20,
        'Balance is aggregate-only; groups smaller than k=20 can re-identify individuals.');

-- 3. Blast radius: no single agent statement may modify more than 500 rows.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, THRESHOLD, NOTE)
VALUES ('write-blast-radius', 'BLAST_RADIUS', 'REQUIRE_APPROVAL', 500,
        'Measured, not estimated: we count the affected rows before executing.');

-- 4. Scope: this agent principal is confined to the ENERGY schema.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, PRINCIPAL, NOTE)
VALUES ('energy-agent-scope', 'SCHEMA_SCOPE', 'ALLOW', 'ENERGY', 'energy-analyst',
        'Least privilege: the energy agent has no business reading retail customers.');

-- 5. Tainted rows never leave the airlock.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, THRESHOLD, NOTE)
VALUES ('block-tainted-rows', 'TAINT_BLOCK', 'DENY', 0.7,
        'Result sets containing prompt-injection payloads are withheld.');

-- 6. The airlock's own schema is never reachable by the traffic it governs.
INSERT INTO POLICY (NAME, RULE_KIND, EFFECT, TARGET_SCHEMA, NOTE)
VALUES ('protect-airlock', 'SCHEMA_DENY', 'DENY', 'AIRLOCK',
        'An agent must not be able to edit the policies or erase the ledger that bind it.');

COMMIT;
