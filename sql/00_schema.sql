-- AIRLOCK core schema
-- Every object an agent's statement touches on its way through the airlock.
-- Run with: exasol connect -f sql/00_schema.sql

CREATE SCHEMA IF NOT EXISTS AIRLOCK;
OPEN SCHEMA AIRLOCK;

-------------------------------------------------------------------------------
-- POLICY: declarative rules. The decision engine is a SQL query over this
-- table, not a model call -- deterministic, versioned, and replayable.
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE POLICY (
    POLICY_ID       DECIMAL(18,0) IDENTITY,
    NAME            VARCHAR(200)   NOT NULL,
    VERSION         DECIMAL(9,0)   DEFAULT 1 NOT NULL,
    IS_ENABLED      BOOLEAN        DEFAULT TRUE NOT NULL,
    -- COLUMN_ACCESS | MIN_AGGREGATION | BLAST_RADIUS | SCHEMA_SCOPE | TAINT_BLOCK
    RULE_KIND       VARCHAR(40)    NOT NULL,
    EFFECT          VARCHAR(20)    NOT NULL,   -- ALLOW | DENY | REQUIRE_APPROVAL
    TARGET_SCHEMA   VARCHAR(128),              -- NULL = any
    TARGET_TABLE    VARCHAR(128),
    TARGET_COLUMN   VARCHAR(128),
    PRINCIPAL       VARCHAR(128),              -- NULL = all agents
    THRESHOLD       DECIMAL(18,4),             -- k for k-anonymity, row cap, taint score
    NOTE            VARCHAR(2000),
    CREATED_AT      TIMESTAMP      DEFAULT CURRENT_TIMESTAMP
);

-------------------------------------------------------------------------------
-- AGENT_SESSION: who is on the other side of the airlock.
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE AGENT_SESSION (
    SESSION_ID      VARCHAR(64)    PRIMARY KEY,
    AGENT_NAME      VARCHAR(200),
    PRINCIPAL       VARCHAR(128),
    CLIENT_INFO     VARCHAR(2000),
    -- Exasol's own session id, from SELECT CURRENT_SESSION. SESSION_ID above is
    -- AIRLOCK's uuid and means nothing to the database; this is what lets the
    -- bypass monitor ask of a live connection "did we let this one in?".
    EXA_SESSION_ID  VARCHAR(64),
    STARTED_AT      TIMESTAMP      DEFAULT CURRENT_TIMESTAMP
);

-------------------------------------------------------------------------------
-- LEDGER: hash-chained, append-only record of every decision.
-- ENTRY_HASH = sha256(SEQ || SESSION_ID || TS || STMT_TEXT || DECISION || PREV_HASH)
-- Any edit to a historical row breaks every hash after it.
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE LEDGER (
    SEQ                 DECIMAL(18,0)  NOT NULL PRIMARY KEY,
    SESSION_ID          VARCHAR(64),
    TS                  TIMESTAMP      NOT NULL,
    PRINCIPAL           VARCHAR(128),
    STMT_KIND           VARCHAR(20),          -- SELECT | UPDATE | DELETE | INSERT | DDL | OTHER
    STMT_TEXT           VARCHAR(2000000),
    FEATURES            VARCHAR(2000000),     -- JSON: tables, columns, joins, aggregates
    DECISION            VARCHAR(20)    NOT NULL,  -- ALLOW | DENY | REQUIRE_APPROVAL
    MATCHED_POLICIES    VARCHAR(2000),        -- csv of POLICY_ID
    REASON              VARCHAR(4000),
    EST_ROWS            DECIMAL(18,0),        -- measured blast radius, not an estimate
    MIN_GROUP           DECIMAL(18,0),        -- measured smallest group, not an estimate
    ROLLBACK_SQL        VARCHAR(2000000),     -- compensating statement for writes
    TAINT_MAX           DECIMAL(9,4),
    LATENCY_MS          DECIMAL(12,3),
    PREV_HASH           CHAR(64),
    ENTRY_HASH          CHAR(64)       NOT NULL
);

-------------------------------------------------------------------------------
-- APPROVAL: the queue of held statements waiting on a human.
--
-- REQUIRE_APPROVAL was a verdict with nowhere to go. A row here is raised by
-- the gateway the moment a statement is held, and an approval releases it back
-- through the gateway rather than executing it directly -- so the released run
-- gets its own policy pass, its own pre-image capture and its own ledger entry.
--
-- LEDGER_SEQ points at the entry that was held and RESULT_SEQ at the entry of
-- the release. Two entries, never one edited: the held record is what the hash
-- chain is protecting, and rewriting it to say ALLOW would make the chain worth
-- nothing.
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE APPROVAL (
    APPROVAL_ID     DECIMAL(18,0)  IDENTITY,
    LEDGER_SEQ      DECIMAL(18,0)  NOT NULL,   -- the entry that was held
    -- Not STATE: that is a reserved word in Exasol and the CREATE is a
    -- syntax error, not a quoted-identifier column.
    APPROVAL_STATE  VARCHAR(20)    NOT NULL,   -- PENDING | APPROVED | REJECTED
    -- SYSTIMESTAMP, not CURRENT_TIMESTAMP: the ledger stamps its entries in UTC
    -- and the drawer shows a hold's queue row beside the entry that raised it.
    -- On a session with an offset, the same event reads two hours apart.
    REQUESTED_AT    TIMESTAMP      DEFAULT SYSTIMESTAMP,
    DECIDED_BY      VARCHAR(128),
    DECIDED_AT      TIMESTAMP,
    NOTE            VARCHAR(2000),
    RESULT_SEQ      DECIMAL(18,0)              -- the ledger entry of the release
);

-------------------------------------------------------------------------------
-- TAINT: rows in the warehouse that carry embedded instructions.
-- Populated by a parallel Python SET UDF sweep (see sql/20_udfs.sql).
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE TAINT (
    SCHEMA_NAME     VARCHAR(128),
    TABLE_NAME      VARCHAR(128),
    COLUMN_NAME     VARCHAR(128),
    ROW_KEY         VARCHAR(256),
    SCORE           DECIMAL(9,4),
    PATTERNS        VARCHAR(2000),
    SAMPLE          VARCHAR(4000),
    SCANNED_AT      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-------------------------------------------------------------------------------
-- REPLAY_RESULT: output of replaying the ledger against a changed policy set.
-------------------------------------------------------------------------------
CREATE OR REPLACE TABLE REPLAY_RESULT (
    REPLAY_ID       VARCHAR(64),
    SEQ             DECIMAL(18,0),
    OLD_DECISION    VARCHAR(20),
    NEW_DECISION    VARCHAR(20),
    CHANGED         BOOLEAN,
    NEW_REASON      VARCHAR(4000),
    REPLAYED_AT     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
