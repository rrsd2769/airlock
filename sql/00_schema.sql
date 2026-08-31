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
