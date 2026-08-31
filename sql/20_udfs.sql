-- In-database logic. Requires: exasol slc install python3
OPEN SCHEMA AIRLOCK;

-------------------------------------------------------------------------------
-- LEDGER_VERIFY: walks the hash chain in sequence order and recomputes every
-- entry hash. Emits only the rows where the chain is broken. Runs where the
-- data lives -- the ledger never leaves the database to be audited.
-------------------------------------------------------------------------------
CREATE OR REPLACE PYTHON3 SET SCRIPT LEDGER_VERIFY(
    SEQ DECIMAL(18,0),
    SESSION_ID VARCHAR(64),
    TS VARCHAR(64),
    STATEMENT VARCHAR(2000000),
    DECISION VARCHAR(20),
    PREV_HASH CHAR(64),
    ENTRY_HASH CHAR(64)
) EMITS (BAD_SEQ DECIMAL(18,0), PROBLEM VARCHAR(200), EXPECTED CHAR(64), FOUND CHAR(64)) AS
import hashlib

GENESIS = '0' * 64

def entry_hash(seq, session_id, ts, statement, decision, prev_hash):
    payload = '|'.join([
        str(int(seq)), session_id or '', ts or '',
        statement or '', decision or '', prev_hash or '',
    ])
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

def run(ctx):
    expected_prev = GENESIS
    while True:
        # chain linkage
        if (ctx.PREV_HASH or '') != expected_prev:
            ctx.emit(ctx.SEQ, 'prev_hash does not match preceding entry',
                     expected_prev, ctx.PREV_HASH)
        # content integrity
        recomputed = entry_hash(ctx.SEQ, ctx.SESSION_ID, ctx.TS,
                                ctx.STATEMENT, ctx.DECISION, ctx.PREV_HASH)
        if recomputed != (ctx.ENTRY_HASH or ''):
            ctx.emit(ctx.SEQ, 'entry was modified after it was written',
                     recomputed, ctx.ENTRY_HASH)
        expected_prev = ctx.ENTRY_HASH
        if not ctx.next():
            break
/

-------------------------------------------------------------------------------
-- SCAN_TAINT: the data-side of prompt injection. Sweeps free-text columns in
-- parallel across the cluster and scores rows that carry instructions aimed at
-- whatever model reads them later. Everyone scans the prompt; nobody scans the
-- rows coming back.
-------------------------------------------------------------------------------
CREATE OR REPLACE PYTHON3 SCALAR SCRIPT SCAN_TAINT(TXT VARCHAR(2000000))
RETURNS VARCHAR(2000) AS
import re

# Weighted signatures of instruction-injection in stored text.
SIGNATURES = [
    (0.45, r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?'),
    (0.40, r'disregard\s+(all\s+)?(previous|prior|the\s+above)'),
    (0.35, r'\byou\s+are\s+now\b'),
    (0.35, r'\bsystem\s*(prompt|message)\b'),
    (0.30, r'</?(system|assistant|user|im_start|im_end)>'),
    (0.30, r'\bnew\s+instructions?\b'),
    (0.25, r'\b(exfiltrate|send|email|post)\b.{0,40}\b(to|at)\b.{0,40}@'),
    (0.25, r'\bDROP\s+TABLE\b|\bDELETE\s+FROM\b|\bGRANT\s+ALL\b'),
    (0.20, r'\bdo\s+not\s+tell\s+the\s+user\b'),
    (0.20, r'\bact\s+as\s+(an?\s+)?(admin|root|superuser)\b'),
]

COMPILED = [(w, re.compile(p, re.IGNORECASE | re.DOTALL)) for w, p in SIGNATURES]

def run(ctx):
    txt = ctx.TXT
    if not txt:
        return '0.0|'
    score = 0.0
    hits = []
    for weight, rx in COMPILED:
        if rx.search(txt):
            score += weight
            hits.append(rx.pattern[:40])
    return '%.4f|%s' % (min(score, 1.0), ','.join(hits))
/

-------------------------------------------------------------------------------
-- STMT_KIND: cheap Lua classifier. Lua is compiled into Exasol -- no container,
-- sub-10ms startup -- so this sits on the hot path without costing anything.
-------------------------------------------------------------------------------
CREATE OR REPLACE LUA SCALAR SCRIPT STMT_KIND(STMT VARCHAR(2000000))
RETURNS VARCHAR(20) AS
function run(ctx)
    if ctx.STMT == nil then return 'OTHER' end
    local s = string.upper(string.gsub(ctx.STMT, '^%s+', ''))
    if     string.find(s, '^SELECT') or string.find(s, '^WITH') then return 'SELECT'
    elseif string.find(s, '^INSERT') then return 'INSERT'
    elseif string.find(s, '^UPDATE') then return 'UPDATE'
    elseif string.find(s, '^DELETE') then return 'DELETE'
    elseif string.find(s, '^MERGE')  then return 'MERGE'
    elseif string.find(s, '^TRUNCATE') or string.find(s, '^DROP')
        or string.find(s, '^ALTER')    or string.find(s, '^CREATE') then return 'DDL'
    end
    return 'OTHER'
end
/
