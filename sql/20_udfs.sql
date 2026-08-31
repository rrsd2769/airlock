-- In-database logic for AIRLOCK.
--
-- Deliberately free of any script language container. Ledger verification is
-- pure SQL (Exasol's native HASH_SHA256 plus a LAG window), and the two scripts
-- are Lua, which is compiled into Exasol itself. Nothing here needs a download,
-- and Lua's sub-10ms startup keeps the governance path cheap enough to sit in
-- front of every statement.

OPEN SCHEMA AIRLOCK;

-------------------------------------------------------------------------------
-- LEDGER_CHECK: recompute every entry hash and every chain link, in SQL.
-- Must stay byte-identical to airlock.ledger.entry_hash in Python.
-------------------------------------------------------------------------------
CREATE OR REPLACE VIEW LEDGER_CHECK AS
SELECT
    SEQ,
    SESSION_ID,
    DECISION,
    PREV_HASH,
    ENTRY_HASH,
    NVL(LAG(ENTRY_HASH) OVER (ORDER BY SEQ),
        '0000000000000000000000000000000000000000000000000000000000000000'
    ) AS EXPECTED_PREV,
    LOWER(TO_CHAR(HASH_SHA256(
        SEQ
        || '|' || NVL(SESSION_ID, '')
        || '|' || TO_CHAR(TS, 'YYYY-MM-DD HH24:MI:SS.FF6')
        || '|' || NVL(STMT_TEXT, '')
        || '|' || NVL(DECISION, '')
        || '|' || NVL(PREV_HASH, '')
    ))) AS RECOMPUTED
FROM LEDGER;

-------------------------------------------------------------------------------
-- LEDGER_BREAKS: the audit result. Empty means the trail is intact.
-- Editing one historical row surfaces here twice: the row itself no longer
-- matches its own hash, and the row after it no longer links back.
-------------------------------------------------------------------------------
CREATE OR REPLACE VIEW LEDGER_BREAKS AS
SELECT SEQ,
       'entry was modified after it was written' AS PROBLEM,
       RECOMPUTED AS EXPECTED,
       ENTRY_HASH AS FOUND_HASH
FROM LEDGER_CHECK
WHERE ENTRY_HASH <> RECOMPUTED
UNION ALL
SELECT SEQ,
       'prev_hash does not match the preceding entry' AS PROBLEM,
       EXPECTED_PREV AS EXPECTED,
       PREV_HASH AS FOUND_HASH
FROM LEDGER_CHECK
WHERE PREV_HASH <> EXPECTED_PREV;

-------------------------------------------------------------------------------
-- SCAN_TAINT: the data side of prompt injection. Everyone scans the prompt;
-- almost nobody scans the rows coming back. Returns "score|matched signatures".
-------------------------------------------------------------------------------
CREATE OR REPLACE LUA SCALAR SCRIPT SCAN_TAINT(TXT VARCHAR(2000000))
RETURNS VARCHAR(2000) AS
local SIGNATURES = {
    {0.45, 'ignore previous instructions'},
    {0.45, 'ignore all previous instructions'},
    {0.40, 'disregard previous'},
    {0.40, 'disregard all previous'},
    {0.35, 'you are now'},
    {0.35, 'system prompt'},
    {0.30, 'new instructions'},
    {0.30, '<|im_start|>'},
    {0.30, '</system>'},
    {0.25, 'drop table'},
    {0.25, 'delete from'},
    {0.25, 'grant all'},
    {0.20, 'do not tell the user'},
    {0.20, 'act as admin'},
}

function run(ctx)
    if ctx.TXT == nil then return '0.0|' end
    local hay = string.lower(ctx.TXT)
    local score = 0.0
    local hits = {}
    for i = 1, #SIGNATURES do
        local weight, needle = SIGNATURES[i][1], SIGNATURES[i][2]
        if string.find(hay, needle, 1, true) ~= nil then
            score = score + weight
            table.insert(hits, needle)
        end
    end
    if score > 1.0 then score = 1.0 end
    return string.format('%.4f|%s', score, table.concat(hits, ','))
end
/

-------------------------------------------------------------------------------
-- STMT_KIND: cheap statement classifier on the hot path.
-------------------------------------------------------------------------------
CREATE OR REPLACE LUA SCALAR SCRIPT STMT_KIND(STMT VARCHAR(2000000))
RETURNS VARCHAR(20) AS
function run(ctx)
    if ctx.STMT == nil then return 'OTHER' end
    local s = string.upper(string.gsub(ctx.STMT, '^%s+', ''))
    if     string.find(s, '^SELECT') or string.find(s, '^WITH') then return 'SELECT'
    elseif string.find(s, '^INSERT')   then return 'INSERT'
    elseif string.find(s, '^UPDATE')   then return 'UPDATE'
    elseif string.find(s, '^DELETE')   then return 'DELETE'
    elseif string.find(s, '^MERGE')    then return 'MERGE'
    elseif string.find(s, '^TRUNCATE') or string.find(s, '^DROP')
        or string.find(s, '^ALTER')    or string.find(s, '^CREATE') then return 'DDL'
    end
    return 'OTHER'
end
/
