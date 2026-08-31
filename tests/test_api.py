"""The console's type coercion. No database needed.

Exasol hands scaled DECIMALs back as strings and scale-0 DECIMALs as ints, so
what reaches the browser has to be normalised on the way out. The trap worth a
test: TAINT.ROW_KEY is a numeric-*looking* string that must survive as a string.
"""
from datetime import UTC, datetime
from decimal import Decimal

from airlock.api import _clean


def test_whole_decimals_become_ints():
    # SEQ and EST_ROWS are counts; "411.0000" in the UI would be wrong.
    assert _clean(Decimal(411)) == 411
    assert isinstance(_clean(Decimal(411)), int)


def test_fractional_decimals_become_floats():
    assert _clean(Decimal("0.7")) == 0.7
    assert isinstance(_clean(Decimal("0.7")), float)


def test_numeric_looking_strings_are_left_alone():
    # ROWID keys arrive as strings and must not be coerced to a number --
    # they exceed float precision and would silently change value.
    key = "92233720368547770049"
    assert _clean(key) == key
    assert isinstance(_clean(key), str)


def test_timestamps_are_serialisable():
    assert _clean(datetime(2026, 8, 31, 17, 22, 57, tzinfo=UTC)).startswith("2026-08-31 17:22:57")


def test_nested_rows_are_cleaned_throughout():
    rows = [{"SEQ": Decimal(1), "SCORE": Decimal("0.85"), "NAME": "acctbal-k-anon"}]
    assert _clean(rows) == [{"SEQ": 1, "SCORE": 0.85, "NAME": "acctbal-k-anon"}]


def test_none_survives():
    assert _clean({"TAINT_MAX": None}) == {"TAINT_MAX": None}
