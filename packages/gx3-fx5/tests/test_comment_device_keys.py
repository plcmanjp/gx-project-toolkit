"""Synthetic numeric comment keys and unregistered storage variants."""
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from gx3_fx5_profile.decoder import _device_id, decode_comments


class CommentDeviceKeyTests(unittest.TestCase):
    def test_f_comment_uses_decimal_ordinal_and_preserves_boundaries(self):
        for value in (0, 9, 10, 15, 16, 126, 127):
            self.assertEqual(f"F{value}", _device_id((1, 4, 0, 0, 0, 0, value, 0)))
        self.assertEqual("M10", _device_id((1, 1, 0, 0, 0, 0, 10, 0)))
        self.assertEqual("X12", _device_id((1, 16, 0, 0, 0, 0, 10, 0)))

    def test_f_extensions_word_bit_and_high_word_are_not_inferred(self):
        for row in ((1, 4, 1, 0, 0, 0, 0, 0), (1, 4, 0, 1, 0, 0, 0, 0),
                    (1, 4, 0, 0, 0, 1, 0, 0), (1, 4, 0, 0, 0, 0, -1, 0),
                    (1, 4, 0, 0, 0, 0, 0, 1), (1, 400, 0, 0, 0, 0, 0, 0)):
            with self.subTest(row=row):
                self.assertIsNone(_device_id(row))

    def test_comment_text_slot_scope_and_unknown_are_all_retained(self):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE DEVICE_DATA(SEQ,DevCode,ExtCode,ExtNo,IsLocal,DevNoHigh,DevNoLow,BitNo)")
        connection.execute("CREATE TABLE COMMENT_DATA(SEQ,DeviceSEQ,CmtNo,CmtData,DelFlag)")
        connection.executemany("INSERT INTO DEVICE_DATA VALUES(?,?,?,?,?,?,?,?)",
                               [(1,4,0,0,0,0,0,0), (2,4,0,0,0,0,127,0), (3,400,0,0,0,0,1,0)])
        connection.executemany("INSERT INTO COMMENT_DATA VALUES(?,?,?,?,?)",
                               [(1,1,6,"synthetic low",None), (2,2,0,"synthetic high",None),
                                (3,3,6,"synthetic unknown",None)])
        archive = SimpleNamespace(entries={"SYN_DC.db": None}, digest=lambda _: "a" * 64)
        with patch("gx3_fx5_profile.decoder._connection", return_value=connection):
            comments, findings, coverage = decode_comments(archive)
        self.assertEqual(["F0", "F127"], [c["device_id"] for c in comments[:2]])
        self.assertEqual(["English", "CmtNo:0"], [c["language_slot"] for c in comments[:2]])
        self.assertEqual("synthetic unknown", comments[2]["value"])
        self.assertTrue(comments[2]["device_id"].startswith("UNRESOLVED_DEVICE_"))
        self.assertEqual(dict(total=3, decoded=1, partial=1, unknown=1), coverage)
        self.assertEqual(1, len(findings))


if __name__ == "__main__":
    unittest.main()
