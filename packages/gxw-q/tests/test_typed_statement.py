"""Synthetic source Statement carriers keep body, type and width distinct."""
import unittest
import gxw_ladder_reader as reader


def frame(body, subtype, encoding="cp1252"):
    payload = body.encode(encoding)
    length = len(payload) + 4
    raw_type = 1 if subtype == "s" else (length + 1) // 2
    return bytes((length, 0x80, raw_type)) + payload + bytes((length,))


class TypedStatementTests(unittest.TestCase):
    def test_raw_type_is_independent_of_literal_body_stars(self):
        for body in ("plain", "*literal", "**literal", "[Title] * middle"):
            for subtype in ("i", "s"):
                with self.subTest(body=body, subtype=subtype):
                    raw = frame(body, subtype) + b"\x04\x34\x02\x04"
                    item, = reader.typed_statement_records(raw)
                    self.assertEqual(body, item["text"])
                    self.assertEqual(subtype, item["subtype"])
                    self.assertEqual(body.encode().hex(), item["raw_text_hex"])
                    self.assertEqual(1 if subtype == "s" else (len(body) + 5) // 2, item["source_step_width"])
                    self.assertEqual(("__STMT__", ("*" if subtype == "s" else "") + body, ""), reader.pou_rows(raw)[0][0])

    def test_korean_reversible_decoding_and_note_are_separate(self):
        raw = frame("준비 * 완료", "s", "cp949") + b"\x04\x34\x02\x04"
        item, = reader.typed_statement_records(raw, text_encoding="cp949")
        self.assertEqual("준비 * 완료", item["text"])
        self.assertEqual([], reader.typed_note_records(raw, text_encoding="cp949"))

    def test_unknown_raw_type_or_damaged_frame_never_becomes_typed(self):
        valid = frame("same body", "i")
        for damaged in (valid[:2] + b"\x02" + valid[3:], valid[:-1] + b"\x00"):
            with self.subTest(raw=damaged.hex()):
                rows, unknown, _ = reader.pou_rows(damaged + b"\x04\x34\x02\x04")
                self.assertTrue(unknown or not any(row[0] == "__STMT__" for row in rows))
                if unknown:
                    with self.assertRaises(ValueError):
                        reader.typed_statement_records(damaged + b"\x04\x34\x02\x04")

    def test_note_payload_is_one_carrier_even_when_it_contains_statement_shape(self):
        inner = b"\x41\x80\x21" + b"A" * 61 + b"\x41"
        note = b"\x45\x82\x23" + inner + b"\x45"
        end = b"\x04\x34\x02\x04"
        self.assertEqual([], reader.typed_statement_records(note + end))
        rows = reader.pou_rows(note + end)[0]
        self.assertEqual(["__NOTE__", "END"], [row[0] for row in rows])
        statement = frame("actual body", "s")
        item, = reader.typed_statement_records(statement + note + end)
        self.assertEqual("actual body", item["text"])
        self.assertEqual("s", item["subtype"])


if __name__ == "__main__":
    unittest.main()
