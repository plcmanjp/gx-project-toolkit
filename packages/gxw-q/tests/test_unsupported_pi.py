"""Unimplemented P/I text cannot disappear into a complete source analysis."""
import unittest

import gxw_ladder_reader as reader


END = b"\x04\x34\x02\x04"


def pi_frame(payload, raw_type=None):
    length = len(payload) + 4
    return bytes((length, 0x81, raw_type if raw_type is not None else (length + 1) // 2)) + payload + bytes((length,))


class UnsupportedPITests(unittest.TestCase):
    def test_separate_carrier_is_unknown_for_every_raw_type(self):
        for raw_type in (1, 9, 0xff):
            raw = pi_frame(b"PI body * text", raw_type) + END
            rows, unknown_i, unknown_d = reader.pou_rows(raw)
            self.assertEqual(["<i:text:pi>", "END"], [row[0] for row in rows])
            self.assertEqual({"<i:text:pi>"}, unknown_i)
            self.assertEqual(set(), unknown_d)
            self.assertEqual([], reader.typed_statement_records(raw))
            self.assertEqual([], reader.typed_note_records(raw, framed_types=True))

    def test_payload_is_not_scanned_as_instructions_notes_or_statements(self):
        statement = b"\x05\x80\x01A\x05"
        note = b"\x05\x82\x01B\x05"
        raw = pi_frame(statement + note + END) + END + b"trailer"
        self.assertEqual(raw[:-7], reader.program_section(raw))
        rows, unknown_i, _ = reader.pou_rows(raw)
        self.assertEqual(["<i:text:pi>", "END"], [row[0] for row in rows])
        self.assertEqual({"<i:text:pi>"}, unknown_i)
        self.assertEqual([], reader.typed_statement_records(raw))
        self.assertEqual([], reader.typed_note_records(raw, framed_types=True))

    def test_damaged_carrier_after_known_instruction_still_blocks(self):
        carrier = pi_frame(b"body")[:-1] + b"\x00"
        rows, unknown_i, _ = reader.pou_rows(b"\x02\x02" + carrier + END)
        self.assertIn("<i:text:pi>", unknown_i)
        self.assertEqual(["NOP", "<i:text:pi>", "END"], [row[0] for row in rows])

    def test_ambiguous_damaged_pi_boundary_is_rejected(self):
        damaged = bytearray(pi_frame(END))
        damaged[-1] = 0
        with self.assertRaisesRegex(ValueError, "ambiguous program section boundary"):
            reader.program_section(bytes(damaged) + END)

    def test_leading_damaged_pi_never_restarts_inside_its_body(self):
        contact = bytes.fromhex("03000304900004")
        for payload in (b"body", b"\x05\x80\x01A\x05", b"\x05\x82\x01B\x05"):
            carrier = pi_frame(payload)[:-1] + b"\x00"
            raw = carrier + contact + END
            rows, unknown_i, _ = reader.pou_rows(raw)
            self.assertEqual(["<i:text:pi>", "LD", "END"], [row[0] for row in rows])
            self.assertEqual({"<i:text:pi>"}, unknown_i)
            for method in (reader.typed_statement_records, reader.typed_note_records):
                try:
                    self.assertEqual([], method(raw))
                except ValueError:
                    pass  # A damaged inventory may refuse the typed view entirely.

    def test_leading_truncated_pi_is_unknown_without_body_rescan(self):
        raw = pi_frame(b"\x05\x80\x01A\x05")[:-1]
        rows, unknown_i, _ = reader.pou_rows(raw)
        self.assertEqual(["<i:text:pi>"], [row[0] for row in rows])
        self.assertEqual({"<i:text:pi>"}, unknown_i)


if __name__ == "__main__":
    unittest.main()
