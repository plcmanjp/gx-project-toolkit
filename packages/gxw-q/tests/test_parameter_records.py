"""Synthetic byte grammar checks; no proprietary project fixtures."""
import struct
import unittest

import gxw_parameter_records as P


def record(tag, payload):
    return struct.pack("<HH", len(payload) + 4, tag) + payload


HEADER = record(0x122, bytes(range(60)))
OPAQUE = record(0x7777, b"\xff\xff\x00\x81")
END = record(0xfe00, b"\x28\x00") + b"\xff\xff"
BASE = HEADER + OPAQUE + END


class ParameterRecordsTests(unittest.TestCase):
    def test_lossless_unknowns_and_duplicate_opaque_tags(self):
        body = HEADER + OPAQUE * 2 + END
        self.assertEqual(body, P.encode_records(P.decode_records(body)))

    def test_label_insertion_has_independent_expected_bytes(self):
        for label, encoded in [("ABCDE", b"\x05ABCDE"), ("ABCDEF", b"\x06ABCDEF\xff"),
                               ("ABCDEFGH", b"\x08ABCDEFGH\xff")]:
            with self.subTest(label=label):
                expected = HEADER + record(0, encoded) + OPAQUE + END
                self.assertEqual(expected, P.replace_ascii_label(BASE, label))
                self.assertEqual({"label": label, "comment": ""}, P.decode_ascii_names(expected))

    def test_replace_remove_preserves_comment_and_opaque(self):
        comment = record(1, b"\x03XYZ")
        original = HEADER + record(0, b"\x03ABC") + comment + OPAQUE + END
        self.assertEqual(HEADER + comment + OPAQUE + END, P.replace_ascii_label(original, ""))
        self.assertEqual(HEADER + record(0, b"\x03DEF") + comment + OPAQUE + END,
                         P.replace_ascii_label(original, "DEF"))
        self.assertEqual(original, P.replace_ascii_label(original, "ABC"))

    def test_all_truncated_prefixes_fail(self):
        for length in range(len(BASE)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                P.decode_records(BASE[:length])

    def test_invalid_framing_and_limits(self):
        for body in [BASE + b"x", b"\xff\xff", b"\x00\x00\x00\x00\xff\xff",
                     b"\x05\x00\x00\x00x\xff\xff", b"x" * (P.MAX_BYTES + 1),
                     record(8, b"") * (P.MAX_RECORDS + 1) + b"\xff\xff"]:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                P.decode_records(body)
        for records in [(), (P.Record(True, b""),), (P.Record(-1, b""),),
                        (P.Record(0, b"x"),), (P.Record(0, bytearray()),),
                        (P.Record(0, bytes(65532)),),
                        (P.Record(0, bytes(1024)),) * 1024]:
            with self.subTest(count=len(records)), self.assertRaises(ValueError):
                P.encode_records(records)

    def test_text_ambiguity_and_encoding_fail_closed(self):
        for middle in [record(0, b"\x03ABC") * 2,
                       record(1, b"\x03XYZ") + record(0, b"\x03ABC"),
                       OPAQUE + record(0, b"\x03ABC"),
                       record(0, b"\x02AB\x00"), record(0, b"\x03A\x80C"),
                       record(0, b"\x00\xff"), record(0, b"\x09ABCDEFGHI")]:
            with self.subTest(middle=middle), self.assertRaises(ValueError):
                P.replace_ascii_label(HEADER + middle + END, "ABC")
        for label in ["123456789", "A B", "é", "A\n", None]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                P.replace_ascii_label(BASE, label)

    def test_signature_is_required_but_framing_is_generic(self):
        body = OPAQUE + END
        self.assertEqual(body, P.encode_records(P.decode_records(body)))
        with self.assertRaises(ValueError):
            P.decode_ascii_names(body)


if __name__ == "__main__":
    unittest.main()
