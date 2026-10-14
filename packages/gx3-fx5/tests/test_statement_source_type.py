"""Raw Statement storage and literal stars remain separate source facts."""
import unittest
import hashlib
import tempfile
from pathlib import Path
from gx3_fx5_profile.decoder import MiningRequired, _decode_lddb, _decode_mil
from gx3_fx5_parser_toolkit.ir import build_neutral_ir
from test_installed_semantics import synthetic_gx3


class StatementSourceTypeTests(unittest.TestCase):
    def test_mil_and_lddb_preserve_body_and_raw_type_independently(self):
        for body in ("plain", "*literal", "**literal", "[Title] text", "\uc900\ube44 * \uc644\ub8cc"):
            for raw_type in ("i", "s"):
                for lane in ("mil", "lddb"):
                    with self.subTest(body=body, raw_type=raw_type, lane=lane):
                        raw = (f"V1:1:1:1:{body}:{raw_type}:ms{{el=[ma{{k=@BE/ST}}]}}" if lane == "mil" else
                               f"V1:1:{len(body)}:{body}:st{{st=c{{t=#:st={raw_type}}}:dim=0x1}}")
                        rows = _decode_mil(raw, 1) if lane == "mil" else _decode_lddb(raw, 1, 1)
                        row, = rows
                        self.assertEqual(body, row["statement_body"])
                        self.assertEqual(raw_type, row["statement_raw_st"])
                        self.assertEqual(("*" if raw_type == "s" else "") + body, row["text"])

    def test_unknown_type_length_and_row_count_remain_closed(self):
        for raw in ("V1:1:4:text:st{st=c{t=#:st=x}:dim=0x1}",
                    "V1:1:3:text:st{st=c{t=#:st=i}:dim=0x1}"):
            with self.assertRaises(MiningRequired):
                _decode_lddb(raw, 1, 1)
        with self.assertRaises(MiningRequired):
            _decode_mil("V1:1:1:1:text:i:ms{el=[ma{k=@BE/ST}]}", 2)

    def test_neutral_ir_binds_raw_type_and_exact_body_digest(self):
        for body in ("plain", "*literal", "**literal", "[Title] text", "준비 * 완료"):
            for raw_type in ("i", "s"):
                with self.subTest(body=body, raw_type=raw_type), tempfile.TemporaryDirectory() as directory:
                    source = Path(directory) / "statement.gx3"
                    synthetic_gx3(source, mil_mov=True, mil_source=
                                  f"V1:1:1:1:{body}:{raw_type}:ms{{el=[ma{{k=@BE/ST}}]}}")
                    value = build_neutral_ir(source)
                    record, = value["pous"][0]["records"]
                    self.assertEqual("statement", record["kind"])
                    self.assertEqual(("*" if raw_type == "s" else "") + body, record["text"])
                    evidence = record["provenance"]["relation_evidence"]
                    self.assertIn(f"statement_raw_st={raw_type}", evidence)
                    self.assertIn("statement_body_sha256=" + hashlib.sha256(body.encode("utf-8")).hexdigest(), evidence)
                    self.assertEqual({"total": 1, "decoded": 1, "partial": 0, "unknown": 0}, value["coverage"]["record"])


if __name__ == "__main__":
    unittest.main()
