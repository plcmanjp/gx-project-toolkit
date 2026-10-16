"""Dummy string classification is specific to four observed Q socket forms."""
import unittest
import gxw_reference_ir as ref


def project(opcode, text, profile="mitsubishi.gxw.q.ladder"):
    return ref.project_rows([{"name": "MAIN", "source_store": "synthetic", "source_digest": "f" * 64,
                              "rows": [(opcode, text, "")]}], input_sha256="a" * 64,
                            profile_id=profile)["occurrences"][0]["operands"]


class SocketDummyTests(unittest.TestCase):
    def test_exact_context_and_no_device_address(self):
        for opcode, text in (("SP.SOCOPEN", "U0 K7 D1000 M110"),
                             ("SP.SOCCLOSE", "U0 K7 D1500 M140"),
                             ("SP.SOCRCV", "U0 K7 D1300 D1400 M130"),
                             ("SP.SOCSND", "U0 K7 D1100 D1200 M120")):
            with self.subTest(opcode=opcode):
                value = project(opcode, text)[0]
                self.assertEqual(("U0", "literal", "decoded", "SOCKET_DUMMY_LITERAL", None),
                                 (value["raw_token"], value["kind"], value["status"], value["access_basis"], value["device"]))
                self.assertEqual("NOT_APPLICABLE", value["coverage"]["state"])
                self.assertIsNone(value["coverage"]["addresses"])

    def test_unverified_context_stays_unknown(self):
        for opcode, text, index in (("MOV", "U0 D0", 0), ("SP.SOCOPEN", "U1 K7 D1000 M110", 0),
                                    ("SP.SOCOPEN", "U0 K7 D1000", 0),
                                    ("SP.SOCOPEN", "K7 U0 D1000 M110", 1),
                                    ("SP.SOCOPEN", "U0 K7 D1000 M110 M120", 0)):
            with self.subTest(text=text):
                self.assertEqual("unknown", project(opcode, text)[index]["status"])
        self.assertEqual("unknown", ref.parse_operand("U0", 0)["status"])
        self.assertEqual("unknown", project("SP.SOCOPEN", "U0 K7 D1000 M110", "other")[0]["status"])

    def test_other_operands_keep_existing_classification(self):
        result = project("SP.SOCRCV", "U0 K7 D1300Z0 D1400 M130")
        self.assertEqual("DYNAMIC", result[2]["coverage"]["state"])
        self.assertEqual("OPCODE_ACCESS_UNCLASSIFIED", result[2]["access_basis"])


if __name__ == "__main__":
    unittest.main()
