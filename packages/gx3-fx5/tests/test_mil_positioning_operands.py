"""Synthetic carriers: source syntax recognition, never target execution proof."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from gx3_fx5_profile.decoder import MiningRequired, _decode_mil, _format_operand
from test_installed_semantics import synthetic_gx3


def carrier(marker, tags, widths, values, *, logic="", kinds=None):
    kinds = kinds or ["d"] * len(values)
    header = ":".join([marker, *tags])
    types = ":".join(f"as{{vt={width}}}" for width in widths)
    operation = f"lct{{op=#:lt={logic}:ct=a:as=[{types}]}}" if logic else f"cl{{op=#:ct=a:as=[{types}]}}"
    args = ":".join(
        f"d{{s=#:a={value}:vt=nn}}" if kind == "d" else f"c{{s=#:v={value}:si=s}}"
        for kind, value in zip(kinds, values)
    )
    return f"V1:1:1:1:{header}:ms{{el=[mc{{op={operation}:as=[{args}]}}]}}"


def positioning(marker="PLSV"):
    if marker == "PLSV":
        return carrier(marker, ["D", "Y", "Y"], ["A32", "Aea", "Abl"], [12, 16, 20])
    return carrier(marker, ["D", "D", "K_1", "M"], ["A32", "A32", "Aea", "Abl"], [12, 24, 3, 40], kinds=["d", "d", "c", "d"])


class PositioningOperandTests(unittest.TestCase):
    def closed(self, data):
        with self.assertRaises(MiningRequired):
            _decode_mil(data, 1)

    def test_double_word_mnemonics_and_values(self):
        for marker, expected in (("PLSV", ["D12", "Y10", "Y14"]), ("DSZR", ["D12", "D24", "K3", "M40"]), ("DRVA", ["D12", "D24", "K3", "M40"])):
            with self.subTest(marker=marker):
                row = _decode_mil(positioning(marker), 1)[0]
                self.assertEqual((row["opcode"], row["operands"]), ("D" + marker, expected))

    def test_positioning_unobserved_variants_stay_closed(self):
        for marker in ("PLSV", "DSZR", "DRVA"):
            for old, new in (("A32", "A16"), ("ct=a", "ct=p"), ("Aea", "A16"), ("op=#", "op=9"), ("s=#", "s=1"), ("vt=nn", "vt=nx"), ("a=12", "a=-12"), (marker + ":D", marker + ":R")):
                with self.subTest(marker=marker, mutation=(old, new)):
                    self.closed(positioning(marker).replace(old, new))
        self.closed(positioning("DSZR").replace("v=3", "v=-3"))
        self.closed(positioning("DSZR").replace("si=s", "si=u"))
        self.closed(positioning().replace("PLSV:D:Y:Y:", "PLSV:D:Y:Y:M:"))
        self.closed(positioning().replace("a=20:vt=nn}", "a=20:vt=nn}:d{s=#:a=1:vt=nn}"))

    def test_dx_contact_is_hexadecimal(self):
        for logic, opcode in (("a", "ANI"), ("o", "ORI")):
            data = carrier("B", ["DX"], ["Abl"], [42], logic=logic)
            self.assertEqual(_decode_mil(data, 1)[0]["operands"], ["DX2A"])
            self.assertEqual(_decode_mil(data, 1)[0]["opcode"], opcode)
            for old, new in (("ct=a", "ct=p"), ("a=42", "a=-1"), ("vt=nn", "vt=nx"), ("s=#", "s=1"), ("Abl", "A16")):
                self.closed(data.replace(old, new))

    def test_sd_move_directions_and_width(self):
        for tags in (["D", "SD"], ["SD", "D"]):
            for width, opcode in (("A16", "MOV"), ("A32", "DMOV")):
                data = carrier("MOV", tags, [width, width], [12, 34])
                row = _decode_mil(data, 1)[0]
                self.assertEqual((row["opcode"], row["operands"]), (opcode, [tags[0] + "12", tags[1] + "34"]))
                for old, new in (("ct=a", "ct=p"), ("vt=nn", "vt=nx"), ("s=#", "s=1")):
                    self.closed(data.replace(old, new))

    def test_sd_signed_double_word_comparison(self):
        for logic, opcode in (("l", "LDD="), ("a", "ANDD=")):
            data = carrier("EQ", ["SD", "D"], ["A32s", "A32s"], [22, 44], logic=logic)
            row = _decode_mil(data, 1)[0]
            self.assertEqual((row["opcode"], row["operands"]), (opcode, ["SD22", "D44"]))
            for old, new in (("lt=" + logic, "lt=o"), ("EQ", "NE"), ("A32s", "A16s"), ("ct=a", "ct=p"), ("a=22", "a=-1"), ("vt=nn", "vt=nx")):
                self.closed(data.replace(old, new))

    def test_no_generic_device_admission(self):
        for tag in ("DX", "SD"):
            with self.assertRaises(MiningRequired):
                _format_operand([tag], ("scalar", (42,)))
        self.closed(carrier("OUT", ["DX"], ["Abl"], [42]))
        self.closed(carrier("MOV", ["SD", "SD"], ["A32", "A32"], [12, 34]))


class InstalledPositioningTests(unittest.TestCase):
    def test_installed_cli_and_continuations(self):
        cases = [(positioning(marker), "D" + marker, count) for marker, count in (("PLSV", 3), ("DSZR", 4), ("DRVA", 4))]
        cases += [(positioning().replace("A32", "A16"), None, 1)]
        for data, opcode, count in cases:
            with self.subTest(opcode=opcode), tempfile.TemporaryDirectory(prefix="gx-positioning-") as folder:
                root = Path(folder)
                source = root / "synthetic.gx3"
                synthetic_gx3(source, mil_mov=True, mil_source=data)
                before = hashlib.sha256(source.read_bytes()).hexdigest()
                result = subprocess.run([sys.executable, "-I", "-B", "-m", "gx3_fx5_parser_toolkit.cli", str(source), "--phase2-output", str(root / "ir")], cwd=root, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                ir = json.loads((root / "ir/neutral-ir.json").read_text(encoding="utf-8"))
                rows = ir["pous"][0]["records"]
                self.assertEqual(len(rows), count)
                self.assertEqual([r["status"] for r in rows], ["decoded" if opcode else "unknown"] * count)
                if opcode:
                    self.assertEqual(rows[0]["opcode"], opcode)
                    self.assertEqual([r["kind"] for r in rows], ["instruction"] + ["continuation"] * (count - 1))
                    self.assertTrue(all(r["continues_record_id"] == rows[0]["record_id"] for r in rows[1:]))
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
