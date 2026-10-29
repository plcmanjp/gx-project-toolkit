"""설치한 읽기 전용 패키지와 합성 공시 계약을 검증합니다."""
from __future__ import annotations

from copy import deepcopy
import importlib
import importlib.metadata as metadata
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

import gxw_analysis_service as service
import gxw_read_v1 as read
import gxw_reference_ir as reference

MODULES = {
    "gxw_ladder_reader", "gxw_pou_devmap", "gxw_reference_ir", "gxw_bounded_ole",
    "gxw_bounded_xml", "gxw_parameter_reader", "gxw_project_analysis", "gxw_read_v1",
    "gxw_analysis_service", "gxw_analysis_worker", "gxw_analysis_mcp",
}
SCRIPTS = {
    "gxw-inspect": "gxw_ladder_reader:main", "gxw-analyze": "gxw_project_analysis:main",
    "gxw-reference-ir": "gxw_reference_ir:main", "gxw-read-service": "gxw_analysis_service:main",
    "gxw-read-mcp": "gxw_analysis_mcp:main",
}
SOURCE_SHA = "a" * 64
POU_NAME = "ExampleProgram"
NOTE_TEXT = "ExampleNote"


def observation(rows=None):
    rows = rows if rows is not None else [("LD", "M1", ""), ("OUT", "M2", ""), ("END", "", "")]
    ir = reference.project_rows([{"name": POU_NAME, "source_store": "m0000", "source_digest": "b" * 64,
                                  "rows": rows}], input_sha256=SOURCE_SHA)
    for occurrence in ir["occurrences"]:
        occurrence["provenance"]["source_locator"] = {
            "member": "m0000", "pou": POU_NAME, "row": occurrence["record"]["sequence"]}
    return {"input": {"sha256": SOURCE_SHA}, "cpu": {"candidates": [{"literal": "Q06UDV"}]},
            "members": [{"member": "m0000", "path": "Example.res"}],
            "metadata": [{"id": "1", "member": "m0000", "role": "pou_resource", "state": "MAPPED"}],
            "pous": [{"name": POU_NAME, "member": "m0000", "rows": len(rows)}], "references": ir,
            "parameters": [], "text_records": [], "device_comments": {"sources": [], "records": []},
            "unknowns": ["CPU_IDENTITY_NOT_AUTHENTICATED"]}


class InstalledPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.prefix == sys.base_prefix:
            raise AssertionError("새 가상환경에 wheel을 설치한 뒤 실행하십시오.")
        cls.dist = metadata.distribution("gxw-parser-toolkit")
        if cls.dist.version != "0.2.0a1":
            raise AssertionError("설치 버전이 0.2.0a1이 아닙니다.")

    def test_distribution_has_exact_readonly_modules_and_entrypoints(self):
        entries = [entry for entry in self.dist.entry_points if entry.group == "console_scripts"]
        self.assertEqual(len(SCRIPTS), len(entries))
        self.assertEqual(SCRIPTS, {entry.name: entry.value for entry in entries})
        files = {str(path) for path in self.dist.files or () if str(path).endswith(".py")}
        self.assertEqual({name + ".py" for name in MODULES}, files)
        prefix = Path(sys.prefix).resolve()
        for name in MODULES:
            with self.subTest(module=name):
                origin = Path(importlib.import_module(name).__file__).resolve()
                self.assertTrue(origin.is_relative_to(prefix))
                self.assertEqual(origin, Path(self.dist.locate_file(name + ".py")).resolve())

    def test_writer_modules_and_alternate_distribution_are_absent(self):
        for name in ("gxw_ladder_writer", "gxw_single_command", "gxw_parameter_records", "wt9_fill_pou_body"):
            with self.subTest(module=name):
                self.assertIsNone(importlib.util.find_spec(name))
        with self.assertRaises(metadata.PackageNotFoundError):
            metadata.distribution("gx-project-toolkit-readonly")
        import gxw_parameter_reader as parameters
        self.assertFalse(hasattr(parameters, "encode_records"))
        self.assertFalse(hasattr(parameters, "replace_ascii_label"))
        direct = json.loads(self.dist.read_text("direct_url.json") or "{}")
        self.assertNotIn("dir_info", direct)
        self.assertIn("archive_info", direct)

    def test_installed_schema_preserves_partial_and_incomplete_contract(self):
        files = [path for path in self.dist.files or () if str(path).replace("\\", "/").endswith(
                 "share/gx-project-toolkit/device-references-v1.schema.json")]
        self.assertEqual(1, len(files))
        path = Path(self.dist.locate_file(files[0])).resolve()
        self.assertTrue(path.is_relative_to(Path(sys.prefix).resolve()))
        schema = json.loads(path.read_bytes())
        self.assertEqual("PARTIAL", schema["properties"]["state"]["const"])
        self.assertIs(False, schema["properties"]["complete_search"]["const"])
        self.assertEqual(read.PROFILE, schema["properties"]["profile"]["const"])


class ProjectionContractTests(unittest.TestCase):
    def test_snapshot_remains_partial_and_preserves_each_operand_role(self):
        source = observation([("MOV", "D7 D7", ""), ("END", "", "")])
        before = deepcopy(source)
        result = read.device_snapshot(source)
        self.assertEqual(source, before)
        self.assertEqual("PARTIAL", result["state"])
        self.assertIs(False, result["complete_search"])
        device, = result["devices"]
        self.assertEqual("D7", device["device"])
        self.assertEqual([(0, "read"), (1, "write")],
                         [(item["operand_position"], item["access"]) for item in device["references"]])
        serialized = json.dumps(result)
        self.assertNotIn(POU_NAME, serialized)
        self.assertNotIn("Example.res", serialized)

    def test_dynamic_reference_keeps_only_its_observed_base(self):
        result = read.device_snapshot(observation([("DMOV", "D0Z1 D10", "")]))
        self.assertEqual(["D0", "D10", "D11"], [device["device"] for device in result["devices"]])
        item = result["devices"][0]["references"][0]
        self.assertEqual(("DYNAMIC", "BASE_ONLY", None),
                         (item["coverage_state"], item["coverage_relation"], item["covered_offset"]))
        self.assertIn("INDEX_OR_INDIRECT_ADDRESS", {edge["reason"] for edge in result["unresolved_edges"]})

    def test_missing_reference_analysis_is_not_decoded_zero(self):
        source = observation()
        del source["references"]
        result = read.device_snapshot(source)
        self.assertEqual("NOT_ANALYZED", result["reference_state"])
        self.assertIsNone(result["unknown_instructions"]["count"])
        self.assertEqual([], result["devices"])
        self.assertIs(False, result["complete_search"])


class DisclosureContractTests(unittest.TestCase):
    def project(self):
        return {"path": "example.gxw", "root": "inputs", "sha256": SOURCE_SHA,
                "profile": service.PROFILE, "authority": "authorized-synthetic"}

    def request(self):
        return {"alias_key": "ab" * 32, "operation": "inspect", "projects": [self.project()],
                "project_ids": ["sample"], "offset": 0, "page_size": 100,
                "memory_bytes": 64 * 1024 * 1024, "timeout": 5}

    def test_summary_default_masks_names_and_never_requests_text(self):
        observed = observation()
        with mock.patch.object(service.engine, "capture_file", return_value=b"synthetic"), \
             mock.patch.object(service.engine, "analyze_bytes", return_value=observed) as analyze:
            response = service.project_result(self.request())
        self.assertFalse(analyze.call_args.kwargs["policy"].include_text)
        self.assertNotIn("detail", response)
        self.assertNotIn(POU_NAME, json.dumps(response))
        self.assertEqual("PARTIAL", response["state"])
        self.assertEqual("UNKNOWN", response["overall_semantic"])
        self.assertEqual("NOT_RUN", response["official_validation"])
        self.assertEqual("DECLARED_NOT_AUTHENTICATED", response["profile_state"])

    def test_detail_grants_reject_missing_duplicate_unknown_and_summary_escalation(self):
        for fields, reason in ((None, "DETAIL_GRANT_REQUIRED"), ([], "DETAIL_GRANT_REJECTED"),
                               (["references", "references"], "DETAIL_GRANT_REJECTED"),
                               (["parameters"], "DETAIL_GRANT_REJECTED")):
            project = self.project()
            if fields is not None:
                project["detail_fields"] = fields
            with self.subTest(fields=fields), self.assertRaisesRegex(service.ServiceError, reason):
                service.detail_fields("authorized-detail", project)
        project = self.project()
        project["detail_fields"] = ["text_records"]
        with self.assertRaisesRegex(service.ServiceError, "DETAIL_GRANT_REJECTED"):
            service.detail_fields("summary-only", project)

    def test_text_grant_preserves_unknown_note_subtype_and_masks_other_fields(self):
        observed = observation()
        observed["text_records"] = [{"member": "m0000", "pou": POU_NAME, "sequence": 1,
            "kind": "note", "text": NOTE_TEXT, "state": "OBSERVED_SOURCE", "raw_type": "0x01",
            "subtype": "i", "extra": "UnselectedValue", "attachment": {"sequence": 0, "opcode": "LD"}}]
        request = self.request()
        request["disclosure"] = "authorized-detail"
        request["projects"][0]["detail_fields"] = ["text_records"]
        with mock.patch.object(service.engine, "capture_file", return_value=b"synthetic"), \
             mock.patch.object(service.engine, "analyze_bytes", return_value=observed):
            response = service.project_result(request)
        self.assertEqual(["text_records"], response["disclosure"]["granted_fields"])
        item, = response["detail"]["items"]
        self.assertEqual(NOTE_TEXT, item["text"])
        self.assertIsNone(item["subtype"])
        self.assertEqual("UNRESOLVED", item["subtype_state"])
        self.assertIs(False, item["raw_type_ui_mapping_verified"])
        self.assertNotIn(POU_NAME, json.dumps(response))
        self.assertNotIn("UnselectedValue", json.dumps(response))
        self.assertIs(False, response["detail"]["complete"])


if __name__ == "__main__":
    unittest.main()
