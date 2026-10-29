"""Synthetic observation-contract tests, without native files or an engine."""
from copy import deepcopy
import json
from unittest import TestCase, main, mock

import gxw_read_v1 as read
import gxw_reference_ir as reference

SHA = "a" * 64
SECRET = "SecretPouName"


def analysis(rows=None):
    rows = rows if rows is not None else [("LD", "M100", ""), ("OUT", "M101", ""), ("END", "", "")]
    ir = reference.project_rows([{"name": SECRET, "source_store": "m0000",
        "source_digest": "b" * 64, "rows": rows}], input_sha256=SHA)
    for occurrence in ir["occurrences"]:
        occurrence["provenance"]["source_locator"] = {
            "member": "m0000", "pou": SECRET, "row": occurrence["record"]["sequence"]}
    return {"input": {"sha256": SHA}, "members": [
                {"member": "m0000", "path": "PRIVATE.res"},
                {"member": "m0001", "path": "PRIVATE.Program.pou"},
                {"member": "m0002", "path": "PRIVATE.bin"}],
            "metadata": [{"id": "1", "member": "m0000", "role": "pou_resource", "state": "MAPPED",
                          "name": "PRIVATE.res"},
                         {"id": "2", "member": "m0001", "role": "pou_program", "state": "MAPPED"},
                         {"id": "3", "member": "m0002", "role": "opaque", "state": "MAPPED"}],
            "pous": [{"name": SECRET, "member": "m0000", "rows": len(rows)}],
            "references": ir, "parameters": [], "text_records": [],
            "device_comments": {"sources": [], "records": []},
            "unknowns": ["CPU_IDENTITY_NOT_AUTHENTICATED"]}


def reasons(result):
    return {e["reason"] for e in result["unresolved_edges"]}


class ReadV1Tests(TestCase):
    def test_frozen_candidate_manifest_has_exact_twelve_arities_and_no_acceptance_claim(self):
        manifest = read.promise_manifest()
        self.assertEqual("q06udv-simple-ladder-read-v1", read.PROFILE)
        self.assertEqual({"END": 0, "LD": 1, "LDI": 1, "AND": 1, "ANI": 1, "OR": 1,
                          "ORI": 1, "OUT": 1, "SET": 1, "RST": 1, "MOV": 2, "DMOV": 2},
                         {f["opcode"]: f["arity"] for f in manifest["forms"]})
        for form in manifest["forms"]:
            self.assertEqual(form["arity"], len(form["operands"]))
            self.assertEqual("OBSERVATION_CONTRACT", form["evidence_status"])
            self.assertEqual("NOT_ESTABLISHED", form["completion"])
        manifest["forms"].clear()
        self.assertEqual(12, len(read.promise_manifest()["forms"]))

    def test_all_candidate_forms_remain_partial_even_when_reference_ir_is_complete(self):
        rows = [(op, "M0", "") for op in ("LD", "LDI", "AND", "ANI", "OR", "ORI", "OUT", "SET", "RST")]
        rows += [("MOV", "D0 D1", ""), ("DMOV", "D2 D4", ""), ("END", "", "")]
        source = analysis(rows)
        self.assertEqual("COMPLETE", source["references"]["analysis"]["state"])
        result = read.build_projection(source)
        self.assertEqual(("PARTIAL", False), (result["state"], result["complete_search"]))
        self.assertEqual(12, len(result["instructions"]))
        self.assertEqual({"OBSERVATION_CONTRACT"}, {i["state"] for i in result["instructions"]})
        self.assertEqual({"NOT_ESTABLISHED"}, {i["evidence_status"] for i in result["instructions"]})
        self.assertEqual([], result["unsupported_in_v1"])

    def test_finite_kh_boundaries_and_unproven_constant_forms(self):
        for op, valid, invalid in (
            ("MOV", ("K-32768", "K32767", "H0", "HFFFF"),
             ("K-32769", "K32768", "H10000", "H-1", "E1", "K1Z1")),
            ("DMOV", ("K-2147483648", "K2147483647", "HFFFFFFFF"),
             ("K-2147483649", "K2147483648", "H100000000", "E1.0")),
        ):
            for token in valid + invalid:
                with self.subTest(op=op, token=token):
                    result = read.build_projection(analysis([(op, token + " D10", "")]))
                    state = result["instructions"][0]["state"]
                    self.assertEqual("OBSERVATION_CONTRACT" if token in valid else "UNSUPPORTED_IN_V1", state)

    def test_recognized_outside_forms_are_not_unknown_instructions(self):
        source = analysis([("BMOV", "D0 D10 K2", ""), ("MOV", "D0Z1 D20", ""),
                           ("LD", "D0.0", ""), ("OUT", "T0 K10", ""),
                           ("MOV", '"Private literal" D30', "")])
        result = read.build_projection(source)
        self.assertEqual(0, result["unknown_instructions"]["count"])
        self.assertEqual(5, len(result["unsupported_in_v1"]))
        self.assertEqual({"UNSUPPORTED_IN_V1"}, {i["state"] for i in result["instructions"]})
        self.assertIn("INDEX_OR_INDIRECT_ADDRESS", reasons(result))
        self.assertNotIn("Private literal", json.dumps(result))

    def test_unknown_count_preserves_every_repeated_occurrence_and_locator(self):
        source = analysis([("<i:aa>", "M1", ""), ("<i:aa>", "M2", ""), ("<i:aa>", "M3", "")])
        self.assertEqual(1, len(source["references"]["diagnostics"]))
        result = read.build_projection(source)
        self.assertEqual((3, 3), (result["unknown_instructions"]["count"],
                                 result["unknown_instructions"]["reported_count"]))
        self.assertEqual([0, 1, 2], sorted(o["locator"]["row"] for o in result["unknown_instructions"]["occurrences"]))
        self.assertTrue(all(o["opcode"] is None for o in result["unknown_instructions"]["occurrences"]))
        source["references"]["coverage"]["unknown_instructions"] = 1
        mismatch = read.build_projection(source)
        self.assertEqual((3, 1), (mismatch["unknown_instructions"]["count"],
                                 mismatch["unknown_instructions"]["reported_count"]))
        self.assertIn("UNKNOWN_INSTRUCTION_COUNT_MISMATCH", reasons(mismatch))

    def test_unknown_roles_and_supplied_roles_are_reused_without_opcode_inference(self):
        source = analysis([("LD", "M1", ""), ("<i:bb>", "M2", "")])
        source["references"]["occurrences"][0]["operands"][0]["access"] = "both"
        result = read.device_snapshot(source)
        refs = {d["device"]: d["references"][0] for d in result["devices"]}
        self.assertEqual("both", refs["M1"]["access"])
        self.assertEqual("unknown", refs["M2"]["access"])
        self.assertIn("REFERENCE_ACCESS_UNKNOWN", reasons(result))

    def test_snapshot_expands_only_supplied_static_coverage_and_sorts_numeric_addresses(self):
        source = analysis([("LD", "X1A", ""), ("OUT", "YF", ""), ("DMOV", "D2 D10", "")])
        result = read.device_snapshot(source)
        self.assertEqual("gx-project-toolkit.device-references/1", result["schema"])
        self.assertEqual(["D2", "D3", "D10", "D11", "X1A", "YF"], [d["device"] for d in result["devices"]])
        for device in result["devices"]:
            ref = device["references"][0]
            self.assertEqual("COVERED_ADDRESS", ref["coverage_relation"])
            if device["family"] == "D":
                self.assertEqual("read" if device["address"] < 10 else "write", ref["access"])
                self.assertEqual(device["address"] % 2, ref["covered_offset"])
            else:
                self.assertEqual(16, device["display_radix"])

    def test_dynamic_address_retains_base_without_fabricating_a_range(self):
        result = read.device_snapshot(analysis([("DMOV", "D0Z1 D10", "")]))
        self.assertEqual(["D0", "D10", "D11"], [d["device"] for d in result["devices"]])
        ref = result["devices"][0]["references"][0]
        self.assertEqual(("DYNAMIC", "BASE_ONLY", None),
                         (ref["coverage_state"], ref["coverage_relation"], ref["covered_offset"]))
        self.assertIn("INDEX_OR_INDIRECT_ADDRESS", reasons(result))

    def test_same_device_keeps_both_operand_positions(self):
        result = read.device_snapshot(analysis([("MOV", "D7 D7", "")]))
        self.assertEqual(1, len(result["devices"]))
        self.assertEqual([(0, "read"), (1, "write")],
                         [(r["operand_position"], r["access"]) for r in result["devices"][0]["references"]])

    def test_inventory_and_missing_reference_ir_do_not_mean_decoded_zero(self):
        for inventory in (True, False):
            with self.subTest(inventory=inventory):
                source = analysis()
                source.pop("references")
                if inventory:
                    source["schema"] = "plcman.gxw.project-inventory/1"
                    source["pous"][0].pop("rows")
                result = read.build_projection(source)
                self.assertEqual("NOT_ANALYZED", result["reference_state"])
                self.assertIsNone(result["unknown_instructions"]["count"])
                self.assertEqual({"state": "NOT_ANALYZED", "observed_count": None,
                                  "reference_occurrences": None}, result["pous"][0]["rows"])
                self.assertIn("REFERENCES_NOT_ANALYZED", reasons(result))
                self.assertEqual([], read.device_snapshot(source)["devices"])

    def test_undecoded_empty_rows_are_exposed_as_inconsistent_not_complete(self):
        source = analysis()
        source["references"]["occurrences"] = []
        source["references"]["coverage"].update(occurrences=0, operands=0)
        result = read.build_projection(source)
        self.assertIn("POU_ROW_COUNT_MISMATCH", reasons(result))
        self.assertEqual("PARTIAL", result["state"])
        source = analysis([])
        source["pous"] = []
        self.assertIn("NO_RECOGNIZED_POU", reasons(read.build_projection(source)))

    def test_semantic_member_recognition_does_not_promote_metadata_or_framing(self):
        source = analysis()
        source["parameters"] = [{"member": "m0002", "state": "FRAMED_ONLY"}]
        result = read.build_projection(source)
        self.assertEqual(["m0001", "m0002"], [m["member"] for m in result["unrecognized_members"]])
        self.assertEqual("pou_resource", result["pous"][0]["role"])
        source["parameters"][0]["state"] = "OBSERVED_ASCII_NAMES"
        self.assertEqual(["m0001"], [m["member"] for m in read.build_projection(source)["unrecognized_members"]])
        unknown = read.build_projection(analysis([("<i:aa>", "", "")]))
        self.assertIn("m0000", [m["member"] for m in unknown["unrecognized_members"]])

    def test_missing_role_and_unresolved_mapping_remain_visible(self):
        source = analysis()
        source["metadata"] = [{"id": "1", "member": None, "role": "pou_resource", "state": "UNRESOLVED"}]
        result = read.build_projection(source)
        self.assertEqual("UNVERIFIED", result["pous"][0]["role"])
        self.assertTrue({"POU_ROLE_UNVERIFIED", "METADATA_TARGET_UNRESOLVED"} <= reasons(result))

    def with_comments(self):
        source = analysis([("LD", "M100", ""), ("OUT", "M101", "Private row comment"),
                           ("__NOTE__", "Private note", ""), ("END", "", "")])
        source["device_comments"] = {
            "sources": [{"member": "m0002", "state": "OBSERVED_SOURCE"}],
            "records": [{"member": "m0002", "sequence": 0, "device": "M101", "state": "OBSERVED_SOURCE",
                         "text": "Private carrier comment", "text_sha256": "c" * 64, "encoding": "utf-16le"}]}
        source["text_records"] = [{"member": "m0000", "pou": SECRET, "sequence": 2, "kind": "note",
            "state": "OBSERVED_SOURCE", "text": "Private note", "text_sha256": "d" * 64,
            "hash_basis": "SOURCE_BYTES", "raw_type": "0x01", "subtype": "i", "source_step_width": 1,
            "attachment": {"sequence": 1, "opcode": "OUT"}}]
        return source

    def test_text_sources_are_separate_unverified_and_note_subtype_is_always_null(self):
        source = self.with_comments()
        result = read.device_snapshot(source, include_text=True)
        device = next(d for d in result["devices"] if d["device"] == "M101")
        self.assertEqual({"device_comment_sources", "device_comment_records", "reference_ir_comments", "text_records"},
                         set(device["comments"]))
        self.assertEqual([1, 1, 1, 1], [len(v) for v in device["comments"].values()])
        for records in device["comments"].values():
            self.assertEqual(("UNVERIFIED", None), (records[0]["ownership"], records[0]["owner"]))
        self.assertIsNone(device["comments"]["text_records"][0]["subtype"])
        self.assertIn("NOTE_SUBTYPE_UNVERIFIED", reasons(result))
        self.assertNotIn("POU_ROW_COUNT_MISMATCH", reasons(result))

    def test_default_masking_rechecks_visible_input_and_does_not_copy_names_or_paths(self):
        source = self.with_comments()
        source["path"] = "C:\\Secret\\private.gxw"
        source["engine"] = {"private": "supersecret"}
        result = read.build_projection(source)
        serialized = json.dumps(result)
        for secret in (SECRET, "PRIVATE", "Private", "C:\\", "supersecret"):
            self.assertNotIn(secret, serialized)
        self.assertIsNone(result["pous"][0]["name"])
        for records in result["comments"].values():
            self.assertTrue(all(r["text"] is None for r in records if "text" in r))
        visible = read.build_projection(source, include_text=True)
        self.assertEqual(SECRET, visible["pous"][0]["name"])
        self.assertEqual("Private note", visible["comments"]["text_records"][0]["text"])
        self.assertEqual("p0000", visible["instructions"][0]["locator"]["pou"])
        self.assertNotIn("C:\\", json.dumps(visible))

    def test_comment_attachment_mismatch_is_not_attached_to_a_device(self):
        source = self.with_comments()
        source["text_records"][0]["attachment"]["opcode"] = "LD"
        result = read.device_snapshot(source)
        self.assertIn("NOTE_ATTACHMENT_UNRESOLVED", reasons(result))
        self.assertTrue(all(not d["comments"]["text_records"] for d in result["devices"]))
        self.assertEqual(1, len(result["comments"]["text_records"]))

    def test_dynamic_comment_device_is_not_assigned_to_its_base(self):
        source = self.with_comments()
        source["device_comments"]["records"][0]["device"] = "M101Z1"
        result = read.device_snapshot(source)
        self.assertIn("COMMENT_DEVICE_UNRESOLVED", reasons(result))
        self.assertIsNone(result["comments"]["device_comment_records"][0]["device"])
        self.assertTrue(all(not d["comments"]["device_comment_records"] for d in result["devices"]))

    def test_deterministic_snapshot_ignores_input_array_order_and_never_adds_time(self):
        source = self.with_comments()
        changed = deepcopy(source)
        for key in ("members", "metadata", "pous", "unknowns"):
            changed[key].reverse()
        changed["references"]["occurrences"].reverse()
        left, right = read.device_snapshot(source), read.device_snapshot(changed)
        self.assertEqual(json.dumps(left, sort_keys=True), json.dumps(right, sort_keys=True))
        self.assertNotIn("timestamp", json.dumps(left))
        self.assertNotIn("path", left)
        canonical = json.dumps(left, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        for _ in range(3):
            self.assertEqual(canonical, json.dumps(read.device_snapshot(source), sort_keys=True,
                ensure_ascii=True, separators=(",", ":")).encode("ascii"))

    def test_same_device_comments_from_two_members_never_imply_global_or_local_ownership(self):
        source = self.with_comments()
        source["members"].append({"member": "m0003", "path": "SecretPouName.qcd"})
        source["metadata"].append({"id": "4", "member": "m0003", "role": "opaque", "state": "MAPPED",
                                   "name": "SecretPouName.qcd"})
        source["device_comments"]["sources"].append({"member": "m0003", "state": "OBSERVED_SOURCE"})
        second = deepcopy(source["device_comments"]["records"][0])
        second.update(member="m0003", text="Second source text", text_sha256="e" * 64)
        source["device_comments"]["records"].append(second)
        result = read.device_snapshot(source, include_text=True)
        records = next(d for d in result["devices"] if d["device"] == "M101")["comments"]["device_comment_records"]
        self.assertEqual(["m0002", "m0003"], [r["member"] for r in records])
        self.assertEqual(["Private carrier comment", "Second source text"], [r["text"] for r in records])
        for record in records:
            self.assertEqual(("UNVERIFIED", None), (record["ownership"], record["owner"]))
            self.assertFalse({"global", "local", "scope", "owner_pou"} & set(record))
        descriptors = next(d for d in result["devices"] if d["device"] == "M101")["comments"]["device_comment_sources"]
        self.assertEqual(["m0002", "m0003"], [s["member"] for s in descriptors])
        self.assertTrue(all(s["ownership"] == "UNVERIFIED" and s["owner"] is None for s in descriptors))
        source["device_comments"]["sources"].reverse()
        source["device_comments"]["records"].reverse()
        self.assertEqual(result, read.device_snapshot(source, include_text=True))

    def test_empty_decoded_comment_source_is_retained_globally_without_semantic_promotion(self):
        source = analysis()
        source["device_comments"]["sources"] = [{"member": "m0002", "state": "OBSERVED_SOURCE",
            "record_count": 0, "reason": None, "encoding": "utf-16le"}]
        result = read.build_projection(source)
        expected = {"member": "m0002", "state": "OBSERVED_SOURCE", "record_count": 0,
                    "reason": None, "encoding": "utf-16le", "encoding_state": "UNVERIFIED",
                    "ownership": "UNVERIFIED", "owner": None}
        self.assertEqual([expected], result["comments"]["device_comment_sources"])
        self.assertIn("m0002", [m["member"] for m in result["unrecognized_members"]])
        snapshot = read.device_snapshot(source)
        self.assertEqual([expected], snapshot["comments"]["device_comment_sources"])
        self.assertTrue(all(not d["comments"]["device_comment_sources"] for d in snapshot["devices"]))
        self.assertFalse(snapshot["complete_search"])

    def test_unresolved_comment_source_keeps_null_count_and_reason_without_records(self):
        source = analysis([])
        source["device_comments"]["sources"] = [{"member": "m0002", "state": "UNRESOLVED_SOURCE",
            "record_count": None, "reason": "DEVICE_COMMENT_FRAMING_UNVERIFIED", "encoding": None}]
        result = read.device_snapshot(source)
        self.assertEqual([], result["devices"])
        descriptor, = result["comments"]["device_comment_sources"]
        self.assertIsNone(descriptor["record_count"])
        self.assertIsNone(descriptor["encoding"])
        self.assertEqual("DEVICE_COMMENT_FRAMING_UNVERIFIED", descriptor["reason"])
        self.assertEqual("UNRESOLVED_SOURCE", descriptor["state"])
        self.assertEqual(("UNVERIFIED", "UNVERIFIED", None),
                         (descriptor["encoding_state"], descriptor["ownership"], descriptor["owner"]))
        self.assertIn("DEVICE_COMMENT_SOURCE_UNRESOLVED", reasons(result))

    def test_comment_source_counts_are_preserved_without_inference_from_records(self):
        source = self.with_comments()
        source["device_comments"]["sources"] = [
            {"member": "m0002", "state": "OBSERVED_SOURCE", "record_count": 7},
            {"member": "m0002", "state": "OBSERVED_SOURCE"},
            {"member": "m0002", "state": "UNRESOLVED_SOURCE", "record_count": None,
             "reason": "DEVICE_COMMENT_PARSE_UNVERIFIED"}]
        result = read.device_snapshot(source)
        descriptors = result["comments"]["device_comment_sources"]
        self.assertEqual(3, len(descriptors))
        self.assertEqual([7], [s["record_count"] for s in descriptors if s["record_count"] is not None])
        self.assertEqual(2, sum(s["record_count"] is None for s in descriptors))
        self.assertEqual(1, len(result["comments"]["device_comment_records"]))
        bound = next(d for d in result["devices"] if d["device"] == "M101")["comments"]["device_comment_sources"]
        self.assertEqual(descriptors, bound)

    def test_comment_source_allowlist_masks_names_paths_and_rejects_malformed_count(self):
        source = analysis()
        source["device_comments"]["sources"] = [{"member": "m0002", "state": "UNRESOLVED_SOURCE",
            "record_count": None, "reason": "DEVICE_COMMENT_PARSE_UNVERIFIED", "encoding": None,
            "name": "PrivateCarrierName", "path": "C:\\Private\\carrier.qcd", "owner_pou": SECRET}]
        expected_keys = {"member", "state", "record_count", "reason", "encoding", "encoding_state", "ownership", "owner"}
        for include_text in (False, True):
            result = read.build_projection(source, include_text=include_text)
            descriptor, = result["comments"]["device_comment_sources"]
            self.assertEqual(expected_keys, set(descriptor))
            self.assertNotIn("PrivateCarrierName", json.dumps(descriptor))
            self.assertNotIn("C:\\", json.dumps(descriptor))
            self.assertNotIn(SECRET, json.dumps(descriptor))
        for count in (-1, True, "1"):
            source["device_comments"]["sources"][0]["record_count"] = count
            with self.subTest(count=count), self.assertRaises(read.ReadV1Error):
                read.build_projection(source)

    def test_projection_is_nonmutating_no_io_and_has_no_engine_dependency(self):
        source = self.with_comments()
        before = deepcopy(source)
        with mock.patch("builtins.open", side_effect=AssertionError("No IO")), \
             mock.patch.dict("sys.modules", {"gxw_project_analysis": None}):
            result = read.device_snapshot(source)
            projection = read.build_projection(source)
        self.assertEqual(before, source)
        result["comments"]["text_records"][0]["text_sha256"] = "e" * 64
        projection["promise_manifest"]["forms"].clear()
        self.assertEqual(before, source)

    def test_ir_count_and_source_locator_mismatches_cannot_disappear(self):
        source = analysis()
        source["references"]["coverage"]["occurrences"] = 100
        source["references"]["coverage"]["operands"] = 100
        result = read.build_projection(source)
        self.assertTrue({"REFERENCE_OCCURRENCE_COUNT_MISMATCH", "REFERENCE_OPERAND_COUNT_MISMATCH"} <= reasons(result))
        source["references"]["occurrences"][0]["provenance"]["source_locator"]["row"] = 100
        with self.assertRaises(read.ReadV1Error):
            read.build_projection(source)

    def test_malformed_inputs_fail_closed_with_privacy_safe_errors(self):
        def set_operand(source, key, value):
            source["references"]["occurrences"][0]["operands"][0][key] = value
        mutations = [
            lambda a: a.update(input={"sha256": "bad"}),
            lambda a: a.update(members="bad"),
            lambda a: a["members"].append(deepcopy(a["members"][0])),
            lambda a: a["members"][0].update(member="C:\\Private"),
            lambda a: a["metadata"][0].update(role=[]),
            lambda a: a["pous"][0].update(rows=True),
            lambda a: a["references"]["input"].update(sha256="b" * 64),
            lambda a: a["references"]["coverage"].update(unknown_instructions=-1),
            lambda a: a["references"]["occurrences"].append(deepcopy(a["references"]["occurrences"][0])),
            lambda a: set_operand(a, "access", []),
            lambda a: set_operand(a, "position", True),
            lambda a: set_operand(a, "raw_token", "M999"),
            lambda a: a["references"]["occurrences"][0]["operands"][0]["device"].update(display_radix=16),
            lambda a: a["references"]["occurrences"][0]["provenance"].pop("source_locator"),
            lambda a: a["references"]["occurrences"][0]["operands"][0]["coverage"]["addresses"][0].update(address=999),
        ]
        for mutate in mutations:
            source = analysis()
            mutate(source)
            with self.subTest(mutation=mutate), self.assertRaises(read.ReadV1Error) as caught:
                read.build_projection(source)
            self.assertNotIn("Private", str(caught.exception))
        for value in (None, [], 1, True):
            with self.subTest(value=value), self.assertRaises(read.ReadV1Error):
                read.build_projection(value)
        with self.assertRaises(read.ReadV1Error):
            read.device_snapshot(analysis(), include_text=1)


if __name__ == "__main__":
    main()
