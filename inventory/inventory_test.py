# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for cache-only availability and conservative dependency closure."""

import copy
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from inventory.binary import (
    audit_transfers,
    decoder_entries,
    relative_transfer,
    split_arguments,
    symbol_key,
)
from inventory.golden import index_artifacts, load_cache, reachable, report, sha256


GOLDEN = (
    Path(os.environ["IXYK_GOLDEN_MANIFEST"]).parent
    if "IXYK_GOLDEN_MANIFEST" in os.environ
    else Path(__file__).resolve().parents[1] / "artifacts/golden"
)


def node(code="4889d8", successors=(), unknown=()):
    return {
        "instructions": [{"address": 16, "hex": code, "opcode": "MOV", "prefix": ""}],
        "successors": list(successors),
        "unknown": list(unknown),
    }


def sample(nodes):
    return {
        "schema": "ixyk.bochs_binary_inventory.v1",
        "source_revision": "revision",
        "elf_sha256": "digest",
        "nodes": nodes,
        "targets": [
            {
                "id": "OP:register",
                "mnemonic": "op",
                "roots": [16],
                "handlers": ["BX_CPU_C::OP"],
                "unresolved_handlers": [],
            }
        ],
    }


class InventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = load_cache(GOLDEN)

    def test_committed_cache(self):
        self.assertEqual(self.cache["acquisitions"], 100)
        self.assertEqual(sum(map(len, self.cache["models"].values())), 81)
        self.assertEqual(len(self.cache["unavailable"]), 19)
        self.assertNotIn("f30f5ac1", self.cache["models"])

    def test_raw_acquisition_adapter_preserves_golden_model_evidence(self):
        # Exercise the live-input format using recorded artifacts, never extraction.
        files = {}
        for path in GOLDEN.glob("*.acquisition.json"):
            files[path.name] = path.read_bytes()
            model = path.name.replace(".acquisition.json", ".model.json")
            files[model] = subprocess.run(
                [
                    os.environ.get("IXYK_ZSTD", "zstd"),
                    "-dc",
                    str(GOLDEN / (model + ".zst")),
                ],
                check=True,
                capture_output=True,
            ).stdout
        manifest = "".join(f"{sha256(files[name])}  {name}\n" for name in sorted(files))
        live = index_artifacts(files, sha256(manifest.encode()), ".model.json", "live")
        self.assertEqual(live["origin"], "live")
        self.assertEqual(live["acquisitions"], self.cache["acquisitions"])
        self.assertEqual(live["unavailable"], self.cache["unavailable"])

        def evidence(cache):
            return {
                key: [(model["model_sha256"], model["source"]) for model in models]
                for key, models in cache["models"].items()
            }

        self.assertEqual(evidence(live), evidence(self.cache))
        expected = report(sample({"16": node()}), self.cache)
        actual = report(sample({"16": node()}), live)
        for field in (
            "available",
            "excluded",
            "cache_covered_forms",
            "exclusion_counts",
        ):
            self.assertEqual(actual[field], expected[field])

    def test_raw_acquisition_adapter_rejects_missing_model(self):
        with self.assertRaisesRegex(ValueError, "exactly one model"):
            index_artifacts(
                {"one.acquisition.json": b"{}"}, "digest", ".model.json", "live"
            )

    def test_raw_acquisition_adapter_rejects_inconsistent_status(self):
        acquisition = {
            "schema": "ixyk.instruction_acquisition.v1",
            "instruction_hex": "c3",
            "status": "unsupported",
            "error": "fixture",
        }
        model = {
            "schema": "ixyk.unavailable_instruction_model.v1",
            "status": "acquisition_error",
        }
        with self.assertRaisesRegex(ValueError, "inconsistent unavailable"):
            index_artifacts(
                {
                    "one.acquisition.json": json.dumps(acquisition).encode(),
                    "one.model.json": json.dumps(model).encode(),
                },
                "digest",
                ".model.json",
                "live",
            )

    def test_manifest_tampering_is_not_a_cache_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(GOLDEN, root, dirs_exist_ok=True)
            (root / "12_ret.acquisition.json").chmod(0o600)
            (root / "12_ret.acquisition.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                load_cache(root)

    def test_same_opcode_different_encoding_is_a_miss(self):
        exact = report(sample({"16": node("4889d8")}), self.cache)
        variant = report(sample({"16": node("4889c3")}), self.cache)
        self.assertEqual(exact["cache_covered_forms"], 1)
        self.assertEqual(variant["cache_covered_forms"], 0)
        self.assertIn("golden_cache_miss", variant["excluded"][0]["reasons"])

    def test_transitive_cycle_and_helper_miss(self):
        inventory = sample({"16": node(successors=[32]), "32": node("50", [16])})
        self.assertEqual(reachable(inventory["nodes"], [16])[0], [16, 32])
        self.assertEqual(report(inventory, self.cache)["cache_covered_forms"], 0)

    def test_unreachable_miss_does_not_block(self):
        result = report(sample({"16": node(), "32": node("50")}), self.cache)
        self.assertEqual(result["cache_covered_forms"], 1)

    def test_partially_resolved_indirect_call_stays_unknown(self):
        inventory = sample(
            {
                "16": node(successors=[32], unknown=["indirect_control_flow"]),
                "32": node(),
            }
        )
        result = report(inventory, self.cache)
        self.assertEqual(result["cache_covered_forms"], 0)
        self.assertEqual(result["excluded"][0]["reasons"], ["unresolved_dependency"])

    def test_missing_handler_does_not_admit_other_root(self):
        inventory = sample({"16": node()})
        inventory["targets"][0]["unresolved_handlers"] = [
            {"handler": "LOAD", "addresses": []}
        ]
        self.assertEqual(report(inventory, self.cache)["cache_covered_forms"], 0)

    def test_missing_block_does_not_pass_vacuously(self):
        self.assertEqual(report(sample({}), self.cache)["cache_covered_forms"], 0)

    def test_report_does_not_mutate_inventory(self):
        inventory = sample({"16": node()})
        original = copy.deepcopy(inventory)
        report(inventory, self.cache)
        self.assertEqual(inventory, original)

    def test_macro_templates_and_memory_roots(self):
        self.assertEqual(split_arguments("a, F<x,y>, z"), ["a", "F<x,y>", "z"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ia_opcodes.def").write_text(
                'bx_define_opcode(OP, "op", "op", &BX_CPU_C::LOAD, '
                "&BX_CPU_C::HANDLE<helper>, ISA, D, S, M, OP_NONE, ATTR)\n"
            )
            rows = decoder_entries(root)
            self.assertEqual(rows[0]["handlers"], ["BX_CPU_C::HANDLE<helper>"])
            self.assertEqual(
                rows[1]["handlers"], ["BX_CPU_C::HANDLE<helper>", "BX_CPU_C::LOAD"]
            )

    def test_function_pointer_template_symbol(self):
        source = "BX_CPU_C::HANDLE_AVX_2OP<xmm_andps>"
        demangled = "void BX_CPU_C::HANDLE_AVX_2OP<&(xmm_andps(BxPackedXmmRegister*, BxPackedXmmRegister const*))>(bxInstruction_c*)"
        self.assertEqual(symbol_key(source), symbol_key(demangled))

    def test_nested_templates_do_not_collapse_to_the_base_name(self):
        self.assertNotEqual(
            symbol_key("BX_CPU_C::H<F<X>>"), symbol_key("BX_CPU_C::H<F<Y>>")
        )

    def test_ret_only_stub_is_not_a_transport_win(self):
        stub = node("c3")
        stub["instructions"][0]["opcode"] = "RET"
        result = report(sample({"16": stub}), self.cache)
        self.assertEqual(result["cache_covered_forms"], 0)
        self.assertEqual(result["excluded"][0]["reasons"], ["trivial_handler_body"])

    def test_relative_encodings_and_rebasing(self):
        for code, target, continuation in [
            ("e80b000000", 32, True),
            ("e90b000000", 32, False),
            ("eb0e", 32, False),
            ("740e", 32, True),
            ("0f840a000000", 32, True),
            ("e2fe", 16, True),
            ("67e3fd", 16, True),
            ("f2e80a000000", 32, True),
            ("e8ebffffff", 0, True),
        ]:
            for base in (0, 0x400000):
                with self.subTest(code=code, base=base):
                    self.assertEqual(
                        relative_transfer({"hex": code, "address": 16 + base}),
                        (target + base, continuation),
                    )
        self.assertIsNone(relative_transfer({"hex": "488d0500000000", "address": 16}))

    def test_fallthrough_only_call_recovers_helper_and_its_miss(self):
        caller = node("e80b000000", [21])
        caller["instructions"][0]["opcode"] = "CALL"
        nodes = {"16": caller, "21": node(), "32": node("50")}
        audit_transfers(nodes)
        self.assertEqual(caller["successors"], [21, 32])
        self.assertEqual(
            caller["recovered_transfers"],
            [{"address": 16, "target": 32, "kind": "relative_target"}],
        )
        self.assertIn(32, reachable(nodes, [16])[0])

    def test_missing_destination_fails_closed(self):
        caller = node("e80b000000", [21])
        nodes = {"16": caller, "21": node()}
        audit_transfers(nodes)
        self.assertIn("relative_transfer_target_not_recovered", caller["unknown"])

    def test_resolved_indirect_target_is_not_exhaustive(self):
        caller = node("ffd0", [32])
        caller["instructions"][0]["opcode"] = "CALL"
        audit_transfers({"16": caller, "32": node()})
        self.assertIn("indirect_or_unclassified_transfer", caller["unknown"])

    def test_branch_recovers_both_arms_and_preserves_unknown(self):
        branch = node("740e", unknown=["existing_unknown"])
        branch["instructions"][0]["opcode"] = "JE"
        audit_transfers({"16": branch, "18": node(), "32": node()})
        self.assertEqual(branch["successors"], [18, 32])
        self.assertEqual(branch["unknown"], ["existing_unknown"])


if __name__ == "__main__":
    unittest.main()
