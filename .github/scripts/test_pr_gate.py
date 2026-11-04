import importlib.util
import os
import unittest

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("pr_gate", os.path.join(HERE, "pr-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CFG = gate.load_config()
TEMPLATE = open(os.path.join(HERE, "..", "pull_request_template.md"), encoding="utf-8").read()
API = "crates/api/src/rooms.rs"


def body(kind, scenario=None, platforms=()):
    types = "\n".join("- [%s] %s" % ("x" if t == kind else " ", t) for t in CFG["types"])
    labs = "\n".join("- [%s] %s" % ("x" if t in platforms else " ", t) for t in CFG["labs"])
    proof = "Scenario: e2e/scenarios/%s" % scenario if scenario else "Scenario: e2e/scenarios/<id>"
    return "## What changed and why\n\nA member can leave a room and the room says so.\n\n## Type\n\n%s\n\n## Clients\n\n%s\n\n## Proof\n\n%s\n" % (
        types, labs, proof)


def run(text, files, scenarios=()):
    return gate.evaluate(CFG, text, files, lambda sid: sid in scenarios, [])


class Gate(unittest.TestCase):
    def test_unfilled_template_fails(self):
        self.assertEqual([r for r, _ in run(TEMPLATE, [API])[0]].count("template"), 2)

    def test_docs_only_passes(self):
        result = run(body("docs"), ["docs/server.md", "README.md"])
        self.assertEqual((result[0], result[1]), ([], []))

    def test_api_change_reaches_every_client(self):
        self.assertEqual(run(body("refactor"), [API])[1], sorted(CFG["labs"]))

    def test_docker_change_is_linux_only(self):
        self.assertEqual(run(body("chore"), ["docker/postgres/init/01-roles.sh"])[1], ["linux"])

    def test_fuzz_and_nextest_config_need_no_proof(self):
        self.assertEqual(run(body("chore"), ["fuzz/Cargo.toml", ".config/nextest.toml"])[1], [])

    def test_feature_needs_its_scenario_in_the_diff(self):
        self.assertEqual([r for r, _ in run(body("feature"), [API])[0]], ["scenario"])
        files = [API, "e2e/scenarios/leave-room/scenario.json"]
        self.assertEqual(run(body("feature", "leave-room"), files, ["leave-room"])[0], [])

    def test_scenario_missing_from_the_diff_fails(self):
        self.assertEqual([r for r, _ in run(body("fix", "leave-room"), [API], ["leave-room"])[0]], ["scenario"])


if __name__ == "__main__":
    unittest.main()
