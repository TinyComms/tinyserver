#!/usr/bin/env python3
"""The merge gate's cheap half: does this pull request carry the proof its change needs?

Reads e2e/gate.json and the pull request (its body, its changed files, the statuses on its head).

  pr-gate.py check          the required check `pr-gate` (needs GH_TOKEN, GITHUB_EVENT_PATH)
  pr-gate.py plan <number>  prints the platforms the lab has to record for that pull request, as
                            JSON. The lab (e2e/README.md) runs this, so it and the gate can never
                            disagree about what a change touches.

The expensive half is the lab, which records the real app on each platform and posts the
`e2e-proof` status. This script never fails a pull request for a missing recording; branch
protection does, once `e2e-proof` is a required status. It only says what is still missing.
"""
import fnmatch
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCENARIO_DIR = "e2e/scenarios"
ID = r"[a-z0-9][a-z0-9._-]*"


def load_config(path=None):
    with open(path or os.path.join(ROOT, "e2e", "gate.json"), encoding="utf-8") as f:
        return json.load(f)


def glob_to_regex(pattern):
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "$")


def matches(path, patterns):
    return any(glob_to_regex(p).match(path) for p in patterns)


def code_files(files, cfg):
    """The changed files that are not docs, site or licence text."""
    return [f for f in files if not matches(f, cfg["no_proof_paths"])]


def platforms_for(files, cfg):
    """The platforms the changed files reach, by gate.json's path map."""
    found = set()
    excludes = cfg.get("platform_excludes", {})
    for platform, patterns in cfg["platforms"].items():
        for f in code_files(files, cfg):
            if matches(f, patterns) and not matches(f, excludes.get(platform, [])):
                found.add(platform)
                break
    return found


def strip_comments(body):
    return re.sub(r"<!--.*?-->", "", body or "", flags=re.S)


def section(body, heading):
    """The text under `## heading`, up to the next `## `."""
    m = re.search(r"^##\s+" + re.escape(heading) + r"[^\n]*\n(.*?)(?=^##\s|\Z)", body, re.S | re.M)
    return m.group(1) if m else ""


def checked(body, words):
    return sorted({m.group(1).lower() for m in re.finditer(
        r"^\s*[-*]\s*\[[xX]\]\s*`?(" + "|".join(map(re.escape, words)) + r")\b", body, re.M)})


def parse_body(body, cfg):
    body = strip_comments(body)
    return {
        "what": section(body, "What changed").strip(),
        "types": checked(body, cfg["types"]),
        "declared": checked(body, cfg["labs"]),
        "scenarios": sorted(set(re.findall(SCENARIO_DIR + "/(" + ID + ")", section(body, "Proof")))),
    }


def evaluate(cfg, body, files, scenario_exists, statuses):
    """Returns (findings, plan). A finding is (rule, message). plan is the lab's work."""
    parsed = parse_body(body, cfg)
    findings = []
    code = code_files(files, cfg)

    if len(parsed["what"]) < 20:
        findings.append(("template", "Say what changed and why under '## What changed and why'."))
    if len(parsed["types"]) != 1:
        findings.append(("template", "Check exactly one type (feature, fix, perf, refactor, chore, docs); found %d." % len(parsed["types"])))
        kind = None
    else:
        kind = parsed["types"][0]

    if kind == "docs" and code:
        findings.append(("template", "Type is docs but the diff changes code: %s." % ", ".join(code[:3])))

    plan = sorted(platforms_for(files, cfg) | set(parsed["declared"])) if code else []

    if kind in cfg["proof_types"] and code:
        if not parsed["scenarios"]:
            findings.append(("scenario", "A %s needs an e2e scenario. Name it under '## Proof' as e2e/scenarios/<id>." % kind))
        for sid in parsed["scenarios"]:
            if not scenario_exists(sid):
                findings.append(("scenario", "%s/%s/scenario.json does not exist." % (SCENARIO_DIR, sid)))
            elif not any(f.startswith("%s/%s/" % (SCENARIO_DIR, sid)) for f in files):
                findings.append(("scenario", "Scenario %s is not in this diff. The scenario moves with the change, or it proves nothing new." % sid))

    states = {ctx: state for ctx, state in statuses}
    lab = {p: states.get("e2e-lab/" + p, "missing") for p in plan}
    proof = states.get(cfg["proof_context"], "missing")
    return findings, plan, lab, proof, kind


def summary(cfg, findings, plan, lab, proof, kind, enforced):
    rows = ["### pr-gate", ""]
    rows.append("Type: **%s**. Lab plan: %s." % (kind or "not chosen", ", ".join(plan) or "nothing to record"))
    rows.append("")
    for rule, msg in findings:
        rows.append("- %s **%s**: %s" % (":x:" if rule in enforced else ":warning:", rule, msg))
    if not findings:
        rows.append("- :white_check_mark: template and scenario rules pass")
    if plan:
        rows += ["", "| Platform | Recording |", "| --- | --- |"]
        rows += ["| %s | %s |" % (p, lab[p]) for p in plan]
        rows += ["", "`%s`: **%s**. The lab posts it when every platform above is recorded green." % (cfg["proof_context"], proof)]
    return "\n".join(rows) + "\n"


def gh(*args):
    out = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def trusted_state(status, actors):
    """A lab status counts only from the account the lab posts as. Empty `actors`: not set up yet."""
    login = (status.get("creator") or {}).get("login", "")
    if status["context"].startswith(("e2e-lab/", "e2e-proof", "e2e-release")) and actors and login not in actors:
        return "untrusted (posted by %s)" % (login or "unknown")
    return status["state"]


def pr_inputs(repo, number, cfg):
    pr = gh("repos/%s/pulls/%s" % (repo, number))
    pages = gh("repos/%s/pulls/%s/files" % (repo, number), "--paginate", "--slurp")
    files = [f["filename"] for page in pages for f in page]
    sha = pr["head"]["sha"]
    seen, statuses = set(), []
    for s in gh("repos/%s/commits/%s/statuses?per_page=100" % (repo, sha)) or []:
        if s["context"] not in seen:  # newest first
            seen.add(s["context"])
            statuses.append((s["context"], trusted_state(s, cfg.get("lab_actors", []))))
    return pr["body"] or "", files, statuses, sha


def scenario_at(repo, sha):
    """Whether the pull request's head has the scenario. The checkout here is the base."""
    def exists(sid):
        try:
            gh("repos/%s/contents/%s/%s/scenario.json?ref=%s" % (repo, SCENARIO_DIR, sid, sha))
            return True
        except subprocess.CalledProcessError:
            return False
    return exists


def main(argv):
    cfg = load_config()
    command = argv[1] if len(argv) > 1 else "check"
    repo = os.environ.get("GITHUB_REPOSITORY") or subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        capture_output=True, text=True).stdout.strip()

    if command == "plan":
        body, files, statuses, sha = pr_inputs(repo, argv[2], cfg)
        _, plan, _, _, _ = evaluate(cfg, body, files, scenario_at(repo, sha), statuses)
        print(json.dumps(plan))
        return 0

    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
        number = json.load(f)["pull_request"]["number"]
    body, files, statuses, sha = pr_inputs(repo, number, cfg)
    exists = scenario_at(repo, sha)
    findings, plan, lab, proof, kind = evaluate(cfg, body, files, exists, statuses)
    enforced = set(cfg["rules_enforced"])
    text = summary(cfg, findings, plan, lab, proof, kind, enforced)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    failed = False
    for rule, msg in findings:
        level = "error" if rule in enforced else "warning"
        print("::%s title=pr-gate %s::%s" % (level, rule, msg))
        failed = failed or rule in enforced
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
