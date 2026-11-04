# e2e

Scenarios for the server follow the same contract as tinyclient's: see
[`e2e/README.md` there](https://github.com/TinyComms/tinyclient/blob/main/e2e/README.md). Here a
scenario is `e2e/scenarios/<id>/scenario.json` plus what it needs to stand up (this branch's
server, a fresh database, the seed), and it names the released client driver it uses.

Built: `pr-gate`, the pull request template, `gate.json`, and the `e2e:` line in
`deploy/release-cut.sh`. The lab itself is not built yet.
