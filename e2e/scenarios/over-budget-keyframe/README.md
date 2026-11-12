# Over-budget keyframe: the keyframe that must get through

Run `sh e2e/scenarios/over-budget-keyframe/run.sh`. It needs no database and no
server process: the scenario drives the SFU crate on loopback with two headless
str0m clients, as `crates/sfu/tests/common` does.

Both camera layer budgets are set to 6 kb/s, so no fixture frame fits either
bucket. On the base the scenario fails: every frame is refused, the layer never
recovers, and the viewer's video slot stays empty. With the branch the oversized
keyframe passes on half a bucket, the slot names the source, and the viewer
sees it.

This is server integration evidence. It does not certify a released tinyclient
on the five platforms; those recordings are pending lab hosts. A lab host whose
local UDP loopback is filtered (a VPN kill switch does this) cannot drive this
driver: the str0m handshake needs real loopback ICE.
