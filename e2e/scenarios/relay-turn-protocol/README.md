# Relay mode: the TURN client protocol

Run `sh e2e/scenarios/relay-turn-protocol/run.sh`. It needs no database, no server process,
and no network: the scenario drives `crates/sfu/src/turn.rs` against a fake challenge the
way the module's tests do.

On the base the scenario fails: `crates/sfu/src/turn.rs` does not exist, so cargo reports no
matching tests. With the branch it proves the client answers its credentials challenge with
an authenticated re-request, retries on the documented schedule, and exhausts a server that
never accepts instead of asking forever.

A lab host whose local UDP loopback is filtered (a VPN kill switch does this) cannot drive
the sfu integration suites; this scenario needs only the pure protocol logic, so it runs
wherever cargo does.
