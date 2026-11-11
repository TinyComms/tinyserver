# Relay mode: the TURN client protocol

Run `sh e2e/scenarios/relay-turn-protocol/run.sh`. It needs no database, no server process,
and no network: the scenario drives `crates/sfu/src/turn.rs` against a fake challenge the
way the module's tests do.

On the base the scenario fails: `crates/sfu/src/turn.rs` does not exist, so cargo reports no
matching tests. With the branch it runs every test in the module (fifteen) and proves the
client answers its credentials challenge — 401 and 438, encoded the way RFC 5389 §15.6 lays
them out — with an authenticated re-request, takes an answer only once its MESSAGE-INTEGRITY
tag verifies (RFC 5389 §15.4), allocates with a four-byte REQUESTED-TRANSPORT, pads its send
indications to four, retries on the doubling RFC 5389 §7.2.1 schedule out to 39.5 seconds
and exhausts a server that never accepts, refreshes on its timers, queues a permission
behind a request in flight instead of losing it, keeps a permission or channel timeout from
killing the whole session, and drops datagrams without the magic cookie, with a mismatched
length, or an IPv6-only relay without spending its retries on them.

A lab host whose local UDP loopback is filtered (a VPN kill switch does this) cannot drive
the sfu integration suites; this scenario needs only the pure protocol logic, so it runs
wherever cargo does.
