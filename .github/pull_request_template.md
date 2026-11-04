## What changed and why

<!-- Two or three short sentences. What can a member do now that they could not, or what no longer breaks? -->

## Type

<!-- Check one. feature and fix need an e2e scenario below. -->

- [ ] feature
- [ ] fix
- [ ] perf
- [ ] refactor
- [ ] chore
- [ ] docs

## Clients

<!-- A server change is proved by the last released tinyclient on each platform, driven against this branch.
     Check the ones you know this reaches. The gate adds every platform it finds in the diff, and you cannot take one off. -->

- [ ] windows
- [ ] macos
- [ ] linux
- [ ] android
- [ ] ios

## Proof

<!-- feature and fix: the scenario that drives a real client against this server and shows the change. It is in this diff.
     The lab records it on every client above, once against the base (it fails) and once against this branch
     (it passes), and posts the `e2e-proof` status. Do not paste your own screenshots in its place.
     A change a released client cannot show yet: say so, and name the client branch that will. -->

Scenario: e2e/scenarios/<id>

Lab run: <!-- link the lab posts under `e2e-proof` -->

## Compatibility

<!-- Older clients must keep working: docs/server.md, the table in docs/calls.md, docs/privacy/migration.md.
     Say what an older client sees. `GET /v1/capabilities` answers 404 on servers from before it. -->

## Migrations

<!-- None, or the file names. A migration needs a restore of a production-shaped dump, run forward, and the rollback written down. -->

## Risk and rollback

<!-- What breaks if this is wrong, and how it is undone: revert, the pre-deploy dump, the previous image. -->
