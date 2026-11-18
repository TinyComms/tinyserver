# presence-states

Issue [#72](https://github.com/TinyComms/tinyserver/issues/72), first stage: a member can set
an availability (`online`, `idle`, `dnd`, `offline`) and a short status text with
`presence.set` over the live socket. Everyone who already sees `presence` gets the same
frame with the new `state` and `text` fields; older clients keep reading `user_id` and
`online`. The text is capped at 128 characters and the frame has its own rate.

The two tests run the real app against a fresh database:

- `live::a_member_sets_a_state_and_a_text_and_the_other_sockets_hear_it` — idle arrives as
  `state: "idle"`, `dnd` with the trimmed text arrives with both fields, an over-long text
  and a control character are refused with `bad_frame` and broadcast nothing, and the
  refused frames reach nobody.
- `bot_live::a_bot_without_members_read_hears_no_set_state_and_cannot_set_one` — a bot with
  `rooms.read` receives no presence frame for a set state and cannot set one (`forbidden`).
