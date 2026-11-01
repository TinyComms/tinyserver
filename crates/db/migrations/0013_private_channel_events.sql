-- Live events for a channel go only to the members who can view that channel.
--
-- Before this, message.created, message.edited, message.deleted, reaction.updated and
-- channel.updated for a channel were emitted with a NULL audience, which is every member
-- socket. A member who was denied view_channel on a channel could not list or fetch it over
-- HTTP, but still received its message bodies, its overrides and a 200-character preview of
-- its last message over the live socket, and again from the 24 hour ?since replay.
--
-- The fix is here, in the one function every emit passes through, so no emit site can forget
-- it. A channel needs a narrowed audience only when someone can lack view_channel in it:
-- the @everyone role does not hold the bit, or some override touches it. Otherwise every
-- member can view it, NULL is exactly right, and the common case costs two index lookups.
--
-- The audience is the set that can view the channel when the event is emitted. A member
-- who gains access later does not receive earlier events, which is also what the HTTP
-- history already does for a channel they cannot view at the time they ask.

CREATE FUNCTION app_channel_viewers(p_channel uuid)
RETURNS uuid[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_restricted boolean;
    v_viewers uuid[];
BEGIN
    SELECT coalesce((SELECT (permissions & 1) = 0 FROM roles WHERE is_default), true)
        OR EXISTS (
            SELECT 1 FROM channel_overrides
            WHERE channel_id = p_channel AND ((allow | deny) & 1) <> 0
        )
    INTO v_restricted;
    IF NOT v_restricted THEN
        RETURN NULL;
    END IF;
    SELECT coalesce(array_agg(m.user_id), '{}')
    INTO v_viewers
    FROM memberships m
    WHERE (app_channel_perms_of(p_channel, m.user_id) & 1) = 1;
    -- An empty array reads as "everyone" to the socket. Owners always view, so this is a
    -- guard and not an expected state: nobody is the nil uuid.
    IF cardinality(v_viewers) = 0 THEN
        RETURN ARRAY['00000000-0000-0000-0000-000000000000'::uuid];
    END IF;
    RETURN v_viewers;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_channel_viewers(uuid) FROM PUBLIC;

-- The audience an event really gets. An explicit audience (a direct conversation, a user's own
-- events) is never widened. A NULL audience on an event about a channel is narrowed to the
-- channel's viewers. Anything else stays NULL.
CREATE FUNCTION app_scope_audience(p_payload jsonb, p_audience uuid[])
RETURNS uuid[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_text text;
    v_channel uuid;
BEGIN
    IF p_audience IS NOT NULL THEN
        RETURN p_audience;
    END IF;
    v_text := coalesce(
        p_payload #>> '{channel,id}',
        p_payload ->> 'channel_id',
        CASE WHEN p_payload ->> 'kind' = 'channel' THEN p_payload ->> 'conversation_id' END
    );
    IF v_text IS NULL OR v_text !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RETURN NULL;
    END IF;
    v_channel := v_text::uuid;
    PERFORM 1 FROM channels WHERE id = v_channel;
    IF NOT FOUND THEN
        -- channel.deleted: the row is gone and the event carries only the id.
        RETURN NULL;
    END IF;
    RETURN app_channel_viewers(v_channel);
END;
$$;

REVOKE EXECUTE ON FUNCTION app_scope_audience(jsonb, uuid[]) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_emit_to(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z]+\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, p_audience))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_emit(p_topic text, p_payload jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z]+\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, NULL))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
