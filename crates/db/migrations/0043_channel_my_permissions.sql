-- The channel list says what the caller may do in each channel. Rows of `app_list_channels`
-- gain `my_permissions`: the mask `app_channel_perms_of` already works out for every channel
-- permission check (every bit for an owner, nothing for a non-member), so what a body reports
-- cannot drift from what the server enforces. The events keep `app_channel_json`, which this
-- does not touch: the one payload still goes to every viewer unchanged. No table, column,
-- topic or status changes.

CREATE FUNCTION app_channel_json_of(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT app_channel_json(p_id) || jsonb_build_object(
        'my_permissions', app_channel_perms_of(p_id, app_uid())
    );
$$;

CREATE OR REPLACE FUNCTION app_list_channels()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(jsonb_agg(
        app_channel_json_of(c.id) ORDER BY c.position, c.name, c.id
    ), '[]'::jsonb)
    FROM channels c
    WHERE app_channel_perms_of(c.id, app_uid()) & 1 = 1
      AND app_is_member()
      AND NOT app_banned(app_uid());
$$;
