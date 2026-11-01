//! Server management against a real Postgres: settings, the icon, roles and permissions,
//! overrides, the hierarchy, legacy role shapes, bans, timeouts, multi-use invites, the audit
//! log's filters, categories, and bootstrap. See `common` for the environment.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::{first_owner, invite_hash, join, profile, run, session, Call, TestDb};
use db::{perm, Caller, Groups, Wrote};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app(db: &TestDb) -> axum::Router {
    api::router(db.runtime.clone(), None)
}

async fn get(app: &axum::Router, token: &str, path: &str) -> (StatusCode, Value) {
    Call::new(Method::GET, path).token(token).send(app).await
}

async fn send(
    app: &axum::Router,
    token: &str,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    Call::new(method, path)
        .token(token)
        .json(body)
        .send(app)
        .await
}

/// A raw request, for the icon and oversized bodies. Sent as JSON, which the icon ignores. Returns the status, the headers, and the body bytes.
async fn raw(
    app: &axum::Router,
    token: &str,
    method: Method,
    path: &str,
    body: Vec<u8>,
    if_none_match: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("cf-connecting-ip", common::fresh_address());
    if let Some(etag) = if_none_match {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

fn error(code: &str) -> Value {
    json!({ "error": code })
}

async fn role_id(app: &axum::Router, token: &str, name: &str) -> String {
    let (_, roles) = get(app, token, "/v1/roles").await;
    roles
        .as_array()
        .expect("roles")
        .iter()
        .find(|role| role["name"] == name)
        .and_then(|role| role["id"].as_str())
        .expect("role")
        .to_string()
}

async fn new_role(app: &axum::Router, token: &str, name: &str, permissions: i64) -> String {
    let (status, role) = send(
        app,
        token,
        Method::POST,
        "/v1/roles",
        json!({"name": name, "permissions": permissions, "color": "#22c55e"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{role}");
    role["id"].as_str().expect("id").to_string()
}

async fn give_roles(app: &axum::Router, token: &str, user_id: &str, role_ids: &[&str]) -> Value {
    let (status, member) = send(
        app,
        token,
        Method::PUT,
        &format!("/v1/members/{user_id}/roles"),
        json!({ "role_ids": role_ids }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{member}");
    member
}

async fn member_row(app: &axum::Router, token: &str, user_id: &str) -> Value {
    let (_, members) = get(app, token, "/v1/members").await;
    members
        .as_array()
        .expect("members")
        .iter()
        .find(|member| member["user_id"] == user_id)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn capabilities_and_me_describe_what_the_caller_may_do() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;

        let (status, _) = Call::new(Method::GET, "/v1/capabilities").send(&app).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = get(&app, &member_token, "/v1/capabilities").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        for feature in [
            "server",
            "roles",
            "categories",
            "bans",
            "timeouts",
            "invite_options",
            "audit_query",
            "voice_moderation",
            "upload_limits",
            "file_scan",
            "first_run_setup",
        ] {
            assert!(
                body["features"]
                    .as_array()
                    .expect("features")
                    .contains(&json!(feature)),
                "{feature}"
            );
        }

        let (_, me) = get(&app, &owner_token, "/v1/me").await;
        assert_eq!(me["role"], "owner");
        assert_eq!(me["owner"], true);
        assert_eq!(me["permissions"], perm::ALL);
        assert_eq!(me["rank"], i32::MAX);
        assert_eq!(me["roles"], json!([]));

        let (_, me) = get(&app, &member_token, "/v1/me").await;
        assert_eq!(me["user_id"], member.user_id);
        assert_eq!(me["role"], "member");
        assert_eq!(me["owner"], false);
        assert_eq!(me["permissions"], perm::EVERYONE);
        assert_eq!(me["rank"], 0);
    })
    .await;
}

#[tokio::test]
async fn the_server_has_settings_and_an_icon_that_only_manage_server_changes() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (_, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;
        let lobby = common::live::room(&db, &owner, "Lobby").await;

        let (status, server) = get(&app, &member_token, "/v1/server").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(server["name"], "Tiny server");
        assert_eq!(server["icon"], Value::Null);
        assert_eq!(server["afk_timeout_secs"], 0);
        assert_eq!(server["image_max_bytes"], 8 * 1024 * 1024);
        assert_eq!(server["file_max_bytes"], 25 * 1024 * 1024);
        assert!(server["created_at"].is_string());

        let (status, body) = send(
            &app,
            &member_token,
            Method::PATCH,
            "/v1/server",
            json!({"name": "Mine"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));

        let (status, server) = send(
            &app,
            &owner_token,
            Method::PATCH,
            "/v1/server",
            json!({"name": " Atomic ", "welcome": "Hi", "default_room_id": lobby.id,
                   "afk_room_id": lobby.id, "afk_timeout_secs": 300,
                   "image_max_bytes": 1024 * 1024, "file_max_bytes": 50 * 1024 * 1024}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        assert_eq!(server["name"], "Atomic");
        assert_eq!(server["welcome"], "Hi");
        assert_eq!(server["description"], "");
        assert_eq!(server["default_room_id"], lobby.id);
        assert_eq!(server["afk_timeout_secs"], 300);
        assert_eq!(server["image_max_bytes"], 1024 * 1024);
        assert_eq!(server["file_max_bytes"], 50 * 1024 * 1024);

        let (status, server) = send(
            &app,
            &owner_token,
            Method::PATCH,
            "/v1/server",
            json!({"afk_room_id": null}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(server["afk_room_id"], Value::Null);
        assert_eq!(server["default_room_id"], lobby.id);

        for bad in [
            json!({"name": ""}),
            json!({"welcome": "w".repeat(2001)}),
            json!({"afk_timeout_secs": -1}),
            json!({"image_max_bytes": 0}),
            json!({"file_max_bytes": 100 * 1024 * 1024 + 1}),
            json!({"default_room_id": "00000000-0000-0000-0000-000000000000"}),
        ] {
            let (status, body) =
                send(&app, &owner_token, Method::PATCH, "/v1/server", bad.clone()).await;
            assert_eq!(
                (status, body),
                (StatusCode::BAD_REQUEST, error("invalid")),
                "{bad}"
            );
        }

        // The icon. A member is refused before the bytes are decoded.
        let stub = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![7; 100]].concat();
        let (status, _, _) = raw(
            &app,
            &member_token,
            Method::PUT,
            "/v1/server/icon",
            stub,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut png = tiny_png();
        png.extend_from_slice(b"%PDF-1.4");
        let (status, _, body) = raw(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/server/icon",
            png,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).expect("json");
        let sha = body["icon"].as_str().expect("sha").to_string();
        assert_eq!(sha.len(), 64);
        let (_, server) = get(&app, &member_token, "/v1/server").await;
        assert_eq!(server["icon"], sha);

        let (status, headers, bytes) = raw(
            &app,
            &member_token,
            Method::GET,
            "/v1/server/icon",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(
            !bytes.windows(4).any(|chunk| chunk == b"%PDF"),
            "the stored icon kept the upload trailer"
        );
        assert_eq!(headers[header::CONTENT_TYPE], "image/png");
        let etag = format!("\"{sha}\"");
        assert_eq!(headers[header::ETAG], etag.as_str());
        let (status, _, _) = raw(
            &app,
            &member_token,
            Method::GET,
            "/v1/server/icon",
            Vec::new(),
            Some(&etag),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);

        let (status, _, body) = raw(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/server/icon",
            b"GIF89a....".to_vec(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json"),
            error("unsupported_media")
        );
        let big = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![0; 300 * 1024]].concat();
        let (status, _, body) = raw(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/server/icon",
            big,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json"),
            error("too_large")
        );
        // Other routes keep the small body cap.
        let big_json = json!({"welcome": "w".repeat(64 * 1024)}).to_string();
        let (status, _, _) = raw(
            &app,
            &owner_token,
            Method::PATCH,
            "/v1/server",
            big_json.into_bytes(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let (status, _, _) = raw(
            &app,
            &owner_token,
            Method::DELETE,
            "/v1/server/icon",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = raw(
            &app,
            &member_token,
            Method::GET,
            "/v1/server/icon",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE action LIKE 'server.%' ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("audit");
        assert_eq!(
            actions,
            [
                "server.update",
                "server.update",
                "server.icon",
                "server.icon"
            ]
        );
    })
    .await;
}

#[tokio::test]
async fn roles_follow_the_hierarchy() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (admin, admin_token) = join(&db, &owner, "admin@tinyserver.test", "admin").await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;
        let (other, _) = join(&db, &owner, "o@tinyserver.test", "member").await;

        let (status, roles) = get(&app, &member_token, "/v1/roles").await;
        assert_eq!(status, StatusCode::OK);
        let roles = roles.as_array().expect("roles").clone();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0]["name"], "Admin");
        assert_eq!(roles[0]["position"], 1);
        assert_eq!(roles[0]["color"], "#3B82F6");
        assert_eq!(roles[0]["hoist"], true);
        assert_eq!(roles[0]["permissions"], perm::ALL);
        assert_eq!(roles[0]["member_count"], 1);
        assert_eq!(roles[1]["name"], "@everyone");
        assert_eq!(roles[1]["default"], true);
        assert_eq!(roles[1]["position"], 0);
        assert_eq!(roles[1]["permissions"], perm::EVERYONE);
        let admin_role = roles[0]["id"].as_str().expect("id").to_string();
        let everyone = roles[1]["id"].as_str().expect("id").to_string();

        // A member cannot make roles.
        let (status, body) = send(
            &app,
            &member_token,
            Method::POST,
            "/v1/roles",
            json!({"name": "Nope"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));

        // The admin's role lands just below the admin.
        let helper = new_role(&app, &admin_token, "Helper", perm::KICK_MEMBERS).await;
        let (_, roles) = get(&app, &owner_token, "/v1/roles").await;
        let names: Vec<&str> = roles
            .as_array()
            .expect("roles")
            .iter()
            .map(|role| role["name"].as_str().expect("name"))
            .collect();
        assert_eq!(names, ["Admin", "Helper", "@everyone"]);
        // The owner's lands at the top.
        let top = new_role(&app, &owner_token, "Top", 0).await;
        let (_, roles) = get(&app, &owner_token, "/v1/roles").await;
        assert_eq!(roles[0]["id"], top);

        // An admin edits roles below them, not their own or above.
        let (status, role) = send(
            &app,
            &admin_token,
            Method::PATCH,
            &format!("/v1/roles/{helper}"),
            json!({"color": null, "hoist": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{role}");
        assert_eq!(role["color"], Value::Null);
        assert_eq!(role["hoist"], true);
        assert_eq!(role["permissions"], perm::KICK_MEMBERS);
        for id in [&admin_role, &top] {
            let (status, body) = send(
                &app,
                &admin_token,
                Method::PATCH,
                &format!("/v1/roles/{id}"),
                json!({"name": "Mine"}),
            )
            .await;
            assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        }

        // Roles are given below the giver's rank, to people below it.
        let row = give_roles(&app, &admin_token, &member.user_id, &[&helper]).await;
        assert_eq!(row["roles"], json!([helper]));
        assert_eq!(row["role"], "member");
        let (status, body) = send(
            &app,
            &admin_token,
            Method::PUT,
            &format!("/v1/members/{}/roles", other.user_id),
            json!({"role_ids": [admin_role]}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        let (status, body) = send(
            &app,
            &admin_token,
            Method::PUT,
            &format!("/v1/members/{}/roles", owner.user_id),
            json!({"role_ids": []}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        let (status, body) = send(
            &app,
            &member_token,
            Method::PUT,
            &format!("/v1/members/{}/roles", other.user_id),
            json!({"role_ids": [helper]}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));

        // Someone with manage_roles cannot hand out bits they lack.
        let roler = new_role(&app, &owner_token, "Roler", perm::MANAGE_ROLES).await;
        let (roler_person, roler_token) = join(&db, &owner, "r@tinyserver.test", "member").await;
        give_roles(&app, &owner_token, &roler_person.user_id, &[&roler]).await;
        let (status, body) = send(
            &app,
            &roler_token,
            Method::POST,
            "/v1/roles",
            json!({"name": "Banner", "permissions": perm::BAN_MEMBERS}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));

        // @everyone stays.
        let (status, body) = Call::new(Method::DELETE, &format!("/v1/roles/{everyone}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, error("default_role"))
        );
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &format!("/v1/roles/{everyone}"),
            json!({"name": "everybody"}),
        )
        .await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, error("default_role"))
        );
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/roles/order",
            json!({"ids": [everyone]}),
        )
        .await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, error("default_role"))
        );

        // The owner reorders: Helper to the top.
        let (_, roles) = get(&app, &owner_token, "/v1/roles").await;
        let mut ids: Vec<String> = roles
            .as_array()
            .expect("roles")
            .iter()
            .filter(|role| role["default"] == false)
            .map(|role| role["id"].as_str().expect("id").to_string())
            .collect();
        ids.retain(|id| *id != helper);
        ids.insert(0, helper.clone());
        let (status, roles) = send(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/roles/order",
            json!({ "ids": ids }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{roles}");
        assert_eq!(roles[0]["id"], helper);
        // An admin cannot move a role at or above them.
        let mut reversed = ids.clone();
        reversed.reverse();
        let (status, body) = send(
            &app,
            &admin_token,
            Method::PUT,
            "/v1/roles/order",
            json!({ "ids": reversed }),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/roles/order",
            json!({ "ids": [helper] }),
        )
        .await;
        assert_eq!((status, body), (StatusCode::BAD_REQUEST, error("invalid")));

        // Deleting a role takes it from its members.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/roles/{helper}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            member_row(&app, &owner_token, &member.user_id).await["roles"],
            json!([])
        );

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE action LIKE 'role.%' ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("audit");
        assert!(actions.contains(&"role.create".to_string()));
        assert!(actions.contains(&"role.update".to_string()));
        assert!(actions.contains(&"role.order".to_string()));
        assert!(actions.contains(&"role.delete".to_string()));
        let _ = admin;
    })
    .await;
}

#[tokio::test]
async fn overrides_shape_room_permissions_and_visibility() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;
        let (_, other_token) = join(&db, &owner, "o@tinyserver.test", "member").await;
        let secret = common::live::room(&db, &owner, "Secret").await;
        let stage = common::live::room(&db, &owner, "Stage").await;
        let everyone = role_id(&app, &owner_token, "@everyone").await;
        let crew = new_role(&app, &owner_token, "Crew", 0).await;
        give_roles(&app, &owner_token, &member.user_id, &[&crew]).await;

        let (_, rooms) = get(&app, &member_token, "/v1/rooms").await;
        assert_eq!(rooms.as_array().expect("rooms").len(), 2);
        assert_eq!(rooms[0]["my_permissions"], perm::EVERYONE);
        assert_eq!(rooms[0]["bitrate_kbps"], 64);
        assert_eq!(rooms[0]["user_limit"], 0);
        assert_eq!(rooms[0]["overrides"], json!([]));

        // Hide Secret from @everyone; Crew sees it again.
        let (status, room) = send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/rooms/{}/overrides/{everyone}", secret.id),
            json!({"allow": 0, "deny": perm::VIEW_CHANNEL}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{room}");
        assert_eq!(
            room["overrides"],
            json!([{"role_id": everyone, "allow": 0, "deny": perm::VIEW_CHANNEL}])
        );
        let visible = |rooms: &Value| -> Vec<String> {
            rooms
                .as_array()
                .expect("rooms")
                .iter()
                .map(|room| room["name"].as_str().expect("name").to_string())
                .collect()
        };
        assert_eq!(
            visible(&get(&app, &other_token, "/v1/rooms").await.1),
            ["Stage"]
        );
        assert_eq!(
            visible(&get(&app, &member_token, "/v1/rooms").await.1),
            ["Stage"]
        );
        assert_eq!(
            visible(&get(&app, &owner_token, "/v1/rooms").await.1),
            ["Secret", "Stage"]
        );
        send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/rooms/{}/overrides/{crew}", secret.id),
            json!({"allow": perm::VIEW_CHANNEL, "deny": 0}),
        )
        .await;
        assert_eq!(
            visible(&get(&app, &member_token, "/v1/rooms").await.1),
            ["Secret", "Stage"]
        );

        // On Stage, @everyone may not speak, Crew may again; a role's deny beats @everyone's
        // allow. Non-channel bits in an override are dropped.
        send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/rooms/{}/overrides/{everyone}", stage.id),
            json!({"allow": perm::PRIORITY_SPEAKER | perm::BAN_MEMBERS, "deny": perm::SPEAK}),
        )
        .await;
        let (_, room) = send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/rooms/{}/overrides/{crew}", stage.id),
            json!({"allow": perm::SPEAK, "deny": perm::PRIORITY_SPEAKER | perm::VIDEO}),
        )
        .await;
        let everyone_override = room["overrides"]
            .as_array()
            .expect("overrides")
            .iter()
            .find(|o| o["role_id"] == everyone)
            .cloned()
            .expect("override");
        assert_eq!(everyone_override["allow"], perm::PRIORITY_SPEAKER);
        let stage_for = |rooms: &Value| {
            rooms
                .as_array()
                .expect("rooms")
                .iter()
                .find(|room| room["name"] == "Stage")
                .map(|room| room["my_permissions"].as_i64().expect("bits"))
                .expect("stage")
        };
        let other = stage_for(&get(&app, &other_token, "/v1/rooms").await.1);
        assert_eq!(
            other,
            (perm::EVERYONE & !perm::SPEAK) | perm::PRIORITY_SPEAKER
        );
        let crew_bits = stage_for(&get(&app, &member_token, "/v1/rooms").await.1);
        assert_eq!(crew_bits, perm::EVERYONE & !perm::VIDEO);
        // Server-wide permissions do not change.
        assert_eq!(
            get(&app, &member_token, "/v1/me").await.1["permissions"],
            perm::EVERYONE
        );

        // Overrides need manage_roles and manage_channels.
        let (status, _) = send(
            &app,
            &member_token,
            Method::PUT,
            &format!("/v1/rooms/{}/overrides/{everyone}", stage.id),
            json!({"allow": 0, "deny": 0}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = Call::new(
            Method::DELETE,
            &format!("/v1/rooms/{}/overrides/{everyone}", secret.id),
        )
        .token(&owner_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            visible(&get(&app, &other_token, "/v1/rooms").await.1).len(),
            2
        );

        // Room settings.
        let (status, room) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &format!("/v1/rooms/{}", stage.id),
            json!({"topic": "Shows", "user_limit": 5, "bitrate_kbps": 96, "ptt_only": true,
                   "video_enabled": false, "e2ee_required": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{room}");
        assert_eq!(room["topic"], "Shows");
        assert_eq!(room["user_limit"], 5);
        assert_eq!(room["bitrate_kbps"], 96);
        assert_eq!(room["ptt_only"], true);
        assert_eq!(room["video_enabled"], false);
        assert_eq!(room["e2ee_required"], true);
        assert_eq!(room["name"], "Stage");
        for bad in [json!({"bitrate_kbps": 8}), json!({"user_limit": 100})] {
            let (status, _) = send(
                &app,
                &owner_token,
                Method::PATCH,
                &format!("/v1/rooms/{}", stage.id),
                bad,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, _) = send(
            &app,
            &member_token,
            Method::PATCH,
            &format!("/v1/rooms/{}", stage.id),
            json!({"topic": "Mine"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn legacy_role_shapes_still_work() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (member, _) = join(&db, &owner, "m@tinyserver.test", "member").await;
        let (admin, admin_token) = join(&db, &owner, "a@tinyserver.test", "admin").await;
        let admin_role = role_id(&app, &owner_token, "Admin").await;

        // An invite for an admin gives the Admin role.
        let row = member_row(&app, &owner_token, &admin.user_id).await;
        assert_eq!(row["role"], "admin");
        assert_eq!(row["roles"], json!([admin_role]));
        assert_eq!(row["owner"], false);
        assert_eq!(row["joined_via"], "invite");
        assert_eq!(admin.role, "admin");

        let path = format!("/v1/members/{}", member.user_id);
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &path,
            json!({"role": "admin"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::OK, json!({"role": "admin"})));
        let row = member_row(&app, &owner_token, &member.user_id).await;
        assert_eq!(row["roles"], json!([admin_role]));
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &path,
            json!({"role": "member"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::OK, json!({"role": "member"})));
        assert_eq!(
            member_row(&app, &owner_token, &member.user_id).await["roles"],
            json!([])
        );
        // An admin cannot make an admin: the Admin role is not below them.
        let (status, body) = send(
            &app,
            &admin_token,
            Method::PATCH,
            &path,
            json!({"role": "admin"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &path,
            json!({"role": "guest"}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::BAD_REQUEST, error("invalid")));

        // The owner flag.
        let (status, row) = send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/members/{}/owner", member.user_id),
            json!({"owner": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{row}");
        assert_eq!(row["owner"], true);
        assert_eq!(row["role"], "owner");
        let (status, body) = send(
            &app,
            &admin_token,
            Method::PUT,
            &format!("/v1/members/{}/owner", member.user_id),
            json!({"owner": false}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));
        send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/members/{}/owner", member.user_id),
            json!({"owner": false}),
        )
        .await;
        let (status, body) = send(
            &app,
            &owner_token,
            Method::PUT,
            &format!("/v1/members/{}/owner", owner.user_id),
            json!({"owner": false}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::CONFLICT, error("last_owner")));

        // A legacy invite body.
        let (status, issued) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/invites",
            json!({"role": "admin"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["role"], "admin");
        assert_eq!(issued["role_ids"], json!([admin_role]));
        assert_eq!(issued["max_uses"], 1);
        assert!(issued["expires_at"].is_string());
    })
    .await;
}

#[tokio::test]
async fn a_ban_removes_the_person_and_keeps_them_out() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (admin, admin_token) = join(&db, &owner, "a@tinyserver.test", "admin").await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;

        let (status, body) = send(
            &app,
            &admin_token,
            Method::POST,
            "/v1/bans",
            json!({"user_id": owner.user_id}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("hierarchy")));
        let (status, body) = send(
            &app,
            &member_token,
            Method::POST,
            "/v1/bans",
            json!({"user_id": admin.user_id}),
        )
        .await;
        assert_eq!((status, body), (StatusCode::FORBIDDEN, error("forbidden")));

        let (status, ban) = send(
            &app,
            &admin_token,
            Method::POST,
            "/v1/bans",
            json!({"user_id": member.user_id, "reason": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{ban}");
        assert_eq!(ban["user_id"], member.user_id);
        assert_eq!(ban["reason"], "spam");
        assert_eq!(ban["banned_by"], admin.user_id);
        assert_eq!(ban["banned_by_name"], "Person");
        assert_eq!(ban["email"], "m@tinyserver.test");
        assert_eq!(ban["expires_at"], Value::Null);

        let (status, _) = get(&app, &member_token, "/v1/me").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            member_row(&app, &owner_token, &member.user_id).await,
            Value::Null
        );
        let (_, bans) = get(&app, &owner_token, "/v1/bans").await;
        assert_eq!(bans.as_array().expect("bans").len(), 1);
        let (status, _) = get(&app, &member_token, "/v1/bans").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A new invite, a joining group, and a plain sign-in are all refused.
        let Ok(Wrote::Fresh(invite)) = db::create_invite(&db.runtime, &owner, "member", None).await
        else {
            panic!("invite");
        };
        let refused = db::sign_in(
            &db.runtime,
            &profile("m@tinyserver.test"),
            Some(&invite_hash(&invite.token)),
            Groups::default(),
        )
        .await;
        assert!(
            matches!(refused, Err(db::AuthError::Banned)),
            "{:?}",
            refused.as_ref().err()
        );
        let groups = Groups {
            join: Some("member"),
            admin: false,
        };
        let refused = db::sign_in(&db.runtime, &profile("m@tinyserver.test"), None, groups).await;
        assert!(matches!(refused, Err(db::AuthError::Banned)));
        // The invite was not used up by the refusal.
        let uses: i32 = sqlx::query_scalar("SELECT uses FROM invites WHERE id = $1::uuid")
            .bind(&invite.id)
            .fetch_one(&db.owner)
            .await
            .expect("uses");
        assert_eq!(uses, 0);

        // Unbanned, the invite lets them back as the same account.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/bans/{}", member.user_id))
            .token(&admin_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let back = db::sign_in(
            &db.runtime,
            &profile("m@tinyserver.test"),
            Some(&invite_hash(&invite.token)),
            Groups::default(),
        )
        .await
        .expect("back");
        assert_eq!(back.user_id, member.user_id);

        // A ban that expires lets them back on its own.
        let (status, _) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/bans",
            json!({"user_id": member.user_id, "expires_at": "2000-01-01T00:00:00Z"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT action, subject_user_id::text, reason FROM audit_log
             WHERE action IN ('member.ban', 'member.unban') ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("audit");
        assert_eq!(
            rows,
            vec![
                (
                    "member.ban".to_string(),
                    Some(member.user_id.clone()),
                    Some("spam".to_string())
                ),
                (
                    "member.unban".to_string(),
                    Some(member.user_id.clone()),
                    None
                ),
            ]
        );
    })
    .await;
}

#[tokio::test]
async fn timeouts_last_up_to_28_days() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (admin, admin_token) = join(&db, &owner, "a@tinyserver.test", "admin").await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;
        let path = format!("/v1/members/{}/timeout", member.user_id);

        let soon = chrono::Utc::now() + chrono::Duration::hours(1);
        let until = soon.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let (status, row) = send(
            &app,
            &member_token,
            Method::PUT,
            &format!("/v1/members/{}/timeout", admin.user_id),
            json!({"until": until}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{row}");
        let (status, row) = send(
            &app,
            &admin_token,
            Method::PUT,
            &path,
            json!({"until": until, "reason": "cool off"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{row}");
        assert_eq!(row["timeout_until"], until);
        let too_long = (chrono::Utc::now() + chrono::Duration::days(29))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let (status, _) = send(
            &app,
            &admin_token,
            Method::PUT,
            &path,
            json!({"until": too_long}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(
            &app,
            &admin_token,
            Method::PUT,
            &path,
            json!({"until": "2000-01-01T00:00:00Z"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(
            &app,
            &admin_token,
            Method::PUT,
            &format!("/v1/members/{}/timeout", owner.user_id),
            json!({"until": until}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, row) = send(
            &app,
            &owner_token,
            Method::PUT,
            &path,
            json!({"until": null}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(row["timeout_until"], Value::Null);
        let reason: Option<String> = sqlx::query_scalar(
            "SELECT reason FROM audit_log WHERE action = 'member.timeout' ORDER BY id LIMIT 1",
        )
        .fetch_one(&db.owner)
        .await
        .expect("audit");
        assert_eq!(reason.as_deref(), Some("cool off"));
    })
    .await;
}

#[tokio::test]
async fn invites_take_a_label_uses_roles_and_an_expiry() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let crew = new_role(&app, &owner_token, "Crew", perm::VIDEO).await;
        let inviter = new_role(&app, &owner_token, "Inviter", perm::CREATE_INVITES).await;
        let (helper, helper_token) = join(&db, &owner, "h@tinyserver.test", "member").await;
        give_roles(&app, &owner_token, &helper.user_id, &[&inviter]).await;

        let (status, issued) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/invites",
            json!({"label": "for friends", "max_uses": 2, "expires_in_secs": 3600,
                   "role_ids": [crew]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["label"], "for friends");
        assert_eq!(issued["max_uses"], 2);
        assert_eq!(issued["role_ids"], json!([crew]));
        assert_eq!(issued["role"], "member");
        let token = issued["token"].as_str().expect("token").to_string();

        let mut joined = Vec::new();
        for email in ["one@tinyserver.test", "two@tinyserver.test"] {
            let person = db::sign_in(
                &db.runtime,
                &profile(email),
                Some(&invite_hash(&token)),
                Groups::default(),
            )
            .await
            .expect("join");
            joined.push(person.user_id);
        }
        let third = db::sign_in(
            &db.runtime,
            &profile("three@tinyserver.test"),
            Some(&invite_hash(&token)),
            Groups::default(),
        )
        .await;
        assert!(matches!(third, Err(db::AuthError::NotMember)));
        for user_id in &joined {
            assert_eq!(
                member_row(&app, &owner_token, user_id).await["roles"],
                json!([crew])
            );
        }

        // Used up, it leaves the list; the bootstrap invite's creator is null.
        let (status, list) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/invites",
            json!({"max_uses": null, "expires_in_secs": null}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{list}");
        assert_eq!(list["max_uses"], Value::Null);
        assert_eq!(list["expires_at"], Value::Null);
        let (_, invites) = get(&app, &owner_token, "/v1/invites").await;
        let invites = invites.as_array().expect("invites");
        assert_eq!(invites.len(), 1, "{invites:?}");
        assert_eq!(invites[0]["created_by"], owner.user_id);
        assert_eq!(invites[0]["created_by_name"], "Owner");
        assert_eq!(invites[0]["uses"], 0);

        // create_invites alone: no roles, no endless invites, only one's own to revoke.
        for body in [
            json!({"role_ids": [crew]}),
            json!({"expires_in_secs": null}),
        ] {
            let (status, _) = send(
                &app,
                &helper_token,
                Method::POST,
                "/v1/invites",
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }
        for body in [json!({"max_uses": 0}), json!({"expires_in_secs": 30})] {
            let (status, _) = send(
                &app,
                &helper_token,
                Method::POST,
                "/v1/invites",
                body.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
        let (status, mine) = send(
            &app,
            &helper_token,
            Method::POST,
            "/v1/invites",
            json!({"label": "mine"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let theirs = list["id"].as_str().expect("id");
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/invites/{theirs}"))
            .token(&helper_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = Call::new(
            Method::DELETE,
            &format!("/v1/invites/{}", mine["id"].as_str().expect("id")),
        )
        .token(&helper_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/invites/{theirs}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    })
    .await;
}

#[tokio::test]
async fn the_audit_log_pages_and_filters_with_names() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (member, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;
        for name in ["A", "B", "C"] {
            common::live::room(&db, &owner, name).await;
        }
        let (status, _) = Call::new(
            Method::DELETE,
            &format!("/v1/members/{}?reason=too%20loud", member.user_id),
        )
        .token(&owner_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, _) = get(&app, &member_token, "/v1/audit").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (_, first) = get(&app, &owner_token, "/v1/audit?limit=2").await;
        let first = first.as_array().expect("rows").clone();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0]["action"], "member.remove");
        assert_eq!(first[0]["actor_name"], "Owner");
        assert_eq!(first[0]["subject_user_id"], member.user_id);
        assert_eq!(first[0]["subject_name"], "Person");
        assert_eq!(first[0]["reason"], "too loud");
        let before = first[1]["id"].as_i64().expect("id");
        let (_, next) = get(
            &app,
            &owner_token,
            &format!("/v1/audit?limit=2&before={before}"),
        )
        .await;
        let next = next.as_array().expect("rows");
        assert_eq!(next.len(), 2);
        assert!(next
            .iter()
            .all(|row| row["id"].as_i64().expect("id") < before));

        let (_, rooms) = get(&app, &owner_token, "/v1/audit?action=room.").await;
        let rooms = rooms.as_array().expect("rows");
        assert_eq!(rooms.len(), 3);
        assert!(rooms.iter().all(|row| row["action"] == "room.create"));
        let (_, by_member) = get(
            &app,
            &owner_token,
            &format!("/v1/audit?actor={}", member.user_id),
        )
        .await;
        let by_member = by_member.as_array().expect("rows");
        assert_eq!(by_member.len(), 1, "{by_member:?}");
        assert_eq!(by_member[0]["action"], "invite.accept");
        assert_eq!(by_member[0]["actor_name"], "Person");
        let (status, _) = get(&app, &owner_token, "/v1/audit?actor=nope").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // The bootstrap row has no actor.
        let (_, setup) = get(&app, &owner_token, "/v1/audit?action=bootstrap").await;
        assert_eq!(setup[0]["actor_id"], Value::Null);
        assert_eq!(setup[0]["actor_name"], Value::Null);
    })
    .await;
}

#[tokio::test]
async fn categories_and_the_layout_order_rooms() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let owner_token = session(&db, &owner.user_id).await;
        let (_, member_token) = join(&db, &owner, "m@tinyserver.test", "member").await;

        let (status, voice) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/categories",
            json!({"name": "Voice"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, games) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/categories",
            json!({"name": "Games"}),
        )
        .await;
        let (status, _) = send(
            &app,
            &member_token,
            Method::POST,
            "/v1/categories",
            json!({"name": "No"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let voice_id = voice["id"].as_str().expect("id").to_string();
        let games_id = games["id"].as_str().expect("id").to_string();

        let (status, lounge) = send(
            &app,
            &owner_token,
            Method::POST,
            "/v1/rooms",
            json!({"name": "Lounge", "category_id": voice_id, "user_limit": 4}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{lounge}");
        assert_eq!(lounge["category_id"], voice_id);
        assert_eq!(lounge["user_limit"], 4);
        let lobby = common::live::room(&db, &owner, "Lobby").await;
        let pit = common::live::room(&db, &owner, "Pit").await;

        let (status, layout) = send(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/layout",
            json!({"categories": [
                {"id": null, "room_ids": [pit.id]},
                {"id": games_id, "room_ids": [lobby.id]},
                {"id": voice_id, "room_ids": [lounge["id"]]},
            ]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{layout}");
        let names = |rooms: &Value| -> Vec<String> {
            rooms
                .as_array()
                .expect("rooms")
                .iter()
                .map(|room| room["name"].as_str().expect("name").to_string())
                .collect()
        };
        assert_eq!(names(&layout["rooms"]), ["Pit", "Lobby", "Lounge"]);
        assert_eq!(layout["categories"][0]["name"], "Games");
        let (_, categories) = get(&app, &member_token, "/v1/categories").await;
        assert_eq!(categories[0]["id"], games_id);
        assert_eq!(categories[1]["id"], voice_id);
        assert_eq!(
            names(&get(&app, &member_token, "/v1/rooms").await.1),
            ["Pit", "Lobby", "Lounge"]
        );

        let (status, _) = send(
            &app,
            &owner_token,
            Method::PUT,
            "/v1/layout",
            json!({"categories": [{"id": null, "room_ids": [pit.id, pit.id]}]}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, renamed) = send(
            &app,
            &owner_token,
            Method::PATCH,
            &format!("/v1/categories/{games_id}"),
            json!({"name": "Play"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(renamed["name"], "Play");
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/categories/{games_id}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, rooms) = get(&app, &member_token, "/v1/rooms").await;
        let lobby_row = rooms
            .as_array()
            .expect("rooms")
            .iter()
            .find(|room| room["id"] == lobby.id)
            .cloned()
            .expect("lobby");
        assert_eq!(lobby_row["category_id"], Value::Null);
    })
    .await;
}

#[tokio::test]
async fn bootstrap_keeps_a_working_owner_invite() {
    run(|db| async move {
        let first = db::bootstrap(&db.owner, false).await.expect("bootstrap");
        let db::Bootstrap::Created(issued) = first else {
            panic!("created: {first:?}");
        };
        let again = db::bootstrap(&db.owner, false).await.expect("bootstrap");
        assert_eq!(
            again,
            db::Bootstrap::Pending {
                id: issued.id.clone(),
                expires_at: issued.expires_at.clone().expect("expiry"),
            }
        );
        let count = |action: &'static str| {
            let pool = db.owner.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_log WHERE action = $1")
                    .bind(action)
                    .fetch_one(&pool)
                    .await
                    .expect("count")
            }
        };
        assert_eq!(count("bootstrap").await, 1);

        // An expired one is replaced.
        sqlx::query("UPDATE invites SET expires_at = now() - interval '1 minute'")
            .execute(&db.owner)
            .await
            .expect("expire");
        let db::Bootstrap::Created(fresh) = db::bootstrap(&db.owner, false).await.expect("b")
        else {
            panic!("created");
        };
        assert_ne!(fresh.id, issued.id);
        assert_eq!(count("bootstrap").await, 2);
        // --owner-invite replaces a working one.
        let db::Bootstrap::Created(forced) = db::bootstrap(&db.owner, true).await.expect("b")
        else {
            panic!("created");
        };
        let alive: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM invites WHERE role = 'owner' AND expires_at > now()",
        )
        .fetch_one(&db.owner)
        .await
        .expect("alive");
        assert_eq!(alive, 1);

        let owner = db::sign_in(
            &db.runtime,
            &profile(common::OWNER_EMAIL),
            Some(&invite_hash(&forced.token)),
            Groups::default(),
        )
        .await
        .expect("owner");
        assert_eq!(owner.role, "owner");
        assert_eq!(
            db::bootstrap(&db.owner, false).await.expect("b"),
            db::Bootstrap::OwnerExists
        );
        let owner = Caller {
            scopes: Vec::new(),
            user_id: owner.user_id,
            role: owner.role,
        };
        let token = session(&db, &owner.user_id).await;
        let (_, invites) = get(&app(&db), &token, "/v1/invites").await;
        assert_eq!(
            invites,
            json!([]),
            "the used owner invite is gone from the list"
        );
    })
    .await;
}

#[tokio::test]
async fn a_member_sets_their_own_picture() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (member, token) = join(&db, &owner, "face@tinyserver.test", "member").await;
        let png = tiny_png();
        let (status, _, _) = raw(
            &app,
            &token,
            Method::PUT,
            "/v1/me/avatar",
            b"GIF89a".to_vec(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (status, _, body) = raw(
            &app,
            &token,
            Method::PUT,
            "/v1/me/avatar",
            png.clone(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).expect("json");
        let sha = body["avatar"].as_str().expect("sha").to_string();
        assert_eq!(sha.len(), 64);
        let path = format!("/v1/users/{}/avatar", member.user_id);
        let (status, headers, bytes) =
            raw(&app, &token, Method::GET, &path, Vec::new(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(headers[header::CONTENT_TYPE], "image/png");
        let row = member_row(&app, &token, &member.user_id).await;
        assert_eq!(row["avatar"], sha);
        let owner_token = session(&db, &owner.user_id).await;
        let (status, _, owner_bytes) =
            raw(&app, &owner_token, Method::GET, &path, Vec::new(), None).await;
        assert_eq!((status, owner_bytes), (StatusCode::OK, bytes));
        let (status, _, _) = raw(
            &app,
            &token,
            Method::GET,
            "/v1/users/00000000-0000-0000-0000-000000000000/avatar",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let big = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![0; 300 * 1024]].concat();
        let (status, _, _) = raw(&app, &token, Method::PUT, "/v1/me/avatar", big, None).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _, _) = raw(
            &app,
            &token,
            Method::DELETE,
            "/v1/me/avatar",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = raw(&app, &token, Method::GET, &path, Vec::new(), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let row = member_row(&app, &token, &member.user_id).await;
        assert!(row["avatar"].is_null());
    })
    .await;
}

/// 1×1 RGB PNG. The same bytes `rewrite_raster` accepts in the db tests.
fn tiny_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8,
        0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0xC9, 0xFE, 0x92, 0xEF, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}
