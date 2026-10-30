//! Community rules through the db functions against a real Postgres. See `common`.

mod common;

use std::time::Duration;

use common::{first_owner, invite_hash, join, owner_count, profile, run, session, TestDb};
use db::{
    create_invite, create_room, delete_room, list_audit, list_members, list_rooms, remove_member,
    set_member_role, AuthError, Caller, CommunityError, Groups, Swept, Wrote,
};

/// Two owners. The second is promoted by the first.
async fn two_owners(db: &TestDb) -> (Caller, Caller) {
    let first = first_owner(db).await;
    let (second, _) = join(db, &first, "second@tinyserver.test", "member").await;
    set_member_role(&db.runtime, &first, &second.user_id, "owner")
        .await
        .expect("promote");
    let second = Caller {
        role: "owner".to_string(),
        ..second
    };
    assert_eq!(owner_count(db).await, 2);
    (first, second)
}

#[tokio::test]
async fn a_second_demotion_waits_for_the_first_and_then_sees_the_last_owner() {
    run(|db| async move {
        let (first, second) = two_owners(&db).await;

        let mut held = db.runtime.begin().await.expect("begin");
        sqlx::query(
            "SELECT set_config('app.user_id', $1, true), set_config('app.role', 'owner', true)",
        )
        .bind(&first.user_id)
        .execute(&mut *held)
        .await
        .expect("scope");
        sqlx::query("SELECT app_set_member_role($1::uuid, 'member')")
            .bind(&first.user_id)
            .execute(&mut *held)
            .await
            .expect("first demotion");

        let pool = db.runtime.clone();
        let racer = tokio::spawn(async move {
            let mut tx = pool.begin().await.expect("begin");
            sqlx::query(
                "SELECT set_config('app.user_id', $1, true), set_config('app.role', 'owner', true)",
            )
            .bind(&second.user_id)
            .execute(&mut *tx)
            .await
            .expect("scope");
            let outcome = sqlx::query("SELECT app_set_member_role($1::uuid, 'member')")
                .bind(&second.user_id)
                .execute(&mut *tx)
                .await;
            if outcome.is_ok() {
                tx.commit().await.expect("commit");
            }
            outcome.map(|_| ()).map_err(|error| error.to_string())
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!racer.is_finished(), "the second demotion did not wait");
        held.commit().await.expect("commit first");

        let outcome = racer.await.expect("racer");
        let error = outcome.expect_err("the second demotion must fail");
        assert!(error.contains("last owner"), "{error}");
        assert_eq!(owner_count(&db).await, 1);
    })
    .await;
}

#[tokio::test]
async fn concurrent_demotions_and_removals_leave_one_owner() {
    run(|db| async move {
        let (first, second) = two_owners(&db).await;
        let (a, b) = tokio::join!(
            set_member_role(&db.runtime, &first, &first.user_id, "member"),
            set_member_role(&db.runtime, &second, &second.user_id, "member"),
        );
        assert_eq!(a.is_ok() as u8 + b.is_ok() as u8, 1, "{a:?} {b:?}");
        assert!(matches!(
            a.err().or(b.err()),
            Some(CommunityError::LastOwner)
        ));
        assert_eq!(owner_count(&db).await, 1);
    })
    .await;

    run(|db| async move {
        let (first, second) = two_owners(&db).await;
        let (a, b) = tokio::join!(
            remove_member(&db.runtime, &first, &second.user_id),
            remove_member(&db.runtime, &second, &first.user_id),
        );
        assert_eq!(a.is_ok() as u8 + b.is_ok() as u8, 1, "{a:?} {b:?}");
        assert_eq!(owner_count(&db).await, 1);
    })
    .await;
}

#[tokio::test]
async fn the_sweep_deletes_expired_rows_and_keeps_accepted_invites() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let arrange = [
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES
                 ($1::uuid, sha256('expired'::bytea), now() - interval '1 minute'),
                 ($1::uuid, sha256('live'::bytea), now() + interval '1 day')",
            "INSERT INTO invites (role, token_hash, created_by, expires_at, accepted_at, accepted_by) VALUES
                 ('member', sha256('expired'::bytea), $1::uuid, now() - interval '1 minute', NULL, NULL),
                 ('member', sha256('accepted'::bytea), $1::uuid, now() - interval '1 minute', now() - interval '1 day', $1::uuid),
                 ('member', sha256('live'::bytea), $1::uuid, now() + interval '1 day', NULL, NULL)",
            "INSERT INTO idempotency_keys (key, request_hash, expires_at) VALUES
                 ($1 || '-expired', 'h', now() - interval '1 minute'),
                 ($1 || '-live', 'h', now() + interval '1 day')",
            "INSERT INTO auth_pending (state_hash, provider, verifier, nonce, client_redirect,
                                      client_challenge, client_state, expires_at) VALUES
                 (sha256(('p-expired-' || $1)::bytea), 'default', 'v', 'n', 'r', 'c', 's', now() - interval '1 minute'),
                 (sha256(('p-live-' || $1)::bytea), 'default', 'v', 'n', 'r', 'c', 's', now() + interval '5 minutes')",
            "INSERT INTO auth_codes (code_hash, user_id, client_challenge, issuer, expires_at) VALUES
                 (sha256('c-expired'::bytea), $1::uuid, 'c', 'i', now() - interval '1 second'),
                 (sha256('c-live'::bytea), $1::uuid, 'c', 'i', now() + interval '1 minute')",
        ];
        for statement in arrange {
            sqlx::query(statement)
                .bind(&owner.user_id)
                .execute(&db.owner)
                .await
                .expect("arrange");
        }

        let swept = db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(
            swept,
            Swept {
                sessions: 1,
                invites: 1,
                idempotency_keys: 1,
                events: 0,
                logins: 2,
                attachments: 0,
            }
        );
        let left: (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM sessions),
                    (SELECT count(*) FROM invites),
                    (SELECT count(*) FROM idempotency_keys),
                    (SELECT count(*) FROM auth_pending),
                    (SELECT count(*) FROM auth_codes)",
        )
        .fetch_one(&db.owner)
        .await
        .expect("counts");
        // The owner's own invite, accepted by first_owner, is kept too.
        assert_eq!(left, (1, 3, 1, 1, 1));
        let accepted: i64 =
            sqlx::query_scalar("SELECT count(*) FROM invites WHERE accepted_at IS NOT NULL")
                .fetch_one(&db.owner)
                .await
                .expect("accepted");
        assert_eq!(accepted, 2);

        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").total(), 0);
    })
    .await;
}

#[tokio::test]
async fn an_owner_invites_a_person_who_leaves_and_comes_back() {
    run(|db| async move {
        let first = first_owner(&db).await;
        let opened = db::open_session(&db.runtime, &first.user_id)
            .await
            .expect("owner session");
        let owner = Caller {
            user_id: opened.identity.user_id,
            role: opened.identity.role,
        };
        assert_eq!(owner.role, "owner");
        let guest_email = "guest@tinyserver.test";

        let Ok(Wrote::Fresh(room)) = create_room(&db.runtime, &owner, "Moss", Some("room")).await
        else {
            panic!("room");
        };
        let Ok(Wrote::Replay(body)) = create_room(&db.runtime, &owner, "Moss", Some("room")).await
        else {
            panic!("replay");
        };
        assert_eq!(body["id"].as_str(), Some(room.id.as_str()));
        assert!(matches!(
            create_room(&db.runtime, &owner, "Other", Some("room")).await,
            Err(CommunityError::IdempotencyConflict)
        ));
        assert!(list_rooms(&db.runtime, &owner)
            .await
            .expect("rooms")
            .iter()
            .any(|item| item.id == room.id));

        let Ok(Wrote::Fresh(issued)) = create_invite(&db.runtime, &owner, "member", None).await
        else {
            panic!("invite");
        };
        assert!(matches!(
            db::sign_in(
                &db.runtime,
                &profile(guest_email),
                Some(&invite_hash("not-the-invite")),
                Groups::default()
            )
            .await,
            Err(AuthError::NotMember)
        ));
        let accepted = db::sign_in(
            &db.runtime,
            &profile(guest_email),
            Some(&invite_hash(&issued.token)),
            Groups::default(),
        )
        .await
        .expect("accept");
        let guest = Caller {
            user_id: accepted.user_id.clone(),
            role: accepted.role.clone(),
        };
        let guest_token = session(&db, &guest.user_id).await;
        assert_eq!(guest.role, "member");
        assert!(list_members(&db.runtime, &guest)
            .await
            .expect("members")
            .iter()
            .any(|member| member.user_id == guest.user_id && member.role == "member"));
        assert!(list_audit(&db.runtime, &owner, 20)
            .await
            .expect("audit")
            .iter()
            .any(|row| row.action == "invite.accept"));

        remove_member(&db.runtime, &owner, &guest.user_id)
            .await
            .expect("remove");
        assert!(db::current_session(&db.runtime, &guest_token)
            .await
            .is_err());

        let Ok(Wrote::Fresh(again)) = create_invite(&db.runtime, &owner, "member", None).await
        else {
            panic!("invite");
        };
        // The same email at another subject is someone else, and the invite makes them a new
        // account. Email never links.
        let mut stranger = profile(guest_email);
        stranger.subject = "someone-else".to_string();
        assert!(matches!(
            db::sign_in(&db.runtime, &stranger, None, Groups::default()).await,
            Err(AuthError::NotMember)
        ));
        let returned = db::sign_in(
            &db.runtime,
            &profile(guest_email),
            Some(&invite_hash(&again.token)),
            Groups::default(),
        )
        .await
        .expect("return");
        assert_eq!(returned.user_id, guest.user_id);

        delete_room(&db.runtime, &owner, &room.id)
            .await
            .expect("delete room");
        assert!(matches!(
            delete_room(&db.runtime, &owner, &room.id).await,
            Err(CommunityError::NotFound)
        ));
    })
    .await;
}
