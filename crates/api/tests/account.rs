//! A person's own account and invite revoke through the db functions. See `common`.

mod common;

use common::{first_owner, invite_hash, profile, run, session};
use db::{
    close_all_sessions, create_invite, current_session, list_audit, list_invites, remove_member,
    rename_me, revoke_invite, set_member_role, Caller, CommunityError, Groups, Wrote,
};

#[tokio::test]
async fn a_member_changes_a_name_and_signs_out_everywhere() {
    run(|db| async move {
        let pool = &db.runtime;
        let owner = first_owner(&db).await;
        let email = "account@tinyserver.test";

        let Ok(Wrote::Fresh(spare)) = create_invite(pool, &owner, "admin", None).await else {
            panic!("spare invite");
        };
        let Ok(Wrote::Fresh(issued)) = create_invite(pool, &owner, "member", None).await else {
            panic!("invite");
        };
        let signed_in = db::sign_in(
            pool,
            &profile(email),
            Some(&invite_hash(&issued.token)),
            Groups::default(),
        )
        .await
        .expect("join");
        let guest = Caller {
            user_id: signed_in.user_id.clone(),
            role: signed_in.role.clone(),
        };
        let first = session(&db, &guest.user_id).await;

        assert!(matches!(
            revoke_invite(pool, &guest, &spare.id).await,
            Err(CommunityError::Forbidden)
        ));
        assert!(matches!(
            revoke_invite(pool, &owner, &issued.id).await,
            Err(CommunityError::NotFound)
        ));
        assert!(matches!(
            revoke_invite(pool, &owner, "not-a-uuid").await,
            Err(CommunityError::NotFound)
        ));
        set_member_role(pool, &owner, &guest.user_id, "admin")
            .await
            .expect("promote");
        let admin = Caller {
            user_id: guest.user_id.clone(),
            role: "admin".to_string(),
        };
        revoke_invite(pool, &admin, &spare.id)
            .await
            .expect("admin revokes");
        assert!(matches!(
            revoke_invite(pool, &admin, &spare.id).await,
            Err(CommunityError::NotFound)
        ));
        assert!(!list_invites(pool, &owner)
            .await
            .expect("invites")
            .iter()
            .any(|invite| invite.id == spare.id));
        set_member_role(pool, &owner, &guest.user_id, "member")
            .await
            .expect("demote");
        let demoted = current_session(pool, &first)
            .await
            .expect("demoted session");
        assert_eq!(demoted.role, "member");

        assert!(matches!(
            rename_me(pool, &guest, "   ").await,
            Err(CommunityError::Invalid)
        ));
        assert!(matches!(
            rename_me(pool, &guest, &"n".repeat(81)).await,
            Err(CommunityError::Invalid)
        ));
        let renamed = rename_me(pool, &guest, "  Moss  ").await.expect("rename");
        assert_eq!(renamed.display_name, "Moss");
        assert_eq!(renamed.email.as_deref(), Some(email));
        assert_eq!(
            current_session(pool, &first)
                .await
                .expect("renamed session")
                .display_name,
            "Moss"
        );

        let second = session(&db, &guest.user_id).await;
        assert_eq!(
            close_all_sessions(pool, &guest).await.expect("close all"),
            2
        );
        assert!(current_session(pool, &first).await.is_err());
        assert!(current_session(pool, &second).await.is_err());

        // Removal ends sessions, and an invite back does not revive them.
        let kept = session(&db, &guest.user_id).await;
        remove_member(pool, &owner, &guest.user_id)
            .await
            .expect("remove");
        assert!(current_session(pool, &kept).await.is_err());
        assert!(matches!(
            db::sign_in(pool, &profile(email), None, Groups::default()).await,
            Err(db::AuthError::NotMember)
        ));
        let Ok(Wrote::Fresh(back)) = create_invite(pool, &owner, "member", None).await else {
            panic!("invite back");
        };
        let returned = db::sign_in(
            pool,
            &profile(email),
            Some(&invite_hash(&back.token)),
            Groups::default(),
        )
        .await
        .expect("join again");
        assert_eq!(
            returned.user_id, guest.user_id,
            "the same (issuer, subject)"
        );
        assert!(current_session(pool, &kept).await.is_err());

        let actions: Vec<String> = list_audit(pool, &owner, 50)
            .await
            .expect("audit")
            .into_iter()
            .filter(|row| row.actor_id.as_deref() == Some(guest.user_id.as_str()))
            .map(|row| row.action)
            .collect();
        for action in [
            "invite.accept",
            "invite.revoke",
            "account.rename",
            "session.close_all",
        ] {
            assert!(actions.iter().any(|seen| seen == action), "{action}");
        }
    })
    .await;
}
