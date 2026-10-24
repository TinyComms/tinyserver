//! A person's own account and invite revoke through the db functions. See `common`.

mod common;

use common::{first_owner, run, PASSWORD};
use db::{
    accept_invite, change_password, close_all_sessions, create_invite, current_session, list_audit,
    list_invites, open_session, remove_member, rename_me, revoke_invite, set_member_role, Caller,
    CommunityError, Wrote,
};

#[tokio::test]
async fn a_member_changes_a_password_a_name_and_signs_out_everywhere() {
    run(|db| async move {
        let pool = &db.runtime;
        let owner = first_owner(&db).await;
        let email = "account@tinyserver.test";
        let second_password = "second-account-password";

        let Ok(Wrote::Fresh(spare)) = create_invite(pool, &owner, "admin", None).await else {
            panic!("spare invite");
        };
        let Ok(Wrote::Fresh(issued)) = create_invite(pool, &owner, "member", None).await else {
            panic!("invite");
        };
        let accepted = accept_invite(pool, &issued.token, email, PASSWORD, "Guest")
            .await
            .expect("accept");
        let guest = Caller {
            user_id: accepted.user_id.clone(),
            role: accepted.role.clone(),
        };

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
        let demoted = current_session(pool, &accepted.token)
            .await
            .expect("demoted session");
        assert_eq!(demoted.role, "member");

        let other = open_session(pool, email, PASSWORD)
            .await
            .expect("second session");
        assert!(matches!(
            change_password(
                pool,
                &guest,
                &accepted.token,
                "wrong-password!",
                second_password
            )
            .await,
            Err(CommunityError::InvalidCredentials)
        ));
        assert!(matches!(
            change_password(pool, &guest, &accepted.token, PASSWORD, "short").await,
            Err(CommunityError::Invalid)
        ));
        let ended = change_password(pool, &guest, &accepted.token, PASSWORD, second_password)
            .await
            .expect("change password");
        assert_eq!(ended, 1);
        assert!(current_session(pool, &accepted.token).await.is_ok());
        assert!(current_session(pool, &other.token).await.is_err());
        assert!(open_session(pool, email, PASSWORD).await.is_err());

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
        assert_eq!(
            current_session(pool, &accepted.token)
                .await
                .expect("renamed session")
                .display_name,
            "Moss"
        );

        let again = open_session(pool, email, second_password)
            .await
            .expect("new password signs in");
        assert_eq!(
            close_all_sessions(pool, &guest).await.expect("close all"),
            2
        );
        assert!(current_session(pool, &accepted.token).await.is_err());
        assert!(current_session(pool, &again.token).await.is_err());

        // Removal ends sessions, and an invite back does not revive them.
        let kept = open_session(pool, email, second_password)
            .await
            .expect("session before removal");
        remove_member(pool, &owner, &guest.user_id)
            .await
            .expect("remove");
        assert!(current_session(pool, &kept.token).await.is_err());
        let Ok(Wrote::Fresh(back)) = create_invite(pool, &owner, "member", None).await else {
            panic!("invite back");
        };
        accept_invite(pool, &back.token, email, second_password, "Moss")
            .await
            .expect("accept again");
        assert!(current_session(pool, &kept.token).await.is_err());

        let actions: Vec<String> = list_audit(pool, &owner, 50)
            .await
            .expect("audit")
            .into_iter()
            .filter(|row| row.actor_id.as_deref() == Some(guest.user_id.as_str()))
            .map(|row| row.action)
            .collect();
        for action in [
            "invite.revoke",
            "account.password",
            "account.rename",
            "session.close_all",
        ] {
            assert!(actions.iter().any(|seen| seen == action), "{action}");
        }
    })
    .await;
}
