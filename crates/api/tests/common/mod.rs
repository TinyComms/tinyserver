//! A fresh database for each test, migrated as `app_owner` and served as `app_runtime`.
//!
//! `TEST_DATABASE_URL_MIGRATE` connects as `app_owner`, which has CREATEDB.
//! `TEST_DATABASE_URL` connects as `app_runtime`. Only the database name is replaced.
//! When either is unset the test returns early and passes.

#![allow(dead_code)]

pub mod live;

use std::future::Future;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use db::{Caller, PgPool, Wrote};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection};
use tower::ServiceExt;

pub const OWNER_EMAIL: &str = "owner@tinyserver.test";
pub const OWNER_PASSWORD: &str = "owner-test-password";
pub const PASSWORD: &str = "person-test-password";

#[derive(Clone)]
pub struct TestDb {
    /// `app_owner`. Bypasses RLS. Use it only to arrange rows and read them back.
    pub owner: PgPool,
    /// `app_runtime`. What the server uses.
    pub runtime: PgPool,
}

/// Runs `test` against a new database and drops the database afterwards, even on a panic.
pub async fn run<F, Fut>(test: F)
where
    F: FnOnce(TestDb) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (Ok(migrate_url), Ok(runtime_url)) = (
        std::env::var("TEST_DATABASE_URL_MIGRATE"),
        std::env::var("TEST_DATABASE_URL"),
    ) else {
        eprintln!("skipped: TEST_DATABASE_URL_MIGRATE and TEST_DATABASE_URL are not set");
        return;
    };
    let admin = PgConnectOptions::from_str(&migrate_url).expect("TEST_DATABASE_URL_MIGRATE");
    let base_runtime = PgConnectOptions::from_str(&runtime_url).expect("TEST_DATABASE_URL");

    let mut connection = PgConnection::connect_with(&admin)
        .await
        .expect("connect as app_owner");
    let name: String = sqlx::query_scalar(
        "SELECT 'tinyserver_test_' || replace(gen_random_uuid()::text, '-', '')",
    )
    .fetch_one(&mut connection)
    .await
    .expect("database name");
    connection
        .execute(format!("CREATE DATABASE {name}").as_str())
        .await
        .expect("create test database");

    let owner = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(admin.clone().database(&name))
        .await
        .expect("owner pool");
    let runtime = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(base_runtime.clone().database(&name))
        .await
        .expect("runtime pool");

    let migrated = db::migrate(&owner).await;
    let outcome = match migrated {
        Ok(()) => Some(
            tokio::spawn(test(TestDb {
                owner: owner.clone(),
                runtime: runtime.clone(),
            }))
            .await,
        ),
        Err(_) => None,
    };

    runtime.close().await;
    owner.close().await;
    // A closed pool can leave idle backends behind, and DROP DATABASE waits on them.
    // Each role may end its own backends, so each one ends what it left in the test database.
    let ended = "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND usename = current_user AND pid <> pg_backend_pid()";
    if let Ok(mut as_runtime) = PgConnection::connect_with(&base_runtime).await {
        let _ = sqlx::query(ended)
            .bind(&name)
            .execute(&mut as_runtime)
            .await;
        let _ = as_runtime.close().await;
    }
    let _ = sqlx::query(ended)
        .bind(&name)
        .execute(&mut connection)
        .await;
    for attempt in 1..=10 {
        match connection
            .execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
            .await
        {
            Ok(_) => break,
            Err(error) if attempt == 10 => eprintln!("could not drop {name}: {error}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let _ = connection.close().await;
    if let Err(error) = migrated {
        panic!("migrate: {error}");
    }
    if let Some(Err(error)) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

/// Creates the first owner and returns the caller for them.
pub async fn first_owner(db: &TestDb) -> Caller {
    db::bootstrap_owner(&db.owner, OWNER_EMAIL, "Owner", OWNER_PASSWORD)
        .await
        .expect("bootstrap");
    let user_id: String =
        sqlx::query_scalar("SELECT id::text FROM users WHERE lower(email) = lower($1)")
            .bind(OWNER_EMAIL)
            .fetch_one(&db.owner)
            .await
            .expect("owner id");
    Caller {
        user_id,
        role: "owner".to_string(),
    }
}

/// Invites and accepts a person through the db functions. Returns the caller and a session token.
pub async fn join(db: &TestDb, by: &Caller, email: &str, role: &str) -> (Caller, String) {
    let Ok(Wrote::Fresh(issued)) = db::create_invite(&db.runtime, by, role, None).await else {
        panic!("invite");
    };
    let accepted = db::accept_invite(&db.runtime, &issued.token, email, PASSWORD, "Person")
        .await
        .expect("accept");
    (
        Caller {
            user_id: accepted.user_id,
            role: accepted.role,
        },
        accepted.token,
    )
}

pub async fn owner_count(db: &TestDb) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM memberships WHERE role = 'owner'")
        .fetch_one(&db.owner)
        .await
        .expect("owner count")
}

/// The SQLSTATE of a database error, or an empty string.
pub fn sqlstate(error: &sqlx::Error) -> String {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.to_string())
        .unwrap_or_default()
}

static ADDRESS: AtomicU32 = AtomicU32::new(1);

/// A different client address on every call, so tests do not share a rate limit bucket.
pub fn fresh_address() -> String {
    let n = ADDRESS.fetch_add(1, Ordering::Relaxed);
    format!("10.{}.{}.{}", (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
}

pub struct Call<'a> {
    pub method: Method,
    pub path: &'a str,
    pub token: Option<&'a str>,
    pub body: Option<Value>,
    pub address: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

impl<'a> Call<'a> {
    pub fn new(method: Method, path: &'a str) -> Self {
        Self {
            method,
            path,
            token: None,
            body: None,
            address: None,
            idempotency_key: None,
        }
    }

    pub fn token(mut self, token: &'a str) -> Self {
        self.token = Some(token);
        self
    }

    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    pub fn idempotency_key(mut self, key: &'a str) -> Self {
        self.idempotency_key = Some(key);
        self
    }

    pub fn address(mut self, address: &'a str) -> Self {
        self.address = Some(address);
        self
    }

    pub async fn send(self, app: &Router) -> (StatusCode, Value) {
        let address = match self.address {
            Some(address) => address.to_string(),
            None => fresh_address(),
        };
        let mut request = Request::builder()
            .method(self.method)
            .uri(self.path)
            .header("cf-connecting-ip", address);
        if let Some(key) = self.idempotency_key {
            request = request.header("idempotency-key", key);
        }
        if let Some(token) = self.token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let body = match self.body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = app
            .clone()
            .oneshot(request.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json body")
        };
        (status, value)
    }
}

/// Signs in over HTTP and returns the session token.
pub async fn sign_in(app: &Router, email: &str, password: &str) -> String {
    let (status, body) = Call::new(Method::POST, "/v1/session")
        .json(serde_json::json!({"email": email, "password": password}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "sign in: {body}");
    body["token"].as_str().expect("token").to_string()
}
