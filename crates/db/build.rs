// `sqlx::migrate!` reads the migrations directory when the macro expands. On stable Rust
// nothing tells cargo that the directory is an input, so a new migration file leaves a cached
// build of this crate without it, and a binary that migrates less than the source says.
// This makes any change under migrations/ rebuild the crate.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
