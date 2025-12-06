use gh_workflow::generate::Generate;
use gh_workflow::*;

#[test]
fn main() {
    // Create the lint-fix job
    let lint_job = Job::new("Lint Fix")
        .name("Lint Fix")
        .runs_on("ubuntu-latest")
        .permissions(Permissions::default().contents(Level::Read))
        .add_step(Step::new("Checkout Code").uses("actions", "checkout", "v4"))
        .add_step(
            Step::new("Setup Rust Toolchain")
                .uses("actions-rust-lang", "setup-rust-toolchain", "v1")
                .with(
                    Input::default()
                        .add("toolchain", "nightly")
                        .add("components", "clippy, rustfmt")
                        .add("cache", "true")
                        .add(
                            "cache-directories",
                            "~/.cargo/registry\n~/.cargo/git\ntarget",
                        ),
                ),
        )
        .add_step(Step::new("Setup protoc").uses("arduino", "setup-protoc", "v3"))
        .add_step(Step::new("Cargo Fmt").run("cargo +nightly fmt --all"))
        .add_step(Step::new("Cargo Clippy").run(
            "cargo +nightly clippy --fix --allow-dirty --all-features --workspace -- -D warnings",
        ))
        .add_step(Step::new("autofix.ci").uses(
            "autofix-ci",
            "action",
            "551dded8c6cc8a1054039c8bc0b8b48c51dfc6ef",
        ))
        .concurrency(
            Concurrency::new(Expression::new("autofix-${{github.ref}}")).cancel_in_progress(false),
        );

    // Create the workflow
    let workflow = Workflow::new("autofix")
        .name("autofix.ci")
        .on(Event::default()
            .push(Push::default().add_branch("main").add_tag("v*"))
            .pull_request(
                PullRequest::default()
                    .add_branch("main")
                    .add_type(PullRequestType::Opened)
                    .add_type(PullRequestType::Synchronize)
                    .add_type(PullRequestType::Reopened),
            ))
        .env(Env::from(("RUSTFLAGS", "-Dwarnings")))
        .add_job("lint", lint_job);

    Generate::new(workflow)
        .name("autofix.yml")
        .generate()
        .unwrap();
}
