use gh_workflow::*;

#[test]
fn main() {
    // Build and Test job with coverage
    let build_job = Job::new("Build and Test")
        .name("Build and Test")
        .runs_on("ubuntu-latest")
        .permissions(Permissions::default().contents(Level::Read))
        .add_step(Step::new("Checkout Code").uses("actions", "checkout", "v4"))
        .add_step(
            Step::new("Setup Rust Toolchain")
                .uses("actions-rust-lang", "setup-rust-toolchain", "v1")
                .with(
                    Input::default()
                        .add("toolchain", "nightly")
                        .add("components", "llvm-tools-preview")
                        .add("cache", "true"),
                ),
        )
        .add_step(
            Step::new("Cache cargo-llvm-cov")
                .uses("actions", "cache", "v4")
                .with(
                    Input::default()
                        .add("path", "~/.cargo/bin/cargo-llvm-cov")
                        .add(
                            "key",
                            "${{ runner.os }}-cargo-llvm-cov-${{ hashFiles('**/Cargo.lock') }}",
                        )
                        .add("restore-keys", "${{ runner.os }}-cargo-llvm-cov-"),
                ),
        )
        .add_step(Step::new("Install cargo-llvm-cov").run("cargo install cargo-llvm-cov || true"))
        .add_step(Step::new("Generate coverage").run(
            "cargo +nightly llvm-cov --all-features --workspace --lcov --output-path lcov.info",
        ))
        .add_step(
            Step::new("Upload Coverage to Codecov")
                .uses("Wandalen", "wretry.action", "v3")
                .with(
                    Input::default()
                        .add("action", "codecov/codecov-action@v4")
                        .add("attempt_limit", "3")
                        .add("attempt_delay", "10000")
                        .add(
                            "with",
                            "token: ${{ secrets.CODECOV_TOKEN }}\nfiles: lcov.info",
                        ),
                ),
        );

    // Lint job
    let lint_job = Job::new("Lint")
        .name("Lint")
        .runs_on("ubuntu-latest")
        .permissions(Permissions::default().contents(Level::Read))
        .add_step(Step::new("Checkout Code").uses("actions", "checkout", "v4"))
        .add_step(
            Step::new("Setup Rust Toolchain")
                .uses("actions-rust-lang", "setup-rust-toolchain", "v1")
                .with(
                    Input::default()
                        .add("toolchain", "nightly")
                        .add("components", "clippy, rustfmt"),
                ),
        )
        .add_step(Step::new("Cargo Fmt").run("cargo +nightly fmt --all --check"))
        .add_step(
            Step::new("Cargo Clippy")
                .run("cargo +nightly clippy --all-features --workspace -- -D warnings"),
        );

    // Release job
    let release_job = Job::new("Release")
        .name("Release")
        .runs_on("ubuntu-latest")
        .needs(vec!["build".to_string(), "lint".to_string()])
        .cond(Expression::new(
            "${{ github.ref == 'refs/heads/main' && github.event_name == 'push' }}",
        ))
        .permissions(
            Permissions::default()
                .contents(Level::Write)
                .pull_requests(Level::Write)
                .packages(Level::Write),
        )
        .env(
            Env::default()
                .add("GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}")
                .add(
                    "CARGO_REGISTRY_TOKEN",
                    "${{ secrets.CARGO_REGISTRY_TOKEN }}",
                ),
        )
        .add_step(Step::new("Checkout Code").uses("actions", "checkout", "v4"))
        .add_step(
            Step::new("Release Plz")
                .uses("release-plz", "action", "v0.5")
                .with(Input::default().add("command", "release")),
        )
        .concurrency(
            Concurrency::new(Expression::new("release-${{github.ref}}")).cancel_in_progress(false),
        );

    // Release PR job
    let release_pr_job = Job::new("Release Pr")
        .name("Release Pr")
        .runs_on("ubuntu-latest")
        .needs(vec!["build".to_string(), "lint".to_string()])
        .cond(Expression::new(
            "${{ github.ref == 'refs/heads/main' && github.event_name == 'push' }}",
        ))
        .permissions(
            Permissions::default()
                .contents(Level::Write)
                .pull_requests(Level::Write)
                .packages(Level::Write),
        )
        .env(
            Env::default()
                .add("GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}")
                .add(
                    "CARGO_REGISTRY_TOKEN",
                    "${{ secrets.CARGO_REGISTRY_TOKEN }}",
                ),
        )
        .add_step(Step::new("Checkout Code").uses("actions", "checkout", "v4"))
        .add_step(
            Step::new("Release Plz")
                .uses("release-plz", "action", "v0.5")
                .with(Input::default().add("command", "release-pr")),
        )
        .concurrency(
            Concurrency::new(Expression::new("release-${{github.ref}}")).cancel_in_progress(false),
        );

    let workflow = Workflow::new("ci")
        .name("ci")
        .env(Env::from(("RUSTFLAGS", "-Dwarnings")))
        .on(Event::default()
            .pull_request(
                PullRequest::default()
                    .add_branch("main")
                    .add_type(PullRequestType::Opened)
                    .add_type(PullRequestType::Synchronize)
                    .add_type(PullRequestType::Reopened),
            )
            .push(Push::default().add_branch("main")))
        .add_job("build", build_job)
        .add_job("lint", lint_job)
        .add_job("release", release_job)
        .add_job("release-pr", release_pr_job);

    workflow.generate().unwrap();
}
