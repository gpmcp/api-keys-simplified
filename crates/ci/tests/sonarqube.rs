use gh_workflow::generate::Generate;
use gh_workflow::*;

#[test]
fn main() {
    let sonarqube_job = Job::new("sonarqube")
        .name("SonarQube")
        .runs_on("ubuntu-latest")
        .add_step(Step::checkout().with(Input::default().add("fetch-depth", "0")))
        .add_step(
            Step::new("SonarQube Scan")
                .uses("SonarSource", "sonarqube-scan-action", "v6")
                .env(Env::default().add("SONAR_TOKEN", "${{ secrets.SONAR_TOKEN }}")),
        );

    let workflow = Workflow::new("Build")
        .on(Event::default()
            .push(Push::default().add_branch("main"))
            .pull_request(
                PullRequest::default()
                    .add_type(PullRequestType::Opened)
                    .add_type(PullRequestType::Synchronize)
                    .add_type(PullRequestType::Reopened),
            ))
        .add_job("sonarqube", sonarqube_job);

    Generate::new(workflow)
        .name("sonarqube.yml")
        .generate()
        .unwrap();
}
