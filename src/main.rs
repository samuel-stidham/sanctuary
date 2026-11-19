use std::process::ExitCode;

fn main() -> ExitCode {
    sanctuary::cmd::run(std::env::args_os().collect())
}
