use structopt::StructOpt;
use std::process;
use audit::Cli;

// TODO:
// - refactor main and put everything else in lib for better testing
// - only main should handle errors every other function should return Result<T,E>
// - print error messages to stderr (eprintln! macro)

fn main() {
    let args = Cli::from_args();

    if let Err(e) = audit::run(args) {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}
