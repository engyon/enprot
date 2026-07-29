// Generate the enprot(1) man page from the clap CLI definition.
// Usage: cargo run --features cli --example gen-manpage > enprot.1

use clap::CommandFactory;
use clap_mangen::Man;

fn main() -> std::io::Result<()> {
    let cmd = enprot::cli::Cli::command();
    let man = Man::new(cmd);
    man.render(&mut std::io::stdout())
}
