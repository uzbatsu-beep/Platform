//! Dedicated Server administrative utility (`neon-cli`).

use clap::Parser;
use platform_cli_core::NeonCli;

fn main() {
    let cli = NeonCli::parse();
    eprintln!(
        "NEON CLI bootstrap initialized (command: {:?}). Command handlers are implemented in PR-03..PR-06.",
        cli.command
    );
    std::process::exit(2);
}
