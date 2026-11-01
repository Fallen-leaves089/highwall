use std::{env, path::PathBuf};

use anyhow::{bail, Context};
use highwall_native_core::{config::AppConfig, state::AppState};

struct Arguments {
    config: PathBuf,
    check: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = AppConfig::load(&arguments.config).with_context(|| {
        format!(
            "cannot load native configuration {}",
            arguments.config.display()
        )
    })?;
    if arguments.check {
        let _state = AppState::new(config)
            .await
            .context("native configuration failed runtime checks")?;
        println!("configuration ok");
        return Ok(());
    }
    highwall_native_core::server::run(config)
        .await
        .context("native server stopped")
}

fn parse_arguments() -> anyhow::Result<Arguments> {
    let mut config = env::var_os("HIGHWALL_NATIVE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("highwall-native.json"));
    let mut check = false;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("arguments must be valid UTF-8"))?;
        match text {
            "--check" => check = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("highwall-native-core {}", highwall_native_core::version());
                std::process::exit(0);
            }
            "--config" => {
                config = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?,
                );
            }
            "--config=*" => {
                config = PathBuf::from(&text["--config=".len()..]);
            }
            _ => bail!("unknown argument: {text}"),
        }
    }
    Ok(Arguments { config, check })
}

fn print_help() {
    println!(
        "highwall-native-core {}\n\nUSAGE:\n    highwall-native-core [--config PATH] [--check]\n\nOPTIONS:\n    --config PATH   JSON configuration path (default: HIGHWALL_NATIVE_CONFIG or highwall-native.json)\n    --check         Validate configuration, TLS material and audit initialization\n    -h, --help      Print help\n    -V, --version   Print version",
        highwall_native_core::version()
    );
}
