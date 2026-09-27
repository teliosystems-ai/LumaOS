//! Native Linux platform boundary. No model-provided command or shell execution.
mod bundle;
mod disk;
mod platform;
mod service;

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("this operation requires a local administrator".into());
    }
    // Privileged operations may hold passphrases; never permit core dumps.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err("cannot protect privileged process memory".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = dispatch() {
        eprintln!("luma-platform: {error}");
        std::process::exit(1);
    }
}

fn dispatch() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("inventory") if args.len() == 1 => disk::inventory(),
        Some("verify") if args.len() == 2 => {
            let verified = bundle::verify(Path::new(&args[1]))?;
            println!("{}", serde_json::to_string_pretty(&verified.manifest)?);
            Ok(())
        }
        Some("install") if args.len() == 3 => platform::install(&args[1], Path::new(&args[2])),
        Some("update") if args.len() == 2 => platform::update(Path::new(&args[1])),
        Some("recover") if args.len() >= 3 => platform::recover(&args[1..]),
        Some("broker") if args.len() == 1 => service::serve(),
        Some("status") if args.len() == 1 => service::client("status"),
        Some("boot-health") if args.len() == 1 => platform::boot_health(),
        Some("boot-failed") if args.len() == 1 => platform::boot_failed(),
        Some("init-data") if args.len() == 2 => platform::init_data(&args[1]),
        Some("help" | "--help") | None => {
            println!("Luma native platform alpha\n\n  inventory\n  verify BUNDLE\n  install /dev/disk/by-id/EXACT-ID BUNDLE\n  update BUNDLE\n  recover unlock /dev/disk/by-id/EXACT-ID\n  recover export /dev/disk/by-id/EXACT-ID EMPTY-DESTINATION\n  recover repair-a|repair-b /dev/disk/by-id/EXACT-ID BUNDLE\n  recover repair-data /dev/disk/by-id/EXACT-ID\n  recover disable-model /dev/disk/by-id/EXACT-ID\n  status\n\nInstall requires local interactive disk confirmation and new credentials.\nLaboratory image: native acceptance and production custody are outstanding.");
            Ok(())
        }
        _ => Err("unknown operation or wrong argument count; run --help".into()),
    }
}
