mod app;
mod auth;
mod config;
mod import;
mod keystore;
mod putty;
mod ssh;
mod sshconfig;
mod ui;

use color_eyre::Result;
use color_eyre::eyre::WrapErr;

/// The name and tagline come from `Cargo.toml` rather than being written out
/// again here. `concat!` folds them at compile time, so this stays a `&'static
/// str` — and the description cannot drift from the one crates.io and the
/// Homebrew formula show.
const HELP: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION"),
    "
",
    env!("CARGO_PKG_DESCRIPTION"),
    "

usage: ",
    env!("CARGO_PKG_NAME"),
    " [options]

options:
  -h, --help       print this help and exit
  -V, --version    print the version and exit

There are no other arguments. Hosts live in an inventory file that is created on
first run; add them from inside the app or edit the file by hand.
"
);

// Hand-rolled on purpose: two flags, neither taking a value, is less surface
// than a parser crate would carry.
//
// Returns the exit code when the process should stop here, `None` to carry on
// into the app.
fn handle_args() -> Option<i32> {
    // Only the first argument is inspected: every flag we accept exits the
    // process, so a second one could never be reached anyway.
    //
    // `args_os`, not `args`: the latter panics on argv that is not valid
    // unicode, and a stray byte in an argument should produce the usage error
    // below, not a crash report.
    let arg = std::env::args_os().nth(1)?;
    match &*arg.to_string_lossy() {
        "-h" | "--help" => {
            print!("{HELP}");
            Some(0)
        }
        "-V" | "--version" => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        other => {
            let name = env!("CARGO_PKG_NAME");
            eprintln!("{name}: unrecognised argument: {other}");
            eprintln!("try '{name} --help'");
            Some(2)
        }
    }
}

fn main() -> Result<()> {
    // Before anything else touches the terminal or the filesystem, so `--version`
    // answers in a packaging smoke test where there is no tty and no inventory
    // file yet.
    if let Some(code) = handle_args() {
        std::process::exit(code);
    }

    // Order matters. `ratatui::init` installs a panic hook that restores the
    // terminal, and it must sit on top of color-eyre's so the terminal is back in
    // cooked mode before any report is printed. Install color-eyre first.
    color_eyre::install()?;

    // ratatui hides the cursor while drawing and its restore path does not put
    // it back, so a panic would drop the user into a shell with an invisible
    // cursor. ratatui's own hook runs first and restores the terminal, then
    // calls this one — so by the time the cursor is shown, we are out of the
    // alternate screen and back in cooked mode.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = ui::show_cursor();
        let _ = ui::pop_title();
        previous_hook(info);
    }));

    // One place computes the path so load and save cannot disagree about it.
    let inventory_path = config::Inventory::path()?;
    // Explicit, not hidden inside `path()`: this touches the filesystem.
    config::Inventory::migrate_from_former_name(&inventory_path);
    let inventory = config::Inventory::load_from(&inventory_path)?;

    // The SSH side is async; the render loop is not. The runtime lives here and
    // background work reports back through a channel the loop drains without blocking.
    // Two workers, not one per core. The work here is a handful of I/O-bound
    // SSH connections; the default spawned a thread per core to sit idle.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    // `ratatui::run` would panic here when there is no terminal — piped output,
    // a cron job, a CI runner — and report it as a crash inside ratatui, which
    // tells the user nothing about what they did wrong.
    let mut terminal = ratatui::try_init()
        .wrap_err("luvienne is a terminal application and needs a terminal to draw on")?;

    // The window keeps whatever title the shell left it with otherwise, which is
    // how this ends up labelled "Terminal".
    let _ = ui::push_title();
    let _ = ui::set_title(ui::APP_TITLE);

    let result =
        app::App::new(inventory, inventory_path, runtime.handle().clone()).run(&mut terminal);

    ratatui::restore();
    // `ratatui::restore` leaves the cursor hidden and the title ours.
    let _ = ui::show_cursor();
    let _ = ui::pop_title();
    result
}
