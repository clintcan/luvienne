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
    " [options] [host]

options:
  -h, --help       print this help and exit
  -V, --version    print the version and exit

Naming a host connects to it straight away, exactly as selecting it in the list
would; detaching drops you back into the list. Without one, luvienne opens on
the list.

Hosts live in an inventory file that is created on first run; add them from
inside the app or edit the file by hand.
"
);

/// What the command line asked for.
enum Args {
    /// Print something and stop, with this exit code.
    Exit(i32),
    /// Open the app, connecting to this host straight away if one was named.
    Run { target: Option<String> },
}

// Hand-rolled on purpose: two flags and one optional operand, none of them
// taking a value, is less surface than a parser crate would carry.
fn handle_args() -> Args {
    // `args_os`, not `args`: the latter panics on argv that is not valid
    // unicode, and a stray byte in an argument should produce the usage error
    // below, not a crash report.
    let mut args = std::env::args_os().skip(1);
    let Some(first) = args.next() else {
        return Args::Run { target: None };
    };

    // At most one. Every flag exits, and a second host name has no meaning —
    // there is one terminal to attach to.
    if args.next().is_some() {
        return usage_error("expected at most one argument");
    }

    match &*first.to_string_lossy() {
        "-h" | "--help" => {
            print!("{HELP}");
            Args::Exit(0)
        }
        "-V" | "--version" => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Args::Exit(0)
        }
        // A leading dash means a mistyped flag, not a host. Inventory names do
        // not start with one, and accepting it would report "no host called
        // --verbose" — an answer that sends the reader to the wrong file.
        other if other.starts_with('-') => usage_error(&format!("unrecognised argument: {other}")),
        host => Args::Run {
            target: Some(host.to_string()),
        },
    }
}

/// Exit 2, not 1: a usage error is not a crash, and `main`'s `Result` can only
/// ever produce 1.
fn usage_error(problem: &str) -> Args {
    let name = env!("CARGO_PKG_NAME");
    eprintln!("{name}: {problem}");
    eprintln!("try '{name} --help'");
    Args::Exit(2)
}

fn main() -> Result<()> {
    // Before anything else touches the terminal or the filesystem, so `--version`
    // answers in a packaging smoke test where there is no tty and no inventory
    // file yet.
    let target = match handle_args() {
        Args::Exit(code) => std::process::exit(code),
        Args::Run { target } => target,
    };

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

    // Resolved before the terminal is taken over, so a mistyped name is a line
    // on stderr rather than an error flashed inside a TUI that then sits there
    // waiting to be quit. `connection_chain` also catches an unreachable jump
    // host, which is the other way a named host cannot be connected to.
    if let Some(name) = &target
        && let Err(err) = inventory.connection_chain(name)
    {
        eprintln!("{}: {err}", env!("CARGO_PKG_NAME"));
        std::process::exit(1);
    }

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

    let mut app = app::App::new(inventory, inventory_path, runtime.handle().clone());
    // The dial runs on the runtime and reports through the same event channel
    // as any other connect, so the loop below picks up its progress, its host
    // key prompt and its failures without knowing this one started early.
    if let Some(name) = &target {
        app.connect_to(name);
    }
    let result = app.run(&mut terminal);

    ratatui::restore();
    // `ratatui::restore` leaves the cursor hidden and the title ours.
    let _ = ui::show_cursor();
    let _ = ui::pop_title();
    result
}
