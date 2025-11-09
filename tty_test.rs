use atty;

fn main() {
    println!("stdin is tty: {}", atty::is(atty::Stream::Stdin));
    println!("stdout is tty: {}", atty::is(atty::Stream::Stdout));
    println!("stderr is tty: {}", atty::is(atty::Stream::Stderr));
}