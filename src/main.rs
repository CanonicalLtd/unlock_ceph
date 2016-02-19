#[macro_use] extern crate clap;

use clap::{Arg, App};


fn main() {
    let matches = clap::App::new("unlock_ceph")
        .version(crate_version!())
        .arg(Arg::with_name("source")
                            .short("s")
                            .help("Source directory to move files from")
                            .takes_value(true))
        .arg(Arg::with_name("destination")
                            .short("d")
                            .help("TMPFS to put files on")
                            .takes_value(true))
        .arg(Arg::with_name("vault")
                            .short("V")
                            .help("Vault server IP")
                            .takes_value(true))
        .arg(Arg::with_name("token")
                            .short("t")
                            .help("Vault authentication token")
                            .takes_value(true))
        .get_matches();

    println!("Matches is {:?}", matches);
}
