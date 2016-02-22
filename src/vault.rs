use std::path::PathBuf;
use std::fs::File;
use std::io::prelude::*;
use std::io;

use hashicorp_vault::Client;

macro_rules! path_to_str (
    ($s:ident) => {
        &$s.to_string_lossy()[..].replace("/", "_|_")
    }
);

pub fn initialize_vault<'a>(host: &'a str, token: &'a str) -> Client<'a> {
    // unwrap is here because we cannot sanely continue without a vault client
    Client::new(host, token).unwrap()
}

pub fn put_file_in_vault(vault: &Client, file: &PathBuf) -> Result<String, io::Error>{
    let mut f = try!(File::open(file));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));

    let path = path_to_str!(file);

    vault.set_secret(path, &s[..]);
    Ok("".to_string())
}

pub fn read_file_from_vault<'a>(vault: &'a Client, file: &'a PathBuf) -> Result<String, String> {
    let path = path_to_str!(file);
    vault.get_secret(path).map_err(|e| e.to_string())
}
