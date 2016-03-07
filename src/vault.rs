use std::io;

use hashicorp_vault::Client;


pub fn initialize_vault<'a>(host: &'a str, token: &'a str) -> Client<'a> {
    // unwrap is here because we cannot sanely continue without a vault client
    Client::new(host, token).unwrap()
}

pub fn put_file_in_vault(vault: &Client, string: &String, hex: &String) -> Result<String, io::Error>{
    let _ = vault.set_secret(&hex[..], &string[..].replace("\n", "\\n")).unwrap();
    Ok("".to_string())
}

pub fn read_file_from_vault<'a>(vault: &'a Client, path: &String) -> Result<String, String> {
    // let path = path_to_str!(file);
    vault.get_secret(path).map_err(|e| e.to_string())
}
