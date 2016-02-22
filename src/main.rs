#[macro_use] extern crate clap;
extern crate hashicorp_vault;
#[macro_use] extern crate log;
extern crate simple_logger;
extern crate walkdir;

use std::fs;
use std::fs::{File, DirBuilder};
use std::io;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use clap::{Arg, App};
use hashicorp_vault::Client;
use walkdir::WalkDir;

mod vault;

use vault::{initialize_vault, put_file_in_vault, read_file_from_vault};

#[cfg(test)]
mod tests {
    mod dir_lists {
        use super::super::{get_files_at_path, get_links_at_path};
        use std::env::{temp_dir};
        use std::fs::{File, DirBuilder};
        use std::fs;
        use std::path::PathBuf;
        use std::os::unix::fs::symlink;

        #[test]
        fn it_can_list_files_in_directory() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_files");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();
            let mut dst1 = dir.clone();
            let mut dst2 = dir.clone();
            dst1.push("test_1.txt");
            dst2.push("test_2.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let _ = File::create(dst2.clone()).unwrap();

            let expected = vec![
                dst1,
                dst2,
            ].sort();

            assert_eq!(get_files_at_path(&dir).sort(), expected);

            // cleanup
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_ignores_symlinks() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_link");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();

            let mut dst_dir = temp_dir();
            dst_dir.push("vault_test_ls_link_dst");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dst_dir);

            let mut dst1 = dir.clone();
            let mut dst2 = dst_dir.clone();
            let mut dst3 = dir.clone();
            dst1.push("test_1.txt");
            dst2.push("test_2.txt");
            dst3.push("test_2.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let _ = File::create(dst2.clone()).unwrap();
            let _ = File::create(dst3.clone()).unwrap();

            let _ = symlink(dst2, dst3);

            let expected = vec![
                dst1,
            ].sort();

            assert_eq!(get_files_at_path(&dir).sort(), expected);

            // cleanup
            let _ = fs::remove_dir_all(dir);
            let _ = fs::remove_dir_all(dst_dir);
        }

        #[test]
        fn it_ignores_directories() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_ignore");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();
            let mut dst1 = dir.clone();
            let mut dst2 = dir.clone();
            dst1.push("test_1.txt");
            dst2.push("recurse_test");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dst2).unwrap();
            dst2.push("test_1.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let _ = File::create(dst2.clone()).unwrap();

            let expected = vec![
                dst1,
                dst2,
            ].sort();

            assert_eq!(get_files_at_path(&dir).sort(), expected);
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_returns_empty_with_non_dir() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_non_dir");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();
            let mut dst1 = dir.clone();
            dst1.push("test_1.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let v : Vec<PathBuf> = vec![];
            assert_eq!(get_files_at_path(&dst1), v);

            // cleanup
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_lists_links_at_path() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_links");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();

            let mut dst_dir = temp_dir();
            dst_dir.push("vault_test_ls_dst");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dst_dir);

            let mut dst1 = dir.clone();
            let mut dst2 = dst_dir.clone();
            let mut dst3 = dir.clone();
            dst1.push("test_1.txt");
            dst2.push("test_2.txt");
            dst3.push("test_2.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let _ = File::create(dst2.clone()).unwrap();
            let _ = File::create(dst3.clone()).unwrap();

            let _ = symlink(dst2, dst3.clone());

            let expected = vec![
                dst3,
            ].sort();

            assert_eq!(get_links_at_path(&dir).sort(), expected);

            // cleanup
            let _ = fs::remove_dir_all(dir);
            let _ = fs::remove_dir_all(dst_dir);
        }
    }

    mod vault_insertion {
        use vault::{put_file_in_vault, read_file_from_vault};
        use std::env::{temp_dir};
        use std::fs::{File, DirBuilder};
        use std::fs;
        use std::io::prelude::*;

        use vault::{initialize_vault};
        #[test]
        fn it_reads_a_file_into_vault() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_vault_in");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir);
            let mut dst1 = dir.clone();
            dst1.push("test_it_reads_a_file_into_vault_1.txt");
            let mut f = File::create(dst1.clone()).unwrap();
            f.write_all(b"Hello, world!").unwrap();

            let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");
            let _ = put_file_in_vault(&vault_client, &dst1).unwrap();

            let path = &dst1.to_string_lossy()[..].replace("/", "_|_");

            // cleanup
            let _ = vault_client.delete_secret(path);
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_read_file_out_of_vault() {
            let mut dir = temp_dir();
            dir.push("vault_test_ls_vault_out");
            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir);
            let mut dst1 = dir.clone();
            dst1.push("test_it_read_file_out_of_vault_1.txt");
            let mut f = File::create(dst1.clone()).unwrap();
            f.write_all(b"Hello, world!").unwrap();

            let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");
            let _ = put_file_in_vault(&vault_client, &dst1).unwrap();
            let value = read_file_from_vault(&vault_client, &dst1).unwrap();

            let path = &dst1.to_string_lossy()[..].replace("/", "_|_");
            let _ = vault_client.delete_secret(path);
            assert_eq!(value, "Hello, world!");

            // cleanup
            let _ = fs::remove_dir_all(dir);
        }
    }

    mod file_manipulation {
        use std::env::{temp_dir};
        use std::fs::{File, DirBuilder};
        use std::fs;
        use vault::{initialize_vault};

        use super::super::make_file_link;

        #[test]
        fn it_replaces_old_file_with_link_to_new_file() {
            let mut dir = temp_dir();
            let mut dst_dir = dir.clone();
            dir.push("vault_test_link_src");

            let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();
            dst_dir.push("vault_test_link_dst");

            let mut dst1 = dir.clone();
            dst1.push("file_manipulation_test_1.txt");
            let _ = File::create(dst1.clone()).unwrap();
            let path = &dst1.to_string_lossy()[..].replace("/", "_|_");
            let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");

            assert_eq!(super::super::get_links_at_path(&dir).len(), 0);
            assert_eq!(super::super::get_files_at_path(&dir).len(), 1);
            assert_eq!(super::super::get_links_at_path(&dst_dir).len(), 0);
            assert_eq!(super::super::get_files_at_path(&dst_dir).len(), 0);

            make_file_link(&dst1, &dst_dir, &vault_client).unwrap();

            assert_eq!(super::super::get_links_at_path(&dir).len(), 1);
            assert_eq!(super::super::get_files_at_path(&dir).len(), 0);
            assert_eq!(super::super::get_links_at_path(&dst_dir).len(), 0);
            assert_eq!(super::super::get_files_at_path(&dst_dir).len(), 1);

            // cleanup
            let _ = vault_client.delete_secret(path);
            let _ = fs::remove_dir_all(dir);
            let _ = fs::remove_dir_all(dst_dir);
        }
    }
}

fn main() {
    let matches = clap::App::new("unlock_ceph")
        .version(crate_version!())
        .arg(Arg::with_name("source")
                            .short("s")
                            .long("source")
                            .help("Source directory to move files from")
                            .takes_value(true)
                            .required(true))
        .arg(Arg::with_name("destination")
                            .short("d")
                            .long("destination")
                            .help("TMPFS to put files on")
                            .takes_value(true)
                            .required(true))
        .arg(Arg::with_name("vault")
                            .short("V")
                            .long("vault")
                            .help("Vault server IP")
                            .takes_value(true)
                            .required(true))
        .arg(Arg::with_name("token")
                            .short("t")
                            .long("token")
                            .help("Vault authentication token")
                            .takes_value(true)
                            .required(true))
        .arg(Arg::with_name("debug")
                           .short("D")
                           .multiple(true)
                           .help("Sets the level of debugging information"))
        .get_matches();

    let log_level = match matches.occurrences_of("debug") {
        0 => log::LogLevel::Warn,
        1 => log::LogLevel::Info,
        2 => log::LogLevel::Debug,
        3 | _ => log::LogLevel::Trace,
    };
    simple_logger::init_with_level(log_level).unwrap();
    info!("Logger initialized at {:?}", log_level);
    // unwrap is safe because these are required above, so Clap will
    // bail if the value is not present
    let source = matches.value_of("source").unwrap();
    let destination = matches.value_of("destination").unwrap();
    let vault_host = matches.value_of("vault").unwrap();
    let token = matches.value_of("token").unwrap();

    debug!("Syncing {} with {}, using vault at {}", source, destination, vault_host);

    let vault_client = initialize_vault(vault_host, token);

    let files_to_link = get_links_at_path(&PathBuf::from(source));

    let files_to_lock = get_files_at_path(&PathBuf::from(source));
    trace!("About to move {:?}", files_to_lock);

    for file in files_to_lock {
        let _ = make_file_link(&file, &PathBuf::from(destination), &vault_client);
    }
}

fn get_links_at_path(path: &PathBuf) -> Vec<PathBuf> {
    let source_path = path.as_path();
    let mut files = vec![];
    if source_path.is_dir() {
        for entry in WalkDir::new(source_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path_is_symbolic_link() {
                let path = entry.path();
                if path.is_dir() {
                    continue
                }
                let pb = path.to_path_buf();
                if pb != source_path {
                    files.push(pb);
                }
            }
        }
    }
    files
}

fn get_files_at_path(path: &PathBuf) -> Vec<PathBuf> {
    let source_path = path.as_path();
    let mut files = vec![];
    if source_path.is_dir() {
        for entry in WalkDir::new(source_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path_is_symbolic_link() {
                continue
            }
            let path = entry.path();
            if path.is_dir() {
                continue
            }
            let pb = path.to_path_buf();
            if pb != source_path {
                files.push(pb);
            }

        }
    }
    files
}

fn make_file_link(source: &PathBuf, dst: &PathBuf, vault: &Client) -> Result<String, io::Error>{
    let _ = put_file_in_vault(vault, source);
    let _ = try!(DirBuilder::new()
                .recursive(true)
                .create(&dst));
    let filename = source.file_name().unwrap();
    let mut new_path: PathBuf = dst.clone();
    new_path.push(filename);
    fs::rename(source, new_path.clone()).unwrap();
    let _ = try!(symlink(new_path, source));
    return Ok("Linked!".to_string())
}

