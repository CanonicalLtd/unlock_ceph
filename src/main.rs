#[macro_use] extern crate clap;
extern crate crypto;
extern crate hashicorp_vault;
#[macro_use] extern crate log;
#[cfg(test)] extern crate rand;
extern crate simple_logger;
extern crate walkdir;

use std::fs;
use std::fs::{File, DirBuilder};
use std::io;
use std::io::prelude::*;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use clap::{Arg, App};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use hashicorp_vault::Client;
use walkdir::WalkDir;

mod vault;

use vault::{initialize_vault, put_file_in_vault, read_file_from_vault};

#[cfg(test)]
mod tests {
    use std::env::{temp_dir as tmp_dir};
    use std::fs::{File, DirBuilder};
    use std::fs;
    use std::io::prelude::*;
    use std::path::PathBuf;

    use crypto::sha1::Sha1;
    use crypto::digest::Digest;
    use vault::{initialize_vault};

    use rand;
    fn temp_dir() -> PathBuf {
        let y = rand::random::<f64>();
        // PathBuf::from(format!("{}/{}", tmp_dir(), y))
        let mut t = tmp_dir();
        t.push(format!("unlock_ceph/{}",y));
        // println!("Providing path of {:?}", t);
        t
    }

    fn make_sha(s: &PathBuf) -> String {
        let mut hasher = Sha1::new();
        hasher.input_str(&s.to_string_lossy()[..]);
        hasher.result_str()
    }

    fn create_file(dir: &PathBuf, subpath: &str, content: Option<&str>) -> PathBuf {
        let mut new_path = dir.clone();
        new_path.push(subpath);
        if content.is_some() {
            let mut f = File::create(&new_path).unwrap();
            f.write_all(content.unwrap().as_bytes()).unwrap();
        }
        new_path
    }

    fn create_dir(dir: &PathBuf) {
        let _ = DirBuilder::new()
                .recursive(true)
                .create(&dir).unwrap();
    }

    #[test]
    fn it_can_eat_a_directory() {
        let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");

        let parent = temp_dir();

        let mut source = parent.clone();
        source.push("source");
        let mut dest = parent.clone();
        dest.push("dest");

        create_dir(&source);
        create_dir(&dest);

        println!("Created dirs, starting on files");
        let dst1 = create_file(&source, "test_1.txt", Some("test1"));
        let dst2 = create_file(&source, "test_2.txt", Some("test2"));
        // symlink target
        let dst3 = create_file(&source, "test_3.txt", Some("text3"));

        let subfolder1 = create_file(&source, "test", None);

        create_dir(&subfolder1);
        let subfolder1 = create_file(&subfolder1, "test_4.txt", Some("text4"));


        let mut linked_src = source.clone();
        linked_src.push("test_3.txt");

        let mut f = File::create(linked_src.clone()).unwrap();
        f.write_all(b"test3").unwrap();

        let _ = super::make_file_link(&linked_src, &dest, &vault_client);

        let linked_dst = create_file(&dest, &make_sha(&linked_src)[..], None);

        let _ = fs::remove_file(&linked_dst).unwrap();
        // let _ = symlink(linked_dst, dst3);

        let new_links = vec![&dst1, &dst2, &subfolder1];
        for item in &new_links {
            println!("Verifying {:?} before move", &item);
            assert!(fs::symlink_metadata(&item).unwrap().file_type().is_file());
            assert!(!fs::symlink_metadata(&item).unwrap().file_type().is_symlink());
        }

        super::eat_files("http://127.0.0.1:8200", "test12345", &source, &dest);

        let paths: Vec<String> = vec![
            make_sha(&dst1),
            make_sha(&dst2),
            make_sha(&dst3),
            make_sha(&subfolder1),
            make_sha(&linked_src),
        ];
        for path in paths {
            let _ = vault_client.delete_secret(&path[..]);
        }

        for item in &new_links {
            println!("Verifying {:?} after move", &item);
            assert!(!fs::symlink_metadata(&item).unwrap().file_type().is_file());
            assert!(fs::symlink_metadata(&item).unwrap().file_type().is_symlink());
        }
        println!("Verifying {:?} after move", &linked_src);
        assert!(fs::symlink_metadata(&linked_src).unwrap().file_type().is_symlink());
        assert!(fs::metadata(&linked_src).unwrap().file_type().is_file());
        // cleanup

        let _ = fs::remove_dir_all(parent);
    }

    mod dir_lists {
        use super::super::{get_files_at_path, get_links_at_path};
        use std::fs;
        use std::path::PathBuf;
        use super::temp_dir;
        use std::os::unix::fs::symlink;


        #[test]
        fn it_can_list_files_in_directory() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);
            let dst1 = super::create_file(&dir, "test_1.txt", None);
            let dst2 = super::create_file(&dir, "test_2.txt", None);
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
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let dst_dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dst_dir);

            let dst1 = super::create_file(&dir, "test_1.txt", None);
            let dst2 = super::create_file(&dst_dir, "test_2.txt", None);
            let dst3 = super::create_file(&dir, "test_2.txt", None);

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
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let dst1 = super::create_file(&dir, "test_1.txt", None);
            let dst2 = super::create_file(&dir, "recurse", None);
            super::create_dir(&dst2);

            let dst2 = super::create_file(&dst2, "test_2.txt", None);

            let expected = vec![
                dst1,
                dst2,
            ].sort();

            assert_eq!(get_files_at_path(&dir).sort(), expected);
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_returns_empty_with_non_dir() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let dst1 = super::create_file(&dir, "test_1.txt", None);
            let v : Vec<PathBuf> = vec![];
            assert_eq!(get_files_at_path(&dst1), v);

            // cleanup
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_lists_links_at_path() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let dst_dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let _ = super::create_file(&dir, "test_1.txt", None);
            let dst2 = super::create_file(&dst_dir, "test_2.txt", None);
            let dst3 = super::create_file(&dir, "test_2.txt", None);
            let _ = symlink(&dst2, &dst3);

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
        use vault::{put_file_in_vault, read_file_from_vault, initialize_vault};
        use super::temp_dir;
        use std::fs;

        #[test]
        fn it_reads_a_file_into_vault() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);
            let dst1 = super::create_file(&dir, "test_1.txt", Some("Hello, world!"));
            let sha = super::make_sha(&dst1);
            let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");
            let _ = put_file_in_vault(&vault_client, &dst1, &sha).unwrap();


            let _ = vault_client.delete_secret(&sha);
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn it_read_file_out_of_vault() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);
            let dst1 = super::create_file(&dir, "test_1.txt", Some("Hello, world!"));

            let sha = super::make_sha(&dst1);
            let vault_client = initialize_vault("http://127.0.0.1:8200", "test12345");
            let _ = put_file_in_vault(&vault_client, &dst1, &sha).unwrap();
            let value = read_file_from_vault(&vault_client, &sha).unwrap();

            let _ = vault_client.delete_secret(&sha);
            assert_eq!(value, "Hello, world!");

            // cleanup
            let _ = fs::remove_dir_all(dir);
        }
    }

    mod file_manipulation {
        use super::temp_dir;
        use std::fs;
        use vault::{initialize_vault};

        use super::super::make_file_link;

        #[test]
        fn it_replaces_old_file_with_link_to_new_file() {
            let dir = super::create_file(&temp_dir(), "", None);
            super::create_dir(&dir);

            let dst_dir = super::create_file(&temp_dir(), "", None);
            let dst1 = super::create_file(&dir, "test_1.txt", Some("Hello, world!"));

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
            let _ = vault_client.delete_secret(&super::make_sha(&dst1)[..]);
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

    eat_files(vault_host, token, &PathBuf::from(source), &PathBuf::from(destination));

    // inotify.watch(&source) {
    //     eat_files(vault_host, token, &PathBuf::from(source), &PathBuf::from(destination));
    // }


}

fn eat_files(vault_host: &str, token: &str, source: &PathBuf, destination: &PathBuf) {
    debug!("Syncing {:?} with {:?}, using vault at {}", source, destination, vault_host);
    let vault_client = initialize_vault(vault_host, token);

    let files_to_link = get_links_at_path(source);

    let files_to_lock = get_files_at_path(source);
    trace!("About to move {:?}", files_to_lock);

    for file in files_to_lock {
        let _ = make_file_link(&file, &PathBuf::from(destination), &vault_client);
    }

    for file in files_to_link {
        let _ = restore_file_at_path(&file, &PathBuf::from(destination), &vault_client);
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
    let mut hasher = Sha1::new();
    hasher.input_str(&source.to_string_lossy()[..]);
    let hex = hasher.result_str();
    let _ = put_file_in_vault(vault, source, &hex);

    let _ = try!(DirBuilder::new()
                .recursive(true)
                .create(&dst));
    // let filename = source.file_name().unwrap();
    let mut new_path: PathBuf = dst.clone();
    new_path.push(hex);
    fs::rename(source, new_path.clone()).unwrap();
    let _ = try!(symlink(new_path, source));
    return Ok("Linked!".to_string())
}

fn restore_file_at_path(source: &PathBuf, dst: &PathBuf, vault: &Client) -> Result<String, io::Error> {
    let mut hasher = Sha1::new();
    hasher.input_str(&source.to_string_lossy()[..]);
    let hex = hasher.result_str();
    let tmp_string = read_file_from_vault(vault, &hex);
    let mut dst_path = PathBuf::from(dst);
    dst_path.push(hex);

    let mut f = File::create(dst_path.clone()).unwrap();
    let _ = f.write_all(tmp_string.unwrap().as_bytes());

    Ok("Str".to_string())
}
