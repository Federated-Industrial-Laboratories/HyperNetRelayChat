use super::*;

#[test]
fn installer_creates_safe_directories_and_replaces_its_own_file() {
    let directory = std::env::temp_dir().join(format!(
        "hrc-install-{}",
        hrc::protocol::Id::random().unwrap()
    ));
    let file = directory.join("Application/Bin/hrc");
    replace(&file, b"first", 0o755).unwrap();
    assert_eq!(
        fs::metadata(file.parent().unwrap()).unwrap().mode() & 0o022,
        0
    );
    replace(&file, b"second", 0o755).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"second");
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o755);
    let link = directory.join("linked");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(replace(&link, b"wrong", 0o755).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"second");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn launcher_paths_preserve_spaces_and_escape_desktop_metacharacters() {
    let entry = desktop_entry(Path::new("/home/A User/Chat/Bin/hrc")).unwrap();
    assert!(entry.contains("Exec=\"/home/A User/Chat/Bin/hrc\" gui\n"));
    assert!(entry.contains("gui --setup\n"));
    assert!(entry.contains("gui --offline\n"));
    assert_eq!(
        exec_path(Path::new("/test/100%/$cash/`name`/\"file\"/a\\b")).unwrap(),
        "\"/test/100%%/\\\\$cash/\\\\`name\\\\`/\\\\\"file\\\\\"/a\\\\\\\\b\""
    );
    assert!(exec_path(Path::new("/test/line\nExec=evil")).is_err());
    assert!(exec_path(Path::new("/test/key=value")).is_err());
}
