use figlet_rs::FIGfont;
use colored::*;
use std::fs::{ self, OpenOptions };
use std::io::{ Write, BufWriter, Read };
use std::process::Command;
use std::path::{ Path };
use std::env;
use std::io;
use walkdir::WalkDir;
use sysinfo::{ System, Process, Disks, Pid, DiskKind };
use sha2::{ Sha256, Digest };

const LOG_FILE: &str = "brontok_removal.log";

const BRONTOK_NAMES: [&str; 6] = [
    "brontok.exe",
    "brontok.a.exe",
    "brontok.b.exe",
    "brontok.vbs",
    "winlogon_.exe",
    "system.exe",
];

const BRONTOK_HASHES: [&str; 3] = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "e99a18c428cb38d5f260853678922e03",
    "b2d6f89c933fa12a8a3e99d4f9a1f6b3",
];

fn get_additional_scan_dirs() -> Vec<String> {
    vec![
        format!( "{}\\AppData\\Roaming", env::var( "USERPROFILE" ).unwrap_or_else( |_| "C:\\Users\\Default".to_string() )),
        format!( "{}\\AppData\\Local\\Temp", env::var( "USERPROFILE" ).unwrap_or_else( |_| "C:\\Users\\Default".to_string() )),
        "C:\\ProgramData".to_string(),
        "C:\\Windows\\Temp".to_string(),
    ]
}

fn get_drives() -> Vec<String> {
    let mut drives = Vec::new();
    let disks = Disks::new_with_refreshed_list();

    for disk in disks.list() {
        let mount_point = disk.mount_point().to_string_lossy().to_string();
        if disk.kind() == DiskKind::HDD || disk.kind() == DiskKind::SSD {
            drives.push( mount_point );
        }
    }

    drives
}

fn log_message( message: &str ) {
    if let Ok( file ) = OpenOptions::new().append( true ).create( true ).open( LOG_FILE ) {
        let mut writer = BufWriter::new( file );
        let _ = writeln!( writer, "{}", message );
    }
}

fn calculate_sha256( file_path: &Path ) -> Option<String> {
    let mut file = fs::File::open( file_path ).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    while let Ok( n ) = file.read( &mut buffer ) {
        if n == 0 { break; }
        hasher.update( &buffer[..n] );
    }

    Some( format!( "{:x}", hasher.finalize() ))
}

fn delete_file( file_path: &Path ) {
    if let Err( e ) = fs::remove_file( file_path ) {
        let msg = format!( "Can't delete {}: {}", file_path.display(), e );
        println!( "{}", msg );
        log_message( &msg );
    } else {
        let msg = format!( "Deleted: {}", file_path.display() );
        println!( "{}", msg );
        log_message( &msg );
    }
}

fn check_and_delete( file_path: &Path ) {
    if let Some( file_name ) = file_path.file_name().and_then( |n| n.to_str() ) {
        if BRONTOK_NAMES.contains( &file_name ) {
            let msg = format!( "Dangerous file: {}", file_path.display() );
            println!( "{}", msg );
            log_message( &msg );
            delete_file( file_path );
            return;
        }
    }

    if let Some( hash ) = calculate_sha256( file_path ) {
        if BRONTOK_HASHES.contains( &hash.as_str() ) {
            let msg = format!( "Dangerous hash: {} ({})", file_path.display(), hash );
            println!( "{}", msg );
            log_message( &msg );
            delete_file( file_path );
        }
    }
}

fn find_and_remove_virus() {
    let drives = get_drives();
    let extra_dirs = get_additional_scan_dirs();

    println!( "Searching is started..." );
    log_message( "=== Searching is started ===" );

    for drive in drives {
        for entry in WalkDir::new( &drive ).into_iter().filter_map( Result::ok ) {
            check_and_delete( entry.path() );
        }
    }

    for dir in extra_dirs {
        if Path::new( &dir ).exists() {
            for entry in WalkDir::new( &dir ).into_iter().filter_map( Result::ok ) {
                check_and_delete( entry.path() );
            }
        }
    }

    log_message( "=== Searching is finished ===" );
}

fn clean_registry() {
    let output = Command::new( "reg" )
        .args( ["delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "Brontok", "/f"] )
        .output();

    let msg = if output.is_ok() {
        "Brontok deleted from the startup.".to_string()
    } else {
        "Can't clean the register.".to_string()
    };

    println!( "{}", msg );
    log_message( &msg );
}

fn check_running_processes() {
    let mut system = System::new_all();
    system.refresh_all();

    println!( "Checking system processes..." );
    log_message( "=== Checking system processes ===" );

    for ( pid, process ) in system.processes() {
        let process_name = process.name().to_string_lossy().to_lowercase();
        if BRONTOK_NAMES.contains( &process_name.as_str() ) {
            let msg = format!( "Dangerous process: {}", process_name );
            println!( "{}", msg );
            log_message( &msg );
            kill_process( pid );
        }
    }
}

fn kill_process( pid: &Pid ) {
    let _ = Command::new( "taskkill" )
        .args( ["/PID", &pid.to_string(), "/F"] )
        .output();
    let msg = format!( "Stopped: PID {}", pid );
    println!( "{}", msg );
    log_message( &msg );
}

fn main() {
    let standard_font = FIGfont::standard().unwrap();
    let figure = standard_font.convert( "BrontokCure" );

    if let Some( figure ) = figure {
        for line in figure.to_string().lines() {
            println!( "{}", line.blue() );
        }
    }

    let mut q = String::new();
    println!( "Press any key to start..." );
    io::stdin().read_line( &mut q ).ok();

    if env::consts::OS != "windows" {
        println!( "Only for Windows!" );
        return;
    }

    println!( "Starting Brontok deleting..." );
    log_message( "=== Starting... ===" );

    check_running_processes();
    find_and_remove_virus();
    clean_registry();

    println!( "Reload your PC." );
    log_message( "=== Ending... ===" );
}
