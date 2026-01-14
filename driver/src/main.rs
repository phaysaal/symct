// Standard library imports
use std::cmp::max;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;

// External crate imports
use clap::{Parser, ValueEnum};
use rayon::{prelude::*, ThreadPoolBuilder};
use strum_macros::{Display, EnumString};

// ============================================================================
// Command-line Arguments
// ============================================================================

#[derive(Parser, Debug, Clone)]
#[command(name = "test-driver", about = "Benchmark Test Driver")]
struct Args {
    #[arg(value_name = "LIBRARY")]
    library: Library,

    #[arg(value_name = "ALGORITHM")]
    algorithm: String,

    #[arg(value_name = "TEST-TYPE")]
    nature: String,

    #[arg(long, default_value_t = 2048)]
    keylen: i32,

    #[arg(value_name = "ROOT_DIR")]
    root: String,

    /// Starting point (core, main, etc.)
    #[arg(long, default_value = "core")]
    startfrom: String,

    /// Timeout in seconds
    #[arg(short, long, default_value_t = 1800)]
    timeout: i32,

    /// Enable debug output
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Randomization mode
    #[arg(long, value_enum, default_value_t = Random::Random)]
    random: Random,

    #[arg(long, default_value = "")]
    extra: String,

    #[arg(long, default_value = "")]
    tag: String,

    /// Run tests in batch mode
    #[arg(long, default_value_t = false)]
    batch: bool,

    /// Run tests from a file with different test configurations
    #[arg(long, default_value = "")]
    batch_file: String,

    #[arg(long, value_enum, default_value_t = Platform::X86_64)]
    platform: Platform,

    /// Enable Bignumber mode
    #[arg(long, default_value_t = false)]
    bn: bool,

    #[arg(long, default_value = "")]
    progressive: String,

    #[arg(long, default_value = "")]
    only: String,

    #[arg(long, default_value_t = false)]
    combinations: bool,

    #[arg(long, default_value = "")]
    optimization: String,
}

// ============================================================================
// Enums
// ============================================================================

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Random {
    #[value(name = "rand")]
    Random,

    #[value(name = "const")]
    Constant,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, EnumString, Display)]
enum Library {
    #[value(name = "openssl", alias = "OpenSSL", alias = "ossl")]
    #[strum(serialize = "openssl")]
    OpenSSL,

    #[value(name = "bearssl", alias = "BearSSL", alias = "bssl")]
    #[strum(serialize = "bearssl")]
    BearSSL,

    #[value(name = "wolfssl", alias = "WolfSSL", alias = "wssl")]
    #[strum(serialize = "wolfssl")]
    WolfSSL,

    #[value(name = "mbedtls", alias = "MbedTLS", alias = "mbedtls")]
    #[strum(serialize = "mbedtls")]
    MbedTLS,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, EnumString, Display)]
enum Platform {
    #[value(name = "32")]
    #[strum(serialize = "32")]
    X86,

    #[value(name = "64")]
    #[strum(serialize = "64")]
    X86_64,
}

// ============================================================================
// Structs
// ============================================================================

struct Run {
    bn: String,
    sse_script: String,
    timeout: i32,
    source: String,
    debug_level: i32,
    solver_timeout: i32,
    sse_depth: i32,
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    let args = Args::parse();
    drive_test(args);
}

// ============================================================================
// Test Driver Functions
// ============================================================================

fn drive_test(args: Args) {
    if !args.batch_file.is_empty() {
        batch_file_test(args);
    } else if args.batch {
        batch_test(args);
    } else {
        single_test(args);
    }
}

fn batch_test(args: Args) {
    let tests: [&'static str; 6] = ["d", "p", "q", "dmp1", "dmq1", "iqmp"];

    let pool = ThreadPoolBuilder::new()
        .num_threads(max(2, num_cpus::get_physical()))
        .build()
        .unwrap();

    pool.install(|| {
        tests.par_iter().for_each(|test| {
            let mut a = args.clone();
            a.nature = format!("{}_{}", a.nature, test);
            eprintln!("start {:<5} on {:?}", test, thread::current().id());
            single_test(a);
            eprintln!("done  {:<5} on {:?}", test, thread::current().id());
        });
    });
}

fn batch_file_test(args: Args) {
    let file = File::open(&args.batch_file)
        .unwrap_or_else(|_| panic!("Could not open batch file: {}", args.batch_file));
    let reader = BufReader::new(file);

    println!("📋 Running tests from batch file: {}", args.batch_file);
    println!("----------------------------------------");

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(e) => {
                eprintln!("❌ Error reading line {}: {}", line_num + 1, e);
                continue;
            }
        };

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut a = args.clone();
        a.nature = line.clone();

        println!("\n🔹 Test {}: {}", line_num + 1, line);
        single_test(a);
        println!("✅ Completed test: {}", line);
    }

    println!("\n----------------------------------------");
    println!("🎉 All tests from batch file completed");
}

fn single_test(args: Args) {
    // Build paths and configuration strings
    let script_root = format!("{}/binsec/", args.root);

    let base_ini = if args.startfrom == "core" {
        format!("{}{}/core.ini", script_root, args.platform)
    } else {
        format!("{}{}/{}", script_root, args.platform, args.startfrom)
    };

    let library = if args.optimization.is_empty() {
        format!("{}", args.library)
    } else {
        format!("{}-{}", args.library, args.optimization)
    };

    let base_dir: String = format!("{}{}/{}", script_root, args.platform, args.library);

    let base_stubs: String = if !args.bn {
        "".to_string()
    } else {
        format!(",{}", list_files(&base_dir).join(","))
    };

    let bn_option: String = if !args.bn {
        "".to_string()
    } else {
        format!("-bn -bn-backend {} -bn-keylen {} ", args.library, args.keylen)
    };

    let base_root_ini: String = if args.nature == "dry" {
        base_ini
    } else {
        format!("{},{}{}/{}.ini", base_ini, script_root, args.platform, args.nature)
    };

    let random_file: String = {
        let random_dir = format!("{}{}/{}/random", script_root, args.platform, args.library);
        if std::path::Path::new(&random_dir).exists() {
            if args.random == Random::Random {
                format!(",{}/rand.ini", random_dir)
            } else {
                format!(",{}/const.ini", random_dir)
            }
        } else {
            "".to_string()
        }
    };

    let algorithm = args.algorithm.to_string();
    let nature = args.nature.to_string();

    let gs_path = if args.platform == Platform::X86 {
        format!(",{}/benchmark/{}/{}/{}/bin/gs.ini", args.root, args.platform, library, algorithm)
    } else {
        "".to_string()
    };

    let extra = if args.extra.is_empty() {
        "".to_string()
    } else {
        format!(",{}", args.extra)
    };

    let tag = if args.tag.is_empty() {
        args.tag
    } else {
        format!("_{}", args.tag)
    };

    let dbg: i32 = if args.debug { 2 } else { 0 };

    // Determine binary path
    let binary_path = if args.startfrom == "core" {
        format!(
            "{}/benchmark/{}/{}/{}/bin/{}_{}_{}.core",
            args.root, args.platform, library, algorithm, algorithm, library, args.platform
        )
    } else {
        format!(
            "{}/benchmark/{}/{}/{}/bin/{}_{}_{}",
            args.root, args.platform, library, algorithm, algorithm, library, args.platform
        )
    };

    // Create output directory
    let output_path = format!("{}/results/{}/{}/{}", args.root, args.platform, library, algorithm);
    fs::create_dir_all(&output_path).expect("Could not create directory");

    // Build combinations of bn scripts
    let bn_dir: String = format!("{}{}/{}/progressive/", script_root, args.platform, args.library);
    let bn_stubs: Vec<String> = if !args.bn { vec![] } else { list_files(&bn_dir) };

    let all_combs = if args.combinations {
        all_combinations(bn_stubs)
    } else if args.progressive.is_empty() {
        vec![("0".to_string(), bn_stubs)]
    } else {
        progressive_list(bn_dir, args.progressive.clone(), args.only.clone())
    };

    // Run tests for each combination
    for (name, c) in all_combs.iter() {
        let bn_scripts = if c.is_empty() {
            "".to_string()
        } else {
            format!(",{}", c.join(","))
        };

        let script_files: String = format!(
            "{},{}{}/mem.ini{}{}{}{}{}",
            base_root_ini, script_root, args.platform, random_file, gs_path, extra, base_stubs, bn_scripts
        );

        let script_list: String = format!("_{}", name);
        let log_file = format!(
            "{}/results/{}/{}/{}/{}{}{}.log",
            args.root, args.platform, library, algorithm, nature, script_list, tag
        );

        let run = Run {
            bn: bn_option.clone(),
            sse_script: script_files,
            timeout: args.timeout,
            source: binary_path.clone(),
            debug_level: dbg,
            solver_timeout: 600,
            sse_depth: 1000000000,
        };

        let run_cmd = format!(
            "binsec -sse -checkct {} -sse-missing-symbol warn -sse-script {} -sse-debug-level {} -sse-depth {} -fml-solver-timeout {} -sse-timeout {} {} -smt-solver bitwuzla:smtlib",
            run.bn, run.sse_script, run.debug_level, run.sse_depth, run.solver_timeout, run.timeout, run.source
        );

        let mut parts = run_cmd.split_whitespace();
        let program = parts.next().expect("empty cmd");
        let run_args: Vec<&str> = parts.collect();

        println!("Test Case: {}", bn_scripts);
        run_and_log(program, &run_args, log_file, algorithm.clone(), nature.clone(), tag.clone());
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

fn all_combinations(items: Vec<String>) -> Vec<(String, Vec<String>)> {
    let n = items.len();
    let mut result: Vec<(String, Vec<String>)> = Vec::new();

    for mask in 0..(1 << n) {
        let mut combo = Vec::new();
        for i in 0..n {
            if (mask >> i) & 1 == 1 {
                combo.push(items[i].clone());
            }
        }
        result.push((format!("{}", mask), combo));
    }

    result
}

fn progressive_list(bn_dir: String, s_items: String, only: String) -> Vec<(String, Vec<String>)> {
    let mut x: Vec<String> = Vec::new();
    let mut acc: Vec<(String, Vec<String>)> = Vec::new();
    acc.push(("0".to_string(), x.clone()));

    // Check if progressive directory has folders
    let mut folders: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(&bn_dir) {
        for entry in entries.filter_map(Result::ok) {
            if entry.path().is_dir() {
                if let Some(folder_name) = entry.file_name().to_str() {
                    folders.push(folder_name.to_string());
                }
            }
        }
    }

    if !folders.is_empty() {
        // Sort folders alphabetically
        folders.sort();

        // If --only is specified, return only that specific step
        if !only.is_empty() {
            // Find the position of the target folder
            if let Some(target_pos) = folders.iter().position(|f| f == &only) {
                // Accumulate files from all folders up to and including the target
                for folder in folders.iter().take(target_pos + 1) {
                    let folder_path = format!("{}{}/", bn_dir, folder);
                    let files_in_folder = list_files(&folder_path);
                    x.extend(files_in_folder);
                }
                // Return only this one combination (no base case)
                return vec![(only.clone(), x)];
            } else {
                eprintln!("Warning: Folder '{}' not found in progressive directory", only);
            }
        }

        // Progressive accumulation of files from folders
        for folder in folders {
            let folder_path = format!("{}{}/", bn_dir, folder);
            let files_in_folder = list_files(&folder_path);

            // Add all files from current folder to accumulator
            x.extend(files_in_folder);
            acc.push((folder.clone(), x.clone()));
        }
    } else {
        // Original behavior: use comma-separated file list
        for (i, item) in s_items.split(',').enumerate() {
            x.push(format!("{}{}", bn_dir, item.trim()));
            acc.push((format!("{}", i + 1), x.clone()));
        }
    }

    acc
}

fn list_files(directory: &str) -> Vec<String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(), // Return empty vector if directory doesn't exist
    };

    let filenames: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| {
            let fname: String = e.file_name().to_string_lossy().into_owned();
            format!("{}/{}", directory, fname)
        })
        .collect();

    filenames
}

fn run_and_log(
    program: &str,
    cmd: &[&str],
    log_file_name: String,
    algorithm: String,
    nature: String,
    tag: String,
) {
    let log = File::create(&log_file_name).expect("Could not create log file");

    println!("▶️  Running: {} {}", program, cmd.join(" "));
    println!("▶️  Output will be written to: {}", log_file_name);

    let status = Command::new(program)
        .args(cmd)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("✅ Output saved to {}", log_file_name);
        }
        Ok(_) | Err(_) => {
            eprintln!(
                "❌ Binsec failed for {} ({}{}). See {}",
                algorithm, nature, tag, log_file_name
            );
        }
    }
}
