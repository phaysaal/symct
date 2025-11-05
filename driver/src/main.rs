use std::fs;
use std::fs::File;
use std::process::{Command, Stdio};
use clap::{Parser, ValueEnum};
use strum_macros::{EnumString, Display};
use rayon::{prelude::*, ThreadPoolBuilder};
use std::cmp::max;
use std::thread;



#[derive(Parser, Debug, Clone)]
#[command(name = "test-driver", about = "Benchmark Test Driver")]
struct Args {
    #[arg(value_name="LIBRARY")]
    library: Library,

    #[arg(value_name="ALGORITHM")]
    algorithm: String,

    /// Nature (description or mode)
    #[arg(value_name="TEST-TYPE")]
    nature: String,

    #[arg(long, default_value_t = 2048)]
    keylen: i32,

    #[arg(value_name="ROOT_DIR")]
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

    #[arg(long, default_value_t = false)]
    batch: bool,

    #[arg(long, value_enum, default_value_t = Platform::X86_64)]
    platform: Platform,

    /// Enable Bignumber mode
    #[arg(long, default_value_t = false)]
    bn: bool,

    #[arg(long, default_value = "")]
    progressive: String,

    #[arg(long, default_value_t = false)]
    combinations: bool,
}

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

fn main() {
    let args = Args::parse();
    drive_test(args);
}

fn drive_test(args : Args) {
    if args.batch == true {
        batch_test (args);
    }
    else {
        single_test (args);
    }
}

fn batch_test(args: Args) {
    let tests: [&'static str; 6] = ["d","p","q","dmp1","dmq1","iqmp"];

    // ⚡ Build a new parallel pool explicitly
    let pool = ThreadPoolBuilder::new()
        .num_threads(max(2, num_cpus::get_physical()))  // set to 20 for your system
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

    /*
    tests.par_iter().for_each(|test| {
        let mut a = args.clone();
        a.nature = format!("{}_{}", a.nature, test);
        eprintln!("start {:<5} on {:?}", test, thread::current().id());
        thread::sleep(Duration::from_millis(500));
        single_test(a);
        eprintln!("done  {:<5} on {:?}", test, thread::current().id());
    });
    */
}

struct Run {
    bn : String,
    sse_script : String,
    timeout : i32,
    source : String,
    debug_level : i32,
    solver_timeout : i32,
    sse_depth : i32,
}

fn single_test (args : Args) {
    let root:String  = format!("{}/binsec/", args.root);
    let base_ini = if args.startfrom == "core" {
        format!("{}{}/core.ini", root, args.platform) 
    } else { 
        format!("{}{}/{}", root, args.platform, args.startfrom) 
    };
    let base_dir: String = format!("{}{}/{}", root, args.platform, args.library);
    let base_stubs: String = if !args.bn { "".to_string() } else { format!(",{}", list_files(&base_dir).join(",")) };
    let bn_option: String = if !args.bn { "".to_string() } else { format!("-bn -bn-backend {} -bn-keylen {} ", args.library, args.keylen) }; 
    let base_root_ini: String = if args.nature == "dry" { base_ini } else {format!("{},{}{}/{}.ini", base_ini, root, args.platform, args.nature)};
    let random_file: String = if args.random == Random::Random { format!(",{}{}/{}/random/rand.ini", root, args.platform, args.library) } else { format!(",{}{}/{}/random/const.ini", root, args.platform, args.library) };
    let algorithm = args.algorithm.to_string();
    let nature = args.nature.to_string();
    let gs_path = if args.platform == Platform::X86 { format!(",{}/benchmark/{}/{}/{}/bin/gs.ini", args.root, args.platform, args.library, algorithm) } else { "".to_string() };

    let extra = if args.extra == "" { "".to_string() } else { format!(",{}", args.extra) };
    let tag = if args.tag == "" { args.tag } else { format!("_{}", args.tag) };
    
    let dbg: i32 = if args.debug { 2 } else { 0 };

    let binary_path = if args.startfrom == "core" { 
        format!("{}/benchmark/{}/{}/{}/bin/{}_{}_{}.core", args.root, args.platform, args.library, algorithm, algorithm, args.library, args.platform) 
    } else {
        format!("{}/benchmark/{}/{}/{}/bin/{}_{}_{}", args.root, args.platform, args.library, algorithm, algorithm, args.library, args.platform)
    };
    let output_path = format!("{}/results/{}/{}/{}", args.root, args.platform, args.library, algorithm);
    fs::create_dir_all(&output_path).expect("Could not create directory");

    
    let bn_dir: String = format!("{}{}/{}/progressive/", root, args.platform, args.library);
    let bn_stubs: Vec<String> = if !args.bn { vec![] } else { list_files(&bn_dir) };
    let all_combs = if args.combinations { 
        all_combinations(bn_stubs) 
    } else {
        if args.progressive == "" {
            let mut x = Vec::new();
            x.push(bn_stubs);
            x
        } else {
            progressive_list(bn_dir, args.progressive.clone()) 
        }
    };

    for (i,c) in all_combs.iter().enumerate() {
        let bn_scripts = if c.is_empty() { "".to_string() } else {format!(",{}", c.join(","))};
        let script_files: String = format!("{},{}{}/mem.ini{}{}{}{}{}", base_root_ini, root, args.platform, random_file, gs_path, extra, base_stubs, bn_scripts.clone());
        let script_list: String = format!{"_{}", i}; // if c.is_empty() { "".to_string() } else {format!("_{}", c.join("_"))};
        let log_file = format!("{}/results/{}/{}/{}/{}{}{}.log", args.root, args.platform, args.library, algorithm.clone(), nature.clone(), script_list, tag);
        
        let run = Run {
            bn : bn_option.clone(),
            sse_script : script_files.clone(),
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
        
        let mut parts: std::str::SplitWhitespace<'_> = run_cmd.split_whitespace(); 
        let program: &str = parts.next().expect("empty cmd");
        let run_args: Vec<&str> = parts.collect();  
        println!("Test Case: {}", bn_scripts.clone());
        run_and_log(program, &run_args, log_file, algorithm.clone(), nature.clone(), tag.clone());
    }

}

fn all_combinations(items: Vec<String>) -> Vec<Vec<String>> {
    let n = items.len();
    let mut result: Vec<Vec<String>> = Vec::new();

    for mask in 0..(1 << n) {
        let mut combo = Vec::new();
        for i in 0..n {
            if (mask >> i) & 1 == 1 {
                combo.push(items[i].clone());
            }
        }
        result.push(combo);
    }

    result
}

fn progressive_list(bn_dir: String, s_items: String) -> Vec<Vec<String>> {
    let mut x : Vec<String> = Vec::new();
    let mut acc : Vec<Vec<String>> = Vec::new();
    acc.push(x.clone());

    for item in s_items.split(",") {
        x.push(format!("{}{}", bn_dir, item.trim().to_string()));
        acc.push(x.clone());
    }
    acc
}

fn list_files(directory : &str) -> Vec<String> {
    let entries = fs::read_dir(directory).expect("Could not read directory");

    let filenames : Vec<String> = entries
    .filter_map(Result::ok)
    .filter(|e| e.path().is_file())
    .map(|e| {
        let fname: String = e.file_name()
            .to_string_lossy()
            .into_owned();
        format!("{}/{}", directory, fname)
    })
    .collect();

    filenames
}

fn run_and_log(program : &str, cmd: &[&str], log_file_name: String, algorithm: String, nature: String, tag: String) {
    // Open the log file for writing (overwrite)
    let log = File::create(&log_file_name).expect("Could not create log file");

    // Show the command about to run
    println!("▶️  Running: {} {}", program, cmd.join(" "));
    println!("▶️  Output will be written to: {}", log_file_name);
    // Run the command with stdout/stderr redirected to the log file
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
