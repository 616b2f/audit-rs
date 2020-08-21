mod core;
mod cpe;
mod purl;
mod analysers;
mod vul_sources;

use structopt::StructOpt;

use std::iter::Iterator;
use clap_verbosity_flag;
use log::{info,debug};
use std::error::Error;

use crate::analysers::npm_analyser::NpmAnalyser;
use crate::analysers::dotnet_analyser::DotNetAnalyser;

use vul_sources::ossindex;

use glob::{glob_with, Paths, MatchOptions};

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(long = "project")]
    pub project: String,
    // #[structopt(parse(from_os_str))]
    // #[structopt(short = "o", long = "out")]
    // outPath: std::path::PathBuf,
    #[structopt(long = "dry-run")]
    pub dry_run: bool,
    #[structopt(parse(from_os_str))]
    #[structopt(short = "s", long = "scan")]
    pub path: std::path::PathBuf,
    #[structopt(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
}

fn search_for_vulnerabilities(dependencies: &mut Vec<core::Dependency>) {
    let mut package_urls:Vec<String> = Vec::new();
    for dep in dependencies.iter() {
        if !dep.package_url.is_empty() {
            package_urls.push(dep.package_url.to_string());
        }
    }
    let reports:Vec<ossindex::ComponentReport> = ossindex::get(package_urls);

    // let dwv = reports.into_iter().filter(|x| !x.vulnerabilities.is_empty());
    let rep:Vec<ossindex::ComponentReport> = reports.into_iter().filter(|x| !x.vulnerabilities.is_empty()).collect();
    for d in rep.iter() {
        for v in d.vulnerabilities.iter() {
            info!("Response contains vulnerabilities:\n CVE: {} Title: {}\n",v.title, v.cve);
        }
    }

    for d in dependencies.iter_mut() {
        match rep.iter().find(|x| x.coordinates == d.package_url) {
            Some(x) => {
                for rv in x.vulnerabilities.iter() {
                    let v = core::Vulnerability { 
                        title: rv.title.to_string(),
                        description: rv.description.to_string(),
                        cve_id: rv.cve.to_string(),
                        cvss_score: rv.cvss_score,
                        cwe: rv.cwe.to_string(),
                        severity: core::Severity::set_severity(rv.cvss_score).unwrap(),
                    };
                    &mut d.vulnerabilities.push(v);
                }
            },
            None => {}
        }
    };
}

fn get_analysers() -> Vec<Box<dyn core::Analyser>>{
    let mut v: Vec<Box<dyn core::Analyser>> = Vec::new();
    v.push(Box::new(DotNetAnalyser));
    v.push(Box::new(NpmAnalyser));

    v
}

fn setup_logger(args: &Cli) {
    let logf = args.verbose.log_level().unwrap();
    if logf != log::Level::Error {
        env_logger::Builder::new().filter(None, logf.to_level_filter()).init();
    } else {
        env_logger::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }
}

fn scan_path_for_files(args: &Cli) -> Result<Paths, Box<dyn Error>> {
    // TODO check type of the file and use different functions for different files
    // e.g. parse *.csproj, project.assets.json, *.nuspec
    let scan_pattern = match args.path.as_path().as_os_str().to_str() {
        Some(s) => s,
        None => return Err("Error reading path as string".into())
    };

    println!("search in: {}", scan_pattern);
    
    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false
    };

    let entries = glob_with(&scan_pattern, options)?;

    Ok(entries)
}

fn scan_files_for_dependencies(entries: Paths) -> Result<Vec<core::Dependency>, Box<dyn Error>> {
    let mut dependencies: Vec<core::Dependency> = Vec::new();
    for entry in entries {
        let path = entry?.display().to_string();
        debug!("{}", path);
        for a in get_analysers() {
            let dep = a.analyse(&path);
            for d in dep {
                dependencies.push(d);
            }
        }
    }

    Ok(dependencies)
}
    

pub fn run(args: Cli) -> Result<(), Box<dyn Error>> {

    setup_logger(&args);

    print!("Project: {}\n\n", args.project);
    // let references = read_references(&args.path);

    // path could return multiple file paths
    // let mut file = File::open(args.path)?;
    // let file = BufReader::new(file);

    //// analyser code
    //// https://github.com/jeremylong/DependencyCheck/blob/567fc6afca16b03a61498863ddbe6e735b25bd15/core/src/main/java/org/owasp/dependencycheck/analyzer/AssemblyAnalyzer.java#L131
    // let asmbl:nvd::Assembly = serde_xml_rs::de::from_reader(file)?;
    // let asmbl:CsProj = serde_xml_rs::de::from_reader(file)?;
    // println!("Assembly: {:?}", asmbl);
    let entries = scan_path_for_files(&args)?;
    
    let mut dependencies = scan_files_for_dependencies(entries)?;

    print!("Dependencies found: {}\n\n", dependencies.len());

    if !args.dry_run {
        search_for_vulnerabilities(&mut dependencies);
        core::print_vulnerabilities(&dependencies);
    }

    Ok(())
}
