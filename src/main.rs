mod core;
mod cpe;
mod purl;
mod analysers;
mod vul_sources;

use structopt::StructOpt;

use std::iter::Iterator;
use clap_verbosity_flag;
use log::{info,debug};

use crate::analysers::npm_analyser::NpmAnalyser;
use crate::analysers::dotnet_analyser::DotNetAnalyser;

use vul_sources::ossindex;

use glob::{glob_with, MatchOptions};

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(long = "project")]
    project: String,
    // #[structopt(parse(from_os_str))]
    // #[structopt(short = "o", long = "out")]
    // outPath: std::path::PathBuf,
    #[structopt(long = "dry-run")]
    dry_run: bool,
    #[structopt(parse(from_os_str))]
    #[structopt(short = "s", long = "scan")]
    path: std::path::PathBuf,
    #[structopt(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
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
    // let dotnet = DotNetAnalyser;
    let mut v: Vec<Box<dyn core::Analyser>> = Vec::new();
    v.push(Box::new(DotNetAnalyser));
    v.push(Box::new(NpmAnalyser));

    v
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::from_args();

    let logf = args.verbose.log_level().unwrap();
    if logf != log::Level::Error {
        env_logger::Builder::new().filter(None, logf.to_level_filter()).init();
    } else {
        env_logger::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

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

    // TODO check type of the file and use different functions for different files
    // e.g. parse *.csproj, project.assets.json, *.nuspec
    let scan_pattern = args.path.into_os_string().into_string().unwrap();
    // let mut dependencies = dotnet_analyser::analyse(&path);

    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false
    };

    let mut dependencies: Vec<core::Dependency> = Vec::new();
    for entry in glob_with(&scan_pattern, options)? {
        let path = entry?.display().to_string();
        debug!("{}", path);
        for a in get_analysers() {
            let dep = a.analyse(&path);
            for d in dep {
                dependencies.push(d);
            }
        }
    }

    print!("Dependencies found: {}\n\n", dependencies.len());

    if !args.dry_run {
        search_for_vulnerabilities(&mut dependencies);
        core::print_vulnerabilities(&dependencies);
    }

    Ok(())
}
