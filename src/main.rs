use structopt::StructOpt;

use std::iter::Iterator;
use colored::*;

mod core;
mod nvd;
mod purl;
mod ossindex;
mod dotnet_analyser;

#[derive(StructOpt)]
struct Cli {
    #[structopt(long = "project")]
    project: String,
    // #[structopt(parse(from_os_str))]
    // #[structopt(short = "o", long = "out")]
    // outPath: std::path::PathBuf,
    #[structopt(parse(from_os_str))]
    #[structopt(short = "s", long = "scan")]
    path: std::path::PathBuf,
}

// fn read_references(&std::path::PathBuf: path) -> Vec<String> {
//     let content = std::fs::read_to_string(*path)
//         .&expect("could not read file");
    
//     let mut references = Vec::new();
//     for line in content.lines() {
//         println!("{}", line);
//         references.push(line.to_string());
//     }

//     references;
// }

fn indent(size: usize) -> String {
    const INDENT: &'static str = "  ";
    (0..size).map(|_| INDENT)
             .fold(String::with_capacity(size*INDENT.len()), |r, s| r + s)
}

fn search_for_vulnerabilities(dependencies: &mut Vec<core::Dependency>) {
    let mut package_urls:Vec<String> = Vec::new();
    for dep in dependencies.iter() {
        if !dep.package_url.is_empty() {
            package_urls.push(dep.package_url.to_string());
        }
    }
    let reports:Vec<ossindex::ComponentReport> = ossindex::get(package_urls);

    let mut rep = reports.iter();
    for d in dependencies.iter_mut() {
        match rep.find(|x| x.coordinates == d.package_url) {
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

fn print_vulnerabilities(deps: &[core::Dependency]) {
    let dv = deps.iter().filter(|&x| x.vulnerabilities.len() > 0);
    for d in dv {
        print!("Vulnerability found in:\n{} v{}\n",d.name, d.version);
        for x in d.vulnerabilities.iter() {
                let sev = &x.severity;
                let rank = match sev {
                    core::Severity::Critical(_) | core::Severity::High(_) => format!("{}", sev).red().to_string(),
                    core::Severity::Medium(_) => format!("{}", sev).bright_red().to_string(),
                    core::Severity::Low(_) => format!("{}", sev).yellow().to_string(),
                    _ => format!("{}", sev)
                };
                print!("\t{}\t{}\n\tTitle: {}\n", rank, x.cve_id, x.title);

                print!("\n\n");
                // println!("{:?}", x);
                // println!("{:?}", v);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::from_args();

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
    let path = args.path.into_os_string().into_string().unwrap();
    let mut dependencies = dotnet_analyser::analyse(&path);

    print!("Dependencies found: {}\n\n", dependencies.len());

    search_for_vulnerabilities(&mut dependencies);
    print_vulnerabilities(&dependencies);

    Ok(())
}
