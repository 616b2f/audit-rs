use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::ffi::OsStr;
use std::io::Read;
use serde_json;
use serde::Deserialize;
use log::{info,debug};

use crate::purl;
use crate::core;
use crate::core::Analyser;

#[derive(Deserialize)]
struct PackageLock {
    name: String,
    version: String,
    lockfileVersion: u16,
    requires: bool,
    #[serde(default)]
    dependencies: HashMap<String,Dependency>
}

#[derive(Deserialize, Debug)]
struct Dependency {
    #[serde(default)]
    version: String,
    #[serde(default)]
    resolved: String,
    #[serde(default)]
    integrity: String,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    requires: HashMap<String, String>,
    #[serde(default)]
    dependencies: HashMap<String,Dependency>
}

pub struct NpmAnalyser;

const PACKAGE_LOCK_FILE_NAME: &str = "package-lock.json";

impl Analyser for NpmAnalyser {
    fn analyse(&self, path: &str) -> Vec<core::Dependency> {
        let p = Path::new(&path);

        if Some(OsStr::new(PACKAGE_LOCK_FILE_NAME)) != p.file_name() {
            return Vec::new();
        }
        println!("npm_analyser: examine {:?}", p);

        let mut file = File::open(path).unwrap();
        let mut packages:Vec<String> = read_project_assets(&mut file);

        let mut dependencies:Vec<core::Dependency> = Vec::new();
        while let Some(a) = packages.pop() {
            let b:Vec<&str> = a.split('@').collect();
            let purl = purl::PackageUrl::new("npm".to_string(), b[0].to_string(), b[1].to_string()).build_purl();
            let d = core::Dependency { 
                name: b[0].to_string(),
                version: b[1].to_string(),
                package_url: purl,
                cpe: String::new(),
                dependencies: Vec::new(),
                vulnerabilities: Vec::new()
            };

            dependencies.push(d);
        }

        dependencies
    }
}

// packages are formated as following "package_name/version"
fn read_project_assets(f: &mut File) -> Vec<String> {
    let mut content = String::new();
    f.read_to_string(&mut content).unwrap();

    let json: PackageLock = serde_json::from_str(&content).unwrap();

    let mut packages: Vec<String> = Vec::new();
    info!("package-lock of: Project: {} Version: {}", json.name, json.version);
    for (dname, dep) in json.dependencies {
        info!("Dependency: {}@{}", dname.replace("@", "%40"), dep.version);
        packages.push(format!("{}@{}", dname.replace("@", "%40"), dep.version));
        for (tname, tdep) in dep.dependencies { // transitive dependency
            info!("Transitive dependency: {}@{}", tname.replace("@", "%40"), tdep.version);
            packages.push(format!("{}@{}", tname.replace("@", "%40"), tdep.version));
        }
        for (trname, trversion) in dep.requires { // transitive dependency
            info!("Transitive required dependency: {}@{}", trname.replace("@", "%40"), trversion);
            packages.push(format!("{}@{}", trname.replace("@", "%40"), trversion));
        }
    }

    debug!("Packages: {:?}", packages);
    
    return packages
}
