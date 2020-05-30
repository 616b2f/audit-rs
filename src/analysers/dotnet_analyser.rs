use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::ffi::OsStr;
use std::path::Path;
use serde_json;
use serde::Deserialize;
use log::{info,debug};

use crate::purl;
use crate::core;
use crate::core::Analyser;

#[derive(Deserialize)]
struct ProjectAssets {
    version: u16,
    #[serde(default)]
    targets: HashMap<String,Target>
}

#[derive(Deserialize, Debug)]
struct Target {
    #[serde(default,flatten)]
    dependencies: HashMap<String, Dep>
}

#[derive(Deserialize, Debug)]
struct Dep {
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    dependencies: HashMap<String, String>
}

pub struct DotNetAnalyser;

const PROJECT_ASSETS_FILE_NAME: &str = "project.assets.json";

impl Analyser for DotNetAnalyser {
    fn analyse(&self, path: &str) -> Vec<core::Dependency> {
        let p = Path::new(path);

        // skip processing if its not and dotnet project assets file
        if Some(OsStr::new(PROJECT_ASSETS_FILE_NAME)) != p.file_name() {
            return Vec::new();
        }
        println!("dotnet_analyser: examine {:?}", p);

        let mut file = File::open(path).unwrap();
        let mut packages:Vec<String> = read_project_assets(&mut file);

        let mut dependencies:Vec<core::Dependency> = Vec::new();
        while let Some(a) = packages.pop() {
            let b:Vec<&str> = a.split('/').collect();
            let purl = purl::PackageUrl::new("nuget".to_string(), b[0].to_string(), b[1].to_string()).build_purl();
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
    let mut project_assets_file = String::new();
    f.read_to_string(&mut project_assets_file).unwrap();

    let json: ProjectAssets = serde_json::from_str(&project_assets_file).unwrap();

    let mut packages: Vec<String> = Vec::new();
    info!("ProjectAssets: Version: {}", json.version);
    for (tkey, target) in json.targets {
        info!("Target: {}", tkey);
        for (dkey, dep) in target.dependencies {
            info!("Dependency: {}", dkey);
            packages.push(dkey);
            for (tname, tversion) in dep.dependencies {
                info!("Transitive dependency: {}/{}", tname, tversion.replace(" ", ""));
                packages.push(format!("{}/{}", tname, tversion.replace(" ", "")));
            }
        }
    }

    debug!("Packages: {:?}", packages);
    
    return packages
}
