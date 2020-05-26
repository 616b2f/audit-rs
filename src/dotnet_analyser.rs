use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use serde_json;
use serde::Deserialize;

use crate::purl;
use crate::core;

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

pub fn analyse(path: &String) -> Vec<core::Dependency> {
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

// packages are formated as following "package_name/version"
fn read_project_assets(f: &mut File) -> Vec<String> {
    let mut project_assets_file = String::new();
    f.read_to_string(&mut project_assets_file).unwrap();

    let json: ProjectAssets = serde_json::from_str(&project_assets_file).unwrap();

    let mut packages: Vec<String> = Vec::new();
    println!("ProjectAssets: Version: {}", json.version);
    for (tkey, target) in json.targets {
        println!("Target: {}", tkey);
        for (dkey, dep) in target.dependencies {
            println!("Dependency: {}", dkey);
            packages.push(dkey);
            for (tname, tversion) in dep.dependencies {
                println!("Transitive dependency: {}/{}", tname, tversion.replace(" ", ""));
                packages.push(format!("{}/{}", tname, tversion.replace(" ", "")));
            }
        }
    }

    println!("Packages: {:?}", packages);
    
    return packages
}
