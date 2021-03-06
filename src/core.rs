use std::fmt;
use colored::*;

// enum EvidenceType {
//     Vendor,
//     Product,
//     Version
// }

// enum Confidence {
//     Highest,
//     High,
//     Medium,
//     Low
// }

// struct Evidence {
//     source: String,
//     name : String,
//     value: String,
//     confidence: Confidence,
// }

pub trait Analyser {
    fn analyse(&self, path: &str) -> Vec<Dependency>;
}

pub struct Dependency {
    pub name: String,
    pub version: String,
    pub package_url: String,
    pub cpe: String,
    pub dependencies: Vec<Dependency>, // for transitive dependencies
    pub vulnerabilities: Vec<Vulnerability>
}

pub enum Severity {
    r#None(f32),
    Low(f32),
    Medium(f32),
    High(f32),
    Critical(f32)
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::None(_) => write!(f, "NONE"),
            Severity::Low(x) => write!(f, "LOW({})", x),
            Severity::Medium(x) => write!(f, "MEDIUM({})", x),
            Severity::High(x) => write!(f, "HIGH({})", x),
            Severity::Critical(x) => write!(f, "CRITICAL({})", x),
        }
    }
}

// Valid VSS Scores
// None	0.0
// Low	0.1-3.9
// Medium	4.0-6.9
// High	7.0-8.9
// Critical	9.0-10.0
impl Severity {
    pub fn set_severity(score: f32) -> Result<Severity, String> {
        match score {
            0.0 => Ok(Severity::None(score)),
            0.1..=3.9 => Ok(Severity::Low(score)),
            4.0..=6.9 => Ok(Severity::Medium(score)),
            7.0..=8.9 => Ok(Severity::High(score)),
            9.0..=10.0 => Ok(Severity::Critical(score)),
            _ => Err(format!("invalid VSS score {}", score))
        }
    } 
}


pub struct Vulnerability {
    pub cve_id: String,
    pub cvss_score: f32,
    pub cwe: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
}

pub fn print_vulnerabilities(deps: &[Dependency]) {
    let dv = deps.iter().filter(|&x| x.vulnerabilities.len() > 0);
    println!("Vulnerability found in:");
    for d in dv {
        println!("{} v{}",d.name, d.version);
        for x in d.vulnerabilities.iter() {
                let sev = &x.severity;
                let rank = match sev {
                    Severity::Critical(_) | Severity::High(_) => format!("{}", sev).red().to_string(),
                    Severity::Medium(_) => format!("{}", sev).bright_red().to_string(),
                    Severity::Low(_) => format!("{}", sev).yellow().to_string(),
                    _ => format!("{}", sev)
                };
                print!("\t{}\t{}\n\tTitle: {}\n", rank, x.cve_id, x.title);

                print!("\n\n");
        }
    }
}
