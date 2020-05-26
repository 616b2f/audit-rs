use std::fmt;
use reqwest;
use serde_json;
use serde::{Serialize,Deserialize};
use reqwest::header::{CONTENT_TYPE,AUTHORIZATION};
use reqwest::StatusCode;


#[derive(Serialize, Debug)]
struct ComponentReportRequest {
    coordinates: Vec<String>
}

#[derive(Deserialize, Debug)]
pub struct ComponentReport {
    pub coordinates: String,
    #[serde(default)]
    pub description: String,
    reference: String,
    pub vulnerabilities: Vec<ComponentReportVulnerability>,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    code: u16,
    message: String,
}

#[derive(Deserialize, Debug)]
pub struct ComponentReportVulnerability {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename(deserialize = "cvssScore"))]
    pub cvss_score: f32,
    #[serde(default,rename(deserialize = "cvssVector"))]
    cvss_vector: String,
    #[serde(default)]
    pub cwe: String,
    #[serde(default)]
    pub cve: String,
    #[serde(default)]
    reference: String,
    #[serde(default,rename(deserialize = "versionRanges"))]
    version_ranges: Vec<String>
}

pub fn get(purls: Vec<String>) -> Vec<ComponentReport> {
    let client = reqwest::blocking::Client::new();

    let mut reports:Vec<ComponentReport> = Vec::new();
    // limit is 128 components per request
    // it's ok for now to get them in sequence
    for chunk in purls.chunks(128) {
        let cr = ComponentReportRequest { coordinates: chunk.to_vec() };

        let json = serde_json::to_string(&cr).unwrap();

        // println!("OssIndex Request: {}", &json);

        //TODO: setup useragent like here: https://github.com/sonatype-nexus-community/auditjs/blob/master/src/Services/RequestHelpers.ts#L20-L26
        let res = client.post("https://ossindex.sonatype.org/api/v3/component-report")
            .body(json)
            .header(CONTENT_TYPE, "application/vnd.ossindex.component-report-request.v1+json")
            .send().unwrap();
        
        match res.status() {
            StatusCode::OK => {
                let r:Vec<ComponentReport> = res.json().unwrap();
                println!("SUCCESS: OSSIndex API: ComponentReport: {:?}", r);
                reports.extend(r);
            },
            StatusCode::BAD_REQUEST => {
                let e:ErrorResponse = res.json().unwrap();
                println!("ERROR: OSSIndex API: {:?}", e);
            },
            StatusCode::TOO_MANY_REQUESTS =>
                println!("ERROR: OSSIndex API: to many requests, try again later."),
            _ => println!("ERROR: OSSIndex API: Uknown error {:?}", res)
        }

        // println!("Response: {:?}", res);

        // let s = serde_json::from_str(b)
    }

    reports
}