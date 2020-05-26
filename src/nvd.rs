use serde;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Assembly
{
    #[serde(rename(deserialize = "companyName"))]
    company_name: String,
    #[serde(rename(deserialize = "productName"))]
    product_name: String,
    #[serde(rename(deserialize = "productVersion"))]
    product_verion: String,
}

// Well-Formed CPE Name (WFN)
// more about CPE and CVE and how they can be used in Vulnerability Management System (VMS)
// https://www.groundai.com/project/software-vulnerability-analysis-using-cpe-and-cve/1
struct CpeWfn {
    part: CpePart,
    vendor: String,
    product: String,
    version: String,
    update: String, // NA= not available
    edition: String, // ANY
    language: String,
    sw_edition: String,
    target_sw: String,
    target_hw: String,
    other: String,
}

// more about this implementation see: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
impl CpeWfn {
    fn new(part: CpePart, vendor: String, product: String, version: String) -> CpeWfn {
        CpeWfn { 
            part: part,
            vendor: vendor,
            product: product,
            version: version,
            update: String::new(),
            edition: String::new(),
            language: String::new(),
            sw_edition: String::new(),
            target_sw: String::new(),
            target_hw: String::new(),
            other: String::new(),
        }
    }

    fn bind_to_uri_2_2(&self) -> String {

        let pct_encode = |st: &String| -> String {
            st.replace("\\.",".") // escaped chars
            .replace("\\!", "%21")
            .replace("\\\"", "%22")
            .replace("\\#", "%23")
            .replace("\\$", "%24")
            .replace("\\%", "%25")
            .replace("\\&", "%26")
            .replace("\\'", "%27")
            .replace("\\(", "%28")
            .replace("\\)", "%29")
            .replace("\\*", "%2a")
            .replace("\\+", "%2b")
            .replace("\\,", "%2c")
            .replace("\\/", "%2f")
            .replace("\\:", "%3a")
            .replace("\\;", "%3b")
            .replace("\\<", "%3c")
            .replace("\\=", "%3d")
            .replace("\\>", "%3e")
            .replace("\\?", "%3f")
            .replace("\\@", "%40")
            .replace("\\[", "%5b")
            .replace("\\\\", "%5c")
            .replace("\\]", "%5d")
            .replace("\\^", "%5e")
            .replace("\\`", "%60")
            .replace("\\{", "%7b")
            .replace("\\|", "%7c")
            .replace("\\}", "%7d")
            .replace("\\~", "%7e")
            .replace("*", "%02") // unescaped chars
            .replace("?", "%01")
        };

        let bind_value_for_uri = |st: &String| -> String {
            match st.as_ref() {
                "ANY" => String::new(),
                "NA" => String::from("-"),
                _ => pct_encode(&st)
            }
        };

        let pack = |ed: &String, sw_ed: &String,t_sw: &String,t_hw: &String, oth: &String| -> String {
            if sw_ed.is_empty()
                && sw_ed.is_empty()
                && t_sw.is_empty() 
                && t_hw.is_empty()
                && oth.is_empty() {
                    return String::from(ed);
            } else {
                return format!("~{}~{}~{}~{}~{}", ed, sw_ed, t_sw, t_hw, oth);
            }
        };

        let mut st = format!("cpe:/{}:{}:{}:{}:{}",
            self.part,
            bind_value_for_uri(&self.vendor),
            bind_value_for_uri(&self.product),
            bind_value_for_uri(&self.version),
            bind_value_for_uri(&self.update)
        );

        st.push(':');

        let ed = bind_value_for_uri(&self.edition);
        let sw_ed = bind_value_for_uri(&self.sw_edition);
        let t_sw = bind_value_for_uri(&self.target_sw);
        let t_hw = bind_value_for_uri(&self.target_hw);
        let oth = bind_value_for_uri(&self.other);
        st += &pack(&ed,&sw_ed,&t_sw,&t_hw,&oth);

        if st.ends_with(':') {
            st.pop();
        }

        st
    }

    fn bind_to_fs_2_3(&self) -> String {

        let process_quoted_chars = |st: &String| -> String {
            let mut ns = String::new();
            let mut it = st.chars().peekable();
            while let Some(c) = it.next() {
                match c {
                    '\\' => { // escaped chars have special cases
                        match it.peek() {
                            Some(n) => {
                                match n {
                                    '.' | '-' | '_' => {
                                        // dot, hyphon and underscore we take unescaped
                                        ns.push(*n);
                                        it.next();
                                    },
                                    _ => {
                                        // escaped chars are kept escaped
                                        ns.push('\\');
                                        ns.push(*n);
                                        it.next();
                                    }
                                }
                            }
                            None => {}
                        }
                    },
                    _ => { // unescaped characters are taken as is
                        ns.push(c);
                    },
                }
            }

            ns
        };

        let bind_value_for_fs = |st: &String| -> String {
            match st.as_ref() {
                "ANY" | "" => String::from("*"),
                "NA" => String::from("-"),
                _ => process_quoted_chars(&st)
            }
        };

        let st = format!("cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part,
            bind_value_for_fs(&self.vendor),
            bind_value_for_fs(&self.product),
            bind_value_for_fs(&self.version),
            bind_value_for_fs(&self.update),
            bind_value_for_fs(&self.edition),
            bind_value_for_fs(&self.language),
            bind_value_for_fs(&self.sw_edition),
            bind_value_for_fs(&self.target_sw),
            bind_value_for_fs(&self.target_hw),
            bind_value_for_fs(&self.other)
        );

        st
    }
}

enum CpePart
{
    Application,
    OperatingSystem,
    HardwareDevice,
}

impl std::fmt::Display for CpePart {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            CpePart::Application => write!(f, "a"),
            CpePart::OperatingSystem => write!(f, "o"),
            CpePart::HardwareDevice => write!(f, "h"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_to_uri_2_2_test_example1() {
        // wfn:[part="a",vendor="microsoft",product="internet_explorer",
        // version="8\.0\.6001",update="beta",edition=ANY]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("microsoft"),
            String::from("internet_explorer"),
            String::from("8\\.0\\.6001"),
        );
        cpe.update = String::from("beta");
        cpe.edition = String::from("ANY");

        assert_eq!("cpe:/a:microsoft:internet_explorer:8.0.6001:beta", cpe.bind_to_uri_2_2());
    }

    #[test]
    fn bind_to_uri_2_2_test_example2() {
        // wfn:[part="a",vendor="microsoft",product="internet_explorer",
        // version="8\.*",update="sp?"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("microsoft"),
            String::from("internet_explorer"),
            String::from("8\\.*"),
        );
        cpe.update = String::from("sp?");

        assert_eq!("cpe:/a:microsoft:internet_explorer:8.%02:sp%01", cpe.bind_to_uri_2_2());
    }

    #[test]
    fn bind_to_uri_2_2_test_example3() {
        // wfn:[part="a",vendor="hp",product="insight_diagnostics",
        // version="7\.4\.0\.1570",update=NA,
        // sw_edition="online",target_sw="win2003",target_hw="x64"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("hp"),
            String::from("insight_diagnostics"),
            String::from("7\\.4\\.0\\.1570"),
        );
        cpe.update = String::from("NA");
        cpe.sw_edition = String::from("online");
        cpe.target_sw = String::from("win2003");
        cpe.target_hw = String::from("x64");

        assert_eq!("cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~", cpe.bind_to_uri_2_2());
    }

    #[test]
    fn bind_to_uri_2_2_test_example4() {
        // wfn:[part="a",vendor="hp",product="openview_network_manager",
        // version="7\.51",target_sw="linux"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("hp"),
            String::from("openview_network_manager"),
            String::from("7\\.51"),
        );
        cpe.target_sw = String::from("linux");

        assert_eq!("cpe:/a:hp:openview_network_manager:7.51::~~~linux~~", cpe.bind_to_uri_2_2());
    }

    #[test]
    fn bind_to_uri_2_2_test_example5() {
        // wfn:[part="a",vendor="foo\\bar",product="big\$money_manager_2010",
        // sw_edition="special",target_sw="ipod_touch",target_hw="80gb"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("foo\\\\bar"),
            String::from("big\\$money_manager_2010"),
            String::new(),
        );
        cpe.sw_edition = String::from("special");
        cpe.target_sw = String::from("ipod_touch");
        cpe.target_hw = String::from("80gb");

        assert_eq!("cpe:/a:foo%5cbar:big%24money_manager_2010:::~~special~ipod_touch~80gb~", cpe.bind_to_uri_2_2());
    }

    #[test]
    fn bind_to_fs_2_3_test_example1() {
        // wfn:[part="a",vendor="microsoft",product="internet_explorer",
        // version="8\.0\.6001",update="beta",edition=ANY]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("microsoft"),
            String::from("internet_explorer"),
            String::from("8\\.0\\.6001"),
        );
        cpe.update = String::from("beta");
        cpe.edition = String::from("ANY");

        assert_eq!("cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*", cpe.bind_to_fs_2_3());
    }

    #[test]
    fn bind_to_fs_2_3_test_example2() {
        // wfn:[part="a",vendor="microsoft",product="internet_explorer",
        // version="8\.*",update="sp?",edition=ANY]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("microsoft"),
            String::from("internet_explorer"),
            String::from("8\\.*"),
        );
        cpe.update = String::from("sp?");

        assert_eq!("cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*", cpe.bind_to_fs_2_3());
    }

    #[test]
    fn bind_to_fs_2_3_test_example3() {
        // wfn:[part="a",vendor="hp",product="insight",
        // version="7\.4\.0\.1570",update=NA,
        // sw_edition="online",target_sw="win2003",target_hw="x64"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("hp"),
            String::from("insight"),
            String::from("7\\.4\\.0\\.1570"),
        );
        cpe.update = String::from("NA");
        cpe.sw_edition = String::from("online");
        cpe.target_sw = String::from("win2003");
        cpe.target_hw = String::from("x64");

        assert_eq!("cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*", cpe.bind_to_fs_2_3());
    }

    #[test]
    fn bind_to_fs_2_3_test_example4() {
        // wfn:[part="a",vendor="hp",product="insight",
        // version="7\.4\.0\.1570",update=NA,
        // sw_edition="online",target_sw="win2003",target_hw="x64"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("hp"),
            String::from("insight"),
            String::from("7\\.4\\.0\\.1570"),
        );
        cpe.update = String::from("NA");
        cpe.sw_edition = String::from("online");
        cpe.target_sw = String::from("win2003");
        cpe.target_hw = String::from("x64");

        assert_eq!("cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*", cpe.bind_to_fs_2_3());
    }

    #[test]
    fn bind_to_fs_2_3_test_example5() {
        // wfn:[part="a",vendor="foo\\bar",product="big\$money_2010",
        // sw_edition="special",target_sw="ipod_touch",target_hw="80gb"]
        let mut cpe = CpeWfn::new( 
            CpePart::Application,
            String::from("foo\\\\bar"),
            String::from("big\\$money_2010"),
            String::new(),
        );
        cpe.sw_edition = String::from("special");
        cpe.target_sw = String::from("ipod_touch");
        cpe.target_hw = String::from("80gb");

        assert_eq!(r#"cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*"#, cpe.bind_to_fs_2_3());
    }
}