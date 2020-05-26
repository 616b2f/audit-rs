// package url (purl)
// Purl spec: https://github.com/package-url/purl-spec
// TODO: implementation is not absolutly spec conform, make sure it is in the future

pub struct PackageUrl {
    scheme: String,
    package_type: String,
    namespace: String,
    name: String,
    version: String,

}

impl PackageUrl {

    pub fn new(package_type: String, name: String, version: String) -> PackageUrl {
        PackageUrl{ scheme: "pkg".to_string(), namespace: String::new(), package_type: package_type, name: name, version: version }
    }

    // format: 'scheme:type/namespace/name@version?qualifiers#subpath'
    pub fn build_purl(&self) -> String {
        let mut s = format!("{}:{}/", self.scheme, self.package_type);

        if !self.namespace.is_empty() {
            s.push_str(&self.namespace);
            s.push('/');
        }

        //TODO: validate each field see spec for what to check
        s.push_str(&self.name);

        if !self.version.is_empty() {
            s.push('@');
            let version = &self.version
                .replace("[", "%5B")
                .replace(",", "%2C")
                .replace(")", "%29");
            s.push_str(version);
        }

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_purl_success() {
        let p = PackageUrl::new(
            "nuget".to_string(),
            "IdentityServer4".to_string(),
            "2.4.0".to_string()
        );

        assert_eq!("pkg:nuget/IdentityServer4@2.4.0", p.build_purl());
    }
}