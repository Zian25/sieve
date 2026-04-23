use url::Url;

#[derive(Debug, Clone)]
pub struct ParsedUrl {
    #[allow(dead_code)]
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
}

#[must_use]
pub fn parse_url(input: &str, assume_scheme: &str) -> Option<ParsedUrl> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handle protocol-relative URLs: //cdn.example.com/file.js
    let trimmed = trimmed.strip_prefix("//").unwrap_or(trimmed);

    let url_str = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("{assume_scheme}://{trimmed}")
    };

    let parsed = Url::parse(&url_str).ok()?;

    let scheme = parsed.scheme().to_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let host = match parsed.host() {
        Some(url::Host::Ipv6(addr)) => format!("[{addr}]"),
        Some(_) => parsed.host_str().unwrap_or("").to_lowercase(),
        None => return None,
    };
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();

    let port = parsed.port();
    let path = percent_decode(parsed.path());

    let query = parsed.query().map(std::string::ToString::to_string);

    Some(ParsedUrl {
        original: trimmed.to_string(),
        scheme,
        host,
        port,
        path,
        query,
    })
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}
