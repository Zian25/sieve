use urlsieve::config::Config;
use urlsieve::dedup::{deduplicate, deduplicate_diff};
use urlsieve::detector::shannon_entropy;
use urlsieve::url::{parse_path, parse_url, Fingerprinter};
use std::env;
use std::io::Cursor;

// ── URL Parsing ──────────────────────────────────────────────

#[test]
fn test_parse_url_with_scheme() {
    let parsed = parse_url("https://example.com/path", "https").unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "example.com");
    assert_eq!(parsed.path, "/path");
}

#[test]
fn test_parse_url_without_scheme() {
    let parsed = parse_url("example.com/path", "https").unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "example.com");
}

#[test]
fn test_parse_url_strips_trailing_dot() {
    let parsed = parse_url("https://example.com./path", "https").unwrap();
    assert_eq!(parsed.host, "example.com");
}

#[test]
fn test_parse_url_rejects_non_http() {
    assert!(parse_url("ftp://example.com/file", "https").is_none());
    assert!(parse_url("javascript:alert(1)", "https").is_none());
    assert!(parse_url("data:text/html,hello", "https").is_none());
}

#[test]
fn test_parse_url_empty_line() {
    assert!(parse_url("", "https").is_none());
    assert!(parse_url("   ", "https").is_none());
}

#[test]
fn test_parse_url_lowercase_host() {
    let parsed = parse_url("https://EXAMPLE.COM/path", "https").unwrap();
    assert_eq!(parsed.host, "example.com");
}

#[test]
fn test_parse_url_default_port_stripped() {
    let parsed = parse_url("https://example.com:443/path", "https").unwrap();
    assert_eq!(parsed.port, None);
}

#[test]
fn test_parse_url_non_default_port() {
    let parsed = parse_url("https://example.com:8080/path", "https").unwrap();
    assert_eq!(parsed.port, Some(8080));
}

#[test]
fn test_parse_url_protocol_relative() {
    // Protocol-relative URLs from crawlers should be handled correctly
    let parsed = parse_url("//cdn.example.com/file.js", "https").unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "cdn.example.com");
    assert_eq!(parsed.path, "/file.js");
}

#[test]
fn test_shannon_entropy_uniform() {
    let e = shannon_entropy("aaaa");
    assert!((e - 0.0).abs() < 0.001);
}

#[test]
fn test_shannon_entropy_max() {
    let e = shannon_entropy("abcd");
    assert!((e - 2.0).abs() < 0.001);
}

#[test]
fn test_shannon_entropy_empty() {
    assert_eq!(shannon_entropy(""), 0.0);
}

#[test]
fn test_shannon_entropy_random_token() {
    let e = shannon_entropy("a3f9d2b1c7e5");
    assert!(e > 3.0);
}

// ── Fingerprinting ──────────────────────────────────────────

#[test]
fn test_fingerprint_uuid_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog", "https").unwrap();
    let p2 = parse_url("https://api.example.com/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{uuid}"));
}

#[test]
fn test_fingerprint_numeric_id_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/users/12345/profile", "https").unwrap();
    let p2 = parse_url("https://api.example.com/users/67890/profile", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{id}"));
}

#[test]
fn test_fingerprint_structural_version_not_normalized() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/v1/users/profile", "https").unwrap();
    let p2 = parse_url("https://api.example.com/v2/users/profile", "https").unwrap();

    assert_ne!(fp.fingerprint(&p1), fp.fingerprint(&p2));
}

#[test]
fn test_fingerprint_mongo_id_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/orders/507f191e810c19729de860ea/items", "https").unwrap();
    let p2 = parse_url("https://api.example.com/orders/507f191e810c19729de860eb/items", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{mongo}"));
}

#[test]
fn test_fingerprint_cache_bust_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://cdn.example.com/assets/bundle.a3f9d2b1c7e5f4a3.js", "https").unwrap();
    let p2 = parse_url("https://cdn.example.com/assets/bundle.b4c5d6e7f8a9b0c1.js", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{hash}"));
}

#[test]
fn test_fingerprint_fragment_stripped() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://example.com/page#section1", "https").unwrap();
    let p2 = parse_url("https://example.com/page#section2", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(!fp.fingerprint(&p1).contains('#'));
}

#[test]
fn test_fingerprint_query_param_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/data?token=abc123&page=1", "https").unwrap();
    let p2 = parse_url("https://api.example.com/data?token=xyz789&page=2", "https").unwrap();

    // Fingerprints differ because page values are preserved (never_normalize)
    assert_ne!(fp.fingerprint(&p1), fp.fingerprint(&p2));

    // token value should be normalized to {dynamic} (always_normalize)
    let fp1 = fp.fingerprint(&p1);
    assert!(
        fp1.contains("token=%7Bdynamic%7D"),
        "token should be {{dynamic}}, got: {}",
        fp1
    );

    // page value should be preserved verbatim (never_normalize)
    assert!(
        fp1.contains("page=1"),
        "page=1 should be preserved, got: {}",
        fp1
    );
}

#[test]
fn test_fingerprint_query_params_sorted() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/data?b=2&a=1", "https").unwrap();
    let p2 = parse_url("https://api.example.com/data?a=1&b=2", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
}

#[test]
fn test_fingerprint_query_param_keys_case_insensitive() {
    // Query param keys should be case-insensitive in fingerprints
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/data?token=abc&page=1", "https").unwrap();
    let p2 = parse_url("https://api.example.com/data?TOKEN=abc&PAGE=1", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
}

#[test]
fn test_fingerprint_repeated_query_params_sorted() {
    // Repeated keys with values in different order should produce the same fingerprint
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/data?a=1&a=2", "https").unwrap();
    let p2 = parse_url("https://api.example.com/data?a=2&a=1", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
}

#[test]
fn test_fingerprint_repeated_always_normalize_param() {
    // Repeated always_normalize keys should both become {dynamic},
    // producing the same fingerprint regardless of original value order
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/data?token=abc&token=xyz", "https").unwrap();
    let p2 = parse_url("https://api.example.com/data?token=xyz&token=abc", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
}

#[test]
fn test_fingerprint_semantic_segments_not_normalized() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://example.com/citiesByState1/results", "https").unwrap();
    let p2 = parse_url("https://example.com/getUserById/data", "https").unwrap();
    let p3 = parse_url("https://example.com/darkMode2/settings", "https").unwrap();

    assert!(fp.fingerprint(&p1).contains("citiesByState1"));
    assert!(fp.fingerprint(&p2).contains("getUserById"));
    assert!(fp.fingerprint(&p3).contains("darkMode2"));
}

#[test]
fn test_fingerprint_short_token_with_digit() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://example.com/r/23c6DSKX", "https").unwrap();
    let p2 = parse_url("https://example.com/r/+GTrA2OF", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{slug}"));
}

#[test]
fn test_fingerprint_mixed_case_token_normalized() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    // Mixed-case short codes with high non-lowercase ratio are detected as tokens
    let p1 = parse_url("https://example.com/r/eVAIHvtd", "https").unwrap();
    let p2 = parse_url("https://example.com/r/GhDCwmjk", "https").unwrap();

    // Both should be normalized to {slug} since they have high non-lowercase ratio
    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{slug}"));
}

#[test]
fn test_fingerprint_ulid_normalization() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://api.example.com/resources/01ARZ3NDEKTSV4RRFFQ69G5FAV/data", "https").unwrap();
    let p2 = parse_url("https://api.example.com/resources/01ARZ3NDEKTSV4RRFFQ69G5FBW/data", "https").unwrap();

    assert_eq!(fp.fingerprint(&p1), fp.fingerprint(&p2));
    assert!(fp.fingerprint(&p1).contains("{ulid}"));
}

// ── Deduplication ───────────────────────────────────────────

#[test]
fn test_deduplicate_basic() {
    let config = Config::default();
    let input = "https://example.com/a\nhttps://example.com/a\nhttps://example.com/b\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    assert_eq!(result.total_urls, 3);
    assert_eq!(result.unique_fingerprints, 2);
    assert_eq!(result.invalid_urls.len(), 0);
}

#[test]
fn test_deduplicate_uuid_groups() {
    let config = Config::default();
    let input = "\
https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog
https://api.example.com/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog
https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog
";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    assert_eq!(result.total_urls, 3);
    assert_eq!(result.unique_fingerprints, 1);
}

#[test]
fn test_deduplicate_representative_deterministic() {
    let config = Config::default();

    let input1 = "\
https://api.example.com/v1/users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/profile
https://api.example.com/v1/users/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/profile
";
    let input2 = "\
https://api.example.com/v1/users/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/profile
https://api.example.com/v1/users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/profile
";

    let r1 = deduplicate(Cursor::new(input1), &config, "https", false, false, false);
    let r2 = deduplicate(Cursor::new(input2), &config, "https", false, false, false);

    assert_eq!(r1.groups.len(), 1);
    assert_eq!(r2.groups.len(), 1);
    assert_eq!(r1.groups[0].representative, r2.groups[0].representative);
    assert_eq!(r1.groups[0].representative, "https://api.example.com/v1/users/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/profile");
}

#[test]
fn test_deduplicate_invalid_urls() {
    let config = Config::default();
    let input = "https://example.com/valid\nftp://example.com/invalid\njavascript:alert(1)\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    assert_eq!(result.total_urls, 3);
    assert_eq!(result.invalid_urls.len(), 2);
}

#[test]
fn test_deduplicate_empty_lines_skipped() {
    let config = Config::default();
    let input = "\n\nhttps://example.com/a\n\n\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    assert_eq!(result.total_urls, 1);
    assert_eq!(result.unique_fingerprints, 1);
}

#[test]
fn test_deduplicate_scheme_assumption() {
    let config = Config::default();
    let input = "example.com/path\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    assert_eq!(result.total_urls, 1);
    assert_eq!(result.unique_fingerprints, 1);
}

#[test]
fn test_deduplicate_strip_query() {
    let config = Config::default();
    let input = "\
https://api.example.com/data?token=abc&page=1
https://api.example.com/data?token=xyz&page=2
";
    let result = deduplicate(Cursor::new(input), &config, "https", true, false, false);

    assert_eq!(result.total_urls, 2);
    assert_eq!(result.unique_fingerprints, 1);
}

// ── Diff Mode ───────────────────────────────────────────────

#[test]
fn test_diff_fingerprint_mode() {
    let config = Config::default();
    let path = env::temp_dir().join("urlsieve_test_fp.txt");

    let baseline_content =
        "https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog\n";
    std::fs::write(&path, baseline_content).unwrap();

    // Same fingerprint, different UUID → should be excluded
    let new_input =
        "https://api.example.com/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog\n";
    let result = deduplicate_diff(
        Cursor::new(new_input),
        path.to_str().unwrap(),
        &config,
        "https",
        false,
        false,
        false,
        false,
    )
    .unwrap();

    assert!(result.is_empty(), "fingerprint match should exclude URL");

    // Different fingerprint → should be included
    let new_input2 = "https://api.example.com/v2/merchants/abc123/catalog\n";
    let result2 = deduplicate_diff(
        Cursor::new(new_input2),
        path.to_str().unwrap(),
        &config,
        "https",
        false,
        false,
        false,
        false,
    )
    .unwrap();

    assert_eq!(result2.len(), 1, "different fingerprint should be included");

    std::fs::remove_file(&path).ok();
}

#[test]
fn test_diff_strict_mode() {
    let config = Config::default();
    let path = env::temp_dir().join("urlsieve_test_strict.txt");

    let baseline_content =
        "https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog\n";
    std::fs::write(&path, baseline_content).unwrap();

    // Same fingerprint but different URL → strict mode should include it
    let new_input =
        "https://api.example.com/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog\n";
    let result = deduplicate_diff(
        Cursor::new(new_input),
        path.to_str().unwrap(),
        &config,
        "https",
        true,
        false,
        false,
        false,
    )
    .unwrap();

    assert_eq!(
        result.len(),
        1,
        "strict mode should include URL with different fingerprint"
    );

    // Exact same URL → should be excluded
    let new_input2 =
        "https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog\n";
    let result2 = deduplicate_diff(
        Cursor::new(new_input2),
        path.to_str().unwrap(),
        &config,
        "https",
        true,
        false,
        false,
        false,
    )
    .unwrap();

    assert!(result2.is_empty(), "exact URL match should be excluded");

    std::fs::remove_file(&path).ok();
}

#[test]
fn test_parse_url_invalid_percent_encoding() {
    // decode_utf8_lossy replaces invalid UTF-8 sequences with U+FFFD replacement character
    // instead of rejecting the URL entirely, allowing bug bounty payloads to be processed
    let parsed = parse_url("https://example.com/path/%FF%FF", "https").unwrap();
    assert!(parsed.path.contains('\u{FFFD}'));
}

#[test]
fn test_parse_url_valid_percent_encoding() {
    let parsed = parse_url("https://example.com/path/hello%20world", "https").unwrap();
    assert_eq!(parsed.path, "/path/hello world");
}

#[test]
fn test_parse_url_httpx_output_format() {
    let parsed = parse_url("https://example.com/path [200] [Cloudflare,HSTS]", "https").unwrap();
    assert_eq!(parsed.host, "example.com");
    assert_eq!(parsed.path, "/path");
}

#[test]
fn test_parse_url_httpx_with_query_params() {
    let parsed = parse_url("https://example.com/search?q=test [301] [Cloudflare]", "https").unwrap();
    assert_eq!(parsed.host, "example.com");
    assert_eq!(parsed.path, "/search");
    assert_eq!(parsed.query.as_deref(), Some("q=test"));
}

// ── Path-Only Mode ──────────────────────────────────────────────

#[test]
fn test_parse_path_basic() {
    let parsed = parse_path("/api/v1/users/12345").unwrap();
    assert_eq!(parsed.scheme, "");
    assert_eq!(parsed.host, "");
    assert_eq!(parsed.path, "/api/v1/users/12345");
    assert!(parsed.query.is_none());
}

#[test]
fn test_parse_path_with_query() {
    let parsed = parse_path("/api/search?q=test&page=1").unwrap();
    assert_eq!(parsed.path, "/api/search");
    assert_eq!(parsed.query.as_deref(), Some("q=test&page=1"));
}

#[test]
fn test_parse_path_query_only() {
    let parsed = parse_path("?action=details").unwrap();
    assert_eq!(parsed.path, "");
    assert_eq!(parsed.query.as_deref(), Some("action=details"));
}

#[test]
fn test_parse_path_with_tool_output() {
    let parsed = parse_path("/api/v1/users [200] [Cloudflare,HSTS]").unwrap();
    assert_eq!(parsed.path, "/api/v1/users");
    assert!(parsed.query.is_none());
}

#[test]
fn test_parse_path_empty() {
    assert!(parse_path("").is_none());
    assert!(parse_path("   ").is_none());
}

#[test]
fn test_deduplicate_path_only_basic() {
    let config = Config::default();
    let input = "/api/v1/users/12345\n/api/v1/users/67890\n/api/v1/users/12345\n/api/v2/products\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, true);
    assert_eq!(result.total_urls, 4);
    // 12345 and 67890 normalize to same fingerprint {id}, so 2 unique groups
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_deduplicate_path_only_groups_uuids() {
    let config = Config::default();
    let input = "/api/v1/users/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/profile\n\
                 /api/v1/users/e917d8d4-1034-44ef-a590-71f53e408986/profile\n\
                 /api/v1/users/57ea1f72-7abe-4d77-be04-94037844e8a2/profile\n\
                 /api/v1/orders/12345\n\
                 /api/v1/orders/67890\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, true);
    assert_eq!(result.total_urls, 5);
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_deduplicate_path_only_query_params() {
    let config = Config::default();
    let input = "/search?q=test&page=1\n\
                 /search?q=other&page=2\n\
                 /search?q=test&page=1\n\
                 ?action=details\n\
                 ?action=details\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, true);
    assert_eq!(result.total_urls, 5);
    assert_eq!(result.unique_fingerprints, 3);
}

// ── Edge Cases ──────────────────────────────────────────────

#[test]
fn test_deduplicate_empty_input() {
    let config = Config::default();
    let result = deduplicate(Cursor::new(""), &config, "https", false, false, false);
    assert_eq!(result.total_urls, 0);
    assert_eq!(result.unique_fingerprints, 0);
    assert!(result.groups.is_empty());
}

#[test]
fn test_deduplicate_all_invalid() {
    let config = Config::default();
    let input = "ftp://bad.com/a\njavascript:alert(1)\ndata:text/html,bad\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);
    assert_eq!(result.total_urls, 3);
    assert_eq!(result.unique_fingerprints, 0);
    assert_eq!(result.invalid_urls.len(), 3);
}

#[test]
fn test_diff_strip_query_mode() {
    let config = Config::default();
    let path = env::temp_dir().join("urlsieve_test_strip.txt");

    let baseline_content = "https://api.example.com/v1/users/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/profile?token=old\n";
    std::fs::write(&path, baseline_content).unwrap();

    let new_input = "https://api.example.com/v1/users/e917d8d4-1034-44ef-a590-71f53e408986/profile?token=new\n";
    let result = deduplicate_diff(
        Cursor::new(new_input),
        path.to_str().unwrap(),
        &config,
        "https",
        false,
        true,
        false,
        false,
    )
    .unwrap();

    assert!(result.is_empty(), "should match when query is stripped and UUIDs normalize");

    std::fs::remove_file(&path).ok();
}

#[test]
fn test_fingerprint_with_port() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p = parse_url("https://example.com:8080/api/data", "https").unwrap();
    let fingerprint = fp.fingerprint(&p);
    assert!(fingerprint.contains(":8080"));
}

#[test]
fn test_fingerprint_strip_query() {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p = parse_url("https://api.example.com/data?token=abc&page=1", "https").unwrap();
    let fp_with_query = fp.fingerprint(&p);
    let fp_without_query = fp.fingerprint_with_strip_query(&p);

    assert!(fp_with_query.contains('?'));
    assert!(!fp_without_query.contains('?'));
    assert_eq!(fp_without_query, "https://api.example.com/data");
}

// ── Learned Config ──────────────────────────────────────────

use urlsieve::pipeline::{build_learned_config, analyze_cardinality};

#[test]
fn test_build_learned_config() {
    let config = Config::default();
    let input = "\
https://api.example.com/v1/users/abc123?session=tok1&locale=en
https://api.example.com/v1/users/def456?session=tok2&locale=en
https://api.example.com/v1/users/ghi789?session=tok3&locale=en
https://api.example.com/v1/users/jkl012?session=tok4&locale=en
https://api.example.com/v1/users/mno345?session=tok5&locale=en
https://api.example.com/v1/users/pqr678?session=tok6&locale=en
";
    let analyzed = analyze_cardinality(Cursor::new(input), &config, "https", false);
    let learned = build_learned_config(&analyzed.report);

    // session has 6 unique values → falls between thresholds (not always/never normalized)
    // locale has 1 unique value → should be in never_normalize (≤5)
    assert!(learned.normalize_params.never_normalize.contains(&"locale".to_string()));
}

#[test]
fn test_save_learned_config_roundtrip() {
    use urlsieve::pipeline::save_learned_config;

    let config = Config::default();
    // Generate enough unique values to trigger always_normalize
    let mut lines = Vec::new();
    for i in 0..60 {
        lines.push(format!("https://api.example.com/page?cache_bust=val{i}"));
    }
    let input = lines.join("\n");

    let analyzed = analyze_cardinality(Cursor::new(input), &config, "https", false);
    save_learned_config(&analyzed.report, "test_learned.toml").unwrap();

    // Verify the file can be loaded back
    let loaded = Config::load(std::path::Path::new("test_learned.toml")).unwrap();
    assert!(loaded.normalize_params.always_normalize.contains(&"cache_bust".to_string()));

    std::fs::remove_file("test_learned.toml").ok();
}

// ── JSON Output ─────────────────────────────────────────────

#[test]
fn test_json_output_format() {
    let config = Config::default();
    let input = "https://example.com/a\nhttps://example.com/b\n";
    let result = deduplicate(Cursor::new(input), &config, "https", false, false, false);

    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("total_urls"));
    assert!(json.contains("unique_fingerprints"));
    assert!(json.contains("groups"));
    assert!(json.contains("fingerprint"));
    assert!(json.contains("invalid_urls"));
}

// ── Contract Tests (end-to-end grouping correctness) ────────

#[test]
fn test_uuid_in_path_groups_correctly() {
    // The core motivating case — URLs with same pattern but different UUIDs
    let input = "\
https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog
https://api.example.com/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog
https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/extra";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);

    // 2 fingerprints: /catalog and /extra — not 3
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_always_normalize_param_grouped() {
    let input = "\
https://api.example.com/search?q=pizza&token=abc123
https://api.example.com/search?q=pizza&token=xyz789";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 1);
}

#[test]
fn test_never_normalize_param_preserved() {
    let input = "\
https://api.example.com/items?page=1
https://api.example.com/items?page=2";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_camelcase_segments_not_normalized() {
    let input = "\
https://api.example.com/citiesByState?state=SP
https://api.example.com/citiesByState?state=RJ
https://api.example.com/getUserProfile/data
https://api.example.com/darkMode/settings";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);

    // citiesByState with different states = 2 fingerprints
    // getUserProfile and darkMode = 2 unique fingerprints, not normalized
    assert_eq!(result.unique_fingerprints, 4);
}

#[test]
fn test_cache_bust_filename_grouped() {
    let input = "\
https://cdn.example.com/assets/bundle.a3f9d2b1.js
https://cdn.example.com/assets/bundle.c7e5d2a1.js";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 1);
}

#[test]
fn test_cache_bust_multi_dot_grouped() {
    // Webpack-style bundles: file.HASH.min.js, file.HASH.prod.css
    let input = "\
https://cdn.example.com/assets/app.a1b2c3d4e5f6.min.js
https://cdn.example.com/assets/app.f6e5d4c3b2a1.min.js
https://cdn.example.com/assets/styles.1234567890abcdef.prod.css
https://cdn.example.com/assets/styles.abcdef1234567890.prod.css";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_cache_bust_numeric_not_grouped() {
    // Pure numeric "hashes" should NOT be treated as cache-bust hashes.
    // These are likely SKUs or product IDs, not build hashes.
    let input = "\
https://cdn.example.com/images/sku.88392011.jpg
https://cdn.example.com/images/sku.99112233.jpg";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_non_hash_filename_not_grouped() {
    let input = "\
https://cdn.example.com/assets/main.js
https://cdn.example.com/assets/vendor.js";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);
    assert_eq!(result.unique_fingerprints, 2);
}

#[test]
fn test_invalid_encoding_processed_lossy() {
    // decode_utf8_lossy replaces invalid UTF-8 sequences with U+FFFD replacement character
    // so URLs with invalid percent encoding are still processed instead of being rejected
    let input = "https://example.com/path/%FF%FF/resource";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);

    assert_eq!(result.total_urls, 1);
    assert_eq!(result.unique_fingerprints, 1);
    assert!(result.invalid_urls.is_empty());
}

#[test]
fn test_marketplace_regression() {
    // Golden test with a small subset of real marketplace URLs
    // This catches unintended behavioral changes
    let input = "\
https://marketplace.example.com.br/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog
https://marketplace.example.com.br/v1/merchants/e917d8d4-1034-44ef-a590-71f53e408986/catalog
https://marketplace.example.com.br/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/extra
https://marketplace.example.com.br/restaurant/0bffccfe-2df1-4fb0-94b5-43100eac659e/menuitem/57ea1f72-7abe-4d77-be04-94037844e8a2
https://marketplace.example.com.br/restaurant/de79e73f-f19d-410d-8b0e-74b885de7525/menuitem/39345825
https://marketplace.example.com.br/shortener/r/23c6DSKX
https://marketplace.example.com.br/shortener/r/+GTrA2OF
https://marketplace.example.com.br/citiesByState?state=AL&country=BR
https://marketplace.example.com.br/citiesByState?state=SP&country=BR
https://marketplace.example.com.br/robots.txt
https://marketplace.example.com.br/favicon.ico
";

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);

    // Expected grouping:
    // 1. /v1/merchants/{uuid}/catalog (2 URLs)
    // 2. /v1/merchants/{uuid}/extra (1 URL)
    // 3. /restaurant/{uuid}/menuitem/{uuid} (1 URL)
    // 4. /restaurant/{uuid}/menuitem/{id} (1 URL — 39345825 is numeric, not UUID)
    // 5. /shortener/r/{slug} (2 URLs)
    // 6. /citiesByState?state=AL (1 URL)
    // 7. /citiesByState?state=SP (1 URL)
    // 8. /robots.txt (1 URL)
    // 9. /favicon.ico (1 URL)
    assert_eq!(result.total_urls, 11);
    assert_eq!(result.unique_fingerprints, 9);
    assert_eq!(result.invalid_urls.len(), 0);
}

#[test]
fn test_real_world_dataset_regression() {
    // Golden test with 200 real URLs from marketplace.txt
    // This catches unintended behavioral changes that synthetic data won't reveal
    let input = include_str!("../testdata/real_world.txt");

    let result = deduplicate(Cursor::new(input), &Config::default(), "https", false, false, false);

    // Fixed numbers from the known dataset
    assert_eq!(result.total_urls, 200);
    // Most URLs are /restaurant/{uuid}/menuitem/{uuid} patterns
    assert!(result.unique_fingerprints <= 30);
    assert_eq!(result.invalid_urls.len(), 0);
}

// ── Pattern Selection ────────────────────────────────────────

#[test]
fn test_patterns_uuid_disabled_falls_back_to_hash() {
    // When uuid detection is disabled, UUIDs with dashes pass through as literals
    // because the hash regex ^[0-9a-fA-F]{16,}$ requires contiguous hex chars
    // (dashes break the match). This documents the contract: disabling a pattern
    // does NOT cause its segments to be caught by another detector.
    let mut config = Config::default();
    config.general.patterns = vec!["hash".into()];
    let fp = Fingerprinter::new(&config);

    let p = parse_url(
        "https://api.example.com/users/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/profile",
        "https",
    ).unwrap();

    let fingerprint = fp.fingerprint(&p);
    assert!(fingerprint.contains("df8b8a77-6f3e-4733-978c-f0b8fa28b0a4"));
}

#[test]
fn test_patterns_selective_only_uuid() {
    // --patterns uuid should only enable UUID detection, everything else passes through
    let mut config = Config::default();
    config.general.patterns = vec!["uuid".into()];
    let fp = Fingerprinter::new(&config);

    // UUID is normalized
    let p1 = parse_url(
        "https://api.example.com/users/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/profile",
        "https",
    ).unwrap();
    assert!(fp.fingerprint(&p1).contains("{uuid}"));

    // Numeric ID is NOT normalized (numid disabled)
    let p2 = parse_url("https://api.example.com/items/12345678/detail", "https").unwrap();
    assert!(fp.fingerprint(&p2).contains("12345678"));

    // Hash is NOT normalized (hash disabled)
    let p3 = parse_url("https://api.example.com/files/a1b2c3d4e5f6a7b8c9d0/data", "https").unwrap();
    assert!(fp.fingerprint(&p3).contains("a1b2c3d4e5f6a7b8c9d0"));
}

#[test]
fn test_all_regex_patterns_compile() {
    use urlsieve::detector::PatternKind;
    for kind in PatternKind::ALL {
        regex::RegexSet::new([kind.regex()]).unwrap_or_else(|_| {
            panic!("Pattern '{}' has invalid regex: {}", kind.name(), kind.regex())
        });
    }
}

#[test]
fn test_cache_bust_with_locale_code() {
    // app.a1b2c3d4e5f6.en.js should normalize the hash even with locale code between hash and extension
    let config = Config::default();
    let fp = Fingerprinter::new(&config);

    let p1 = parse_url("https://cdn.example.com/app.a1b2c3d4e5f6.en.js", "https").unwrap();
    let p2 = parse_url("https://cdn.example.com/app.deadbeefcafe.en.js", "https").unwrap();

    let fp1 = fp.fingerprint(&p1);
    let fp2 = fp.fingerprint(&p2);
    assert_eq!(fp1, fp2);
    assert!(fp1.contains("{hash}"));
}
