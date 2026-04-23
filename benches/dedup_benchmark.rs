use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use urlsieve::config::Config;
use urlsieve::dedup::deduplicate;
use urlsieve::url::Fingerprinter;
use std::io::Cursor;

struct SeededRng(u64);

impl SeededRng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn rng_uuid(rng: &mut SeededRng) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rng.next() & 0xFFFFFFFF,
        (rng.next() & 0xFFFF) as u16,
        (rng.next() & 0xFFFF) as u16,
        (rng.next() & 0xFFFF) as u16,
        rng.next() & 0xFFFFFFFFFFFF,
    )
}

fn rng_slug(rng: &mut SeededRng) -> String {
    format!("{:08X}", rng.next() & 0xFFFFFFFF)
}

fn generate_realistic_urls(count: usize) -> String {
    let mut urls = String::with_capacity(count * 120);
    let mut rng = SeededRng(42);

    // Each template uses named placeholders for correct substitution
    let templates: &[fn(&mut SeededRng) -> String] = &[
        |rng| format!("/v1/merchants/{}/catalog", rng_uuid(rng)),
        |rng| format!("/v1/merchants/{}/extra", rng_uuid(rng)),
        |rng| {
            format!(
                "/v1/merchants/{}/catalog-category/{}/items",
                rng_uuid(rng),
                rng_uuid(rng)
            )
        },
        |rng| format!("/v1/customers/me/orders/{}/events", rng_uuid(rng)),
        |rng| format!("/v1/merchants/{}/payment-methods", rng_uuid(rng)),
        |rng| format!("/v1/merchants/{}/taxonomies", rng_uuid(rng)),
        |rng| format!("/v1/merchants/{}/item-recommendation", rng_uuid(rng)),
        |_rng| "/v1/consumers/services/me/attributes".to_string(),
        |_rng| "/v1/customers/me/contact-methods".to_string(),
        |_rng| "/v1/customers/me/data-privacy/preferences".to_string(),
        |_rng| "/v1/credential-support/forms".to_string(),
        |_rng| "/v1/campaigns/tags".to_string(),
        |_rng| "/v1/identity-providers/OTP/authorization-codes".to_string(),
        |_rng| "/v1/merchant-info/graphql".to_string(),
        |rng| format!("/v1/bm/merchants/{}/catalog", rng_uuid(rng)),
        |rng| {
            format!(
                "/restaurant/{}/menuitem/{}",
                rng_uuid(rng),
                rng.next() % 100000
            )
        },
        |rng| {
            let cities = [
                "sao-paulo-sp",
                "rio-de-janeiro-rj",
                "belo-horizonte-mg",
                "curitiba-pr",
                "porto-alegre-rs",
                "salvador-ba",
                "recife-pe",
                "fortaleza-ce",
                "brasilia-df",
                "manaus-am",
            ];
            format!(
                "/v1/merchants-by-city/br/{}",
                cities[(rng.next() as usize) % cities.len()]
            )
        },
        |rng| format!("/shortener/r/{}", rng_slug(rng)),
        |rng| {
            let states = ["AC", "AL", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MG"];
            format!(
                "/citiesByState?state={}&country=BR",
                states[(rng.next() as usize) % states.len()]
            )
        },
    ];

    let mut recent_urls: Vec<String> = Vec::with_capacity(count);

    for i in 0..count {
        // ~25% chance of duplicating a recent URL
        if i > 100 && !recent_urls.is_empty() && rng.next() % 4 == 0 {
            let idx = (rng.next() as usize) % recent_urls.len();
            urls.push_str(&recent_urls[idx]);
            urls.push('\n');
            continue;
        }

        let template_idx = (rng.next() as usize) % templates.len();
        let path = templates[template_idx](&mut rng);
        let domain = rng.next() % 5;
        let url = format!("https://api{}.example.com{}", domain, path);

        urls.push_str(&url);
        urls.push('\n');

        if recent_urls.len() < 200 {
            recent_urls.push(url);
        } else {
            let idx = (rng.next() as usize) % recent_urls.len();
            recent_urls[idx] = url;
        }
    }

    urls
}

fn bench_fingerprint_single(c: &mut Criterion) {
    let config = Config::default();
    let fp = Fingerprinter::new(&config);
    let parsed = urlsieve::url::parse_url(
        "https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog?page=1&token=abc123",
        "https",
    )
    .unwrap();

    c.bench_function("fingerprint_single", |b| {
        b.iter(|| fp.fingerprint(&parsed));
    });
}

fn bench_parse_single(c: &mut Criterion) {
    let url = "https://api.example.com/v1/merchants/df8b8a77-6f3e-4733-978c-f0b8fa28b0a4/catalog?page=1&token=abc123";

    c.bench_function("parse_single", |b| {
        b.iter(|| urlsieve::url::parse_url(url, "https"));
    });
}

fn bench_dedup(c: &mut Criterion) {
    let config = Config::default();
    let sizes = [1_000, 10_000, 100_000];

    for size in sizes {
        let urls = generate_realistic_urls(size);
        c.bench_with_input(BenchmarkId::new("dedup", size), &urls, |b, urls| {
            b.iter(|| deduplicate(Cursor::new(urls), &config, "https", false, false));
        });
    }
}

fn bench_throughput(c: &mut Criterion) {
    let config = Config::default();
    let urls = generate_realistic_urls(100_000);

    c.bench_function("throughput_100k", |b| {
        b.iter(|| {
            let result = deduplicate(Cursor::new(&urls), &config, "https", false, false);
            result.unique_fingerprints
        });
    });
}

criterion_group!(
    benches,
    bench_parse_single,
    bench_fingerprint_single,
    bench_dedup,
    bench_throughput,
);
criterion_main!(benches);
