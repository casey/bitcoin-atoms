use {
  colored::Colorize,
  reqwest::{blocking::get, StatusCode},
  std::process,
};

const ENDPOINTS: &[(&str, StatusCode, &str, &str)] = &[
  // PNG content is cached for one year
  (
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    StatusCode::OK,
    "HIT",
    "public, max-age=31536000, immutable",
  ),
  // HTML content is cached for one year
  (
    "/content/114c5c87c4d0a7facb2b4bf515a4ad385182c076a5cfcc2982bf2df103ec0fffi0",
    StatusCode::OK,
    "HIT",
    "public, max-age=31536000, immutable",
  ),
  // content respopnses that aren't found aren't cached
  (
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i1",
    StatusCode::NOT_FOUND,
    "BYPASS",
    "no-store",
  ),
  // HTML previews are cached for one year
  (
    "/preview/114c5c87c4d0a7facb2b4bf515a4ad385182c076a5cfcc2982bf2df103ec0fffi0",
    StatusCode::OK,
    "HIT",
    "public, max-age=31536000, immutable",
  ),
  // non-HTML previews are cached for four hours
  (
    "/preview/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    StatusCode::OK,
    "HIT",
    "max-age=14400",
  ),
  // Sat content is never cached
  (
    "/r/sat/1026903946383519/at/-1/content",
    StatusCode::OK,
    "BYPASS",
    "",
  ),
  ("/static/index.css", StatusCode::OK, "HIT", "max-age=14400"),
  ("/static/index.js", StatusCode::OK, "HIT", "max-age=14400"),
  ("/sat/FOO", StatusCode::BAD_REQUEST, "HIT", "max-age=14400"),
  ("/", StatusCode::OK, "BYPASS", ""),
  ("/blockheight", StatusCode::OK, "BYPASS", ""),
];

fn main() {
  eprint!("Warming up the cache");

  for (endpoint, expected_status_code, _expected_cache_status, _expected_cache_control) in ENDPOINTS
  {
    let response = get(format!("https://ordinals.com{endpoint}")).unwrap();

    assert_eq!(response.status(), *expected_status_code);

    eprint!(".");
  }

  eprintln!();

  let mut failures = 0;

  for (endpoint, expected_status_code, expected_cache_status, expected_cache_control) in ENDPOINTS {
    eprint!("GET {endpoint}");

    let response = get(format!("https://ordinals.com{endpoint}")).unwrap();

    let status_code = response.status();

    eprint!(" {}", status_code.as_u16());

    assert_eq!(response.status(), *expected_status_code);

    let headers = response.headers();

    let mut pass = true;

    let cache_status = headers
      .get("cf-cache-status")
      .map(|value| value.to_str().unwrap().to_string())
      .unwrap_or_default();
    if cache_status == *expected_cache_status {
      eprint!(" {}", cache_status.green());
    } else {
      eprint!(" {}", cache_status.red());
      pass = false;
    }

    let cache_control = headers
      .get("cache-control")
      .map(|value| value.to_str().unwrap().to_string())
      .unwrap_or_default();
    if cache_control == *expected_cache_control {
      eprintln!(" {}", cache_control.green());
    } else {
      eprintln!(" {}", cache_control.red());
      pass = false;
    }

    failures += u32::from(!pass);
  }

  if failures > 0 {
    eprintln!("{failures} failures");
    process::exit(1);
  }
}
