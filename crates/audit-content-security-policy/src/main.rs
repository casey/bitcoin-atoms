use {colored::Colorize, reqwest::blocking::get, std::process};

const SERVERS: &[(&str, &str, &str)] = &[
  (
    "regtest.ordinals.net",
    "/content/41bf99a297ca79d181160a91fc0efc8a71170ee24b87783c9c11b0fcbe23615fi0",
    "https://regtest.ordinals.com/content/",
  ),
  (
    "regtest.ordinals.com",
    "/content/41bf99a297ca79d181160a91fc0efc8a71170ee24b87783c9c11b0fcbe23615fi0",
    "https://regtest.ordinals.com/content/",
  ),
  (
    "signet.ordinals.net",
    "/content/7e1bc3b56b872aaf4d1aaf1565fac72182313c9142b207f9398afe263e234135i0",
    "https://signet.ordinals.com/",
  ),
  (
    "signet.ordinals.com",
    "/content/7e1bc3b56b872aaf4d1aaf1565fac72182313c9142b207f9398afe263e234135i0",
    "https://signet.ordinals.com/",
  ),
  (
    "testnet.ordinals.net",
    "/content/0a1b4e4acf89686e4d012561014041bffd57a62254486f24cb5b0a216c04f102i0",
    "https://testnet.ordinals.com/content/",
  ),
  (
    "testnet.ordinals.com",
    "/content/0a1b4e4acf89686e4d012561014041bffd57a62254486f24cb5b0a216c04f102i0",
    "https://testnet.ordinals.com/content/",
  ),
  (
    "alpha.ordinals.net",
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    "https://ordinals.com/content/",
  ),
  (
    "bravo.ordinals.net",
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    "https://ordinals.com/content/",
  ),
  (
    "charlie.ordinals.net",
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    "https://ordinals.com/content/",
  ),
  (
    "ordinals.com",
    "/content/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
    "https://ordinals.com/content/",
  ),
];

fn main() {
  let mut failures = 0;

  for (host, path, needle) in SERVERS {
    eprint!("GET {host}");

    let response = get(format!("https://{host}{path}")).unwrap();

    let mut fail = false;

    if !response.status().is_success() {
      eprint!(" {}", response.status().to_string().red());
      fail = true;
    }

    let headers = response.headers();

    let content_security_policy = headers
      .get("content-security-policy")
      .map(|value| value.to_str().unwrap().to_string())
      .unwrap_or_default();

    if !content_security_policy.contains(needle) {
      fail = true;
    }

    if fail {
      eprintln!(" {}", "FAIL".red());
      failures += 1;
    } else {
      eprintln!(" {}", "PASS".green());
    }
  }

  if failures > 0 {
    process::exit(1);
  }
}
