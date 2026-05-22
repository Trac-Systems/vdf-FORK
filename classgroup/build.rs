use std::process::Command;

fn main() {
    check_gmp_version();
}

fn check_gmp_version() {
    if let Ok(output) = Command::new("pkg-config").args(["--modversion", "gmp"]).output() {
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout);
            assert_gmp_safe(version.trim());
            return;
        }
    }

    // Fallback: read version macros directly from gmp.h
    let header_paths = [
        "/usr/include/gmp.h",
        "/usr/local/include/gmp.h",
        "/opt/homebrew/include/gmp.h",
    ];

    for path in &header_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Some(version) = parse_gmp_header_version(&content) {
                assert_gmp_safe(&version);
                return;
            }
        }
    }

    println!(
        "cargo:warning=Could not determine GMP version. \
         GMP >= 6.2.0 is required for safe primality testing (Baillie-PSW). \
         See https://eprint.iacr.org/2018/749.pdf"
    );
}

fn parse_gmp_header_version(content: &str) -> Option<String> {
    let mut major = None;
    let mut minor = None;
    let mut patch = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#define __GNU_MP_VERSION ") {
            major = rest.trim().parse::<u32>().ok();
        } else if let Some(rest) = line.strip_prefix("#define __GNU_MP_VERSION_MINOR ") {
            minor = rest.trim().parse::<u32>().ok();
        } else if let Some(rest) = line.strip_prefix("#define __GNU_MP_VERSION_PATCHLEVEL ") {
            patch = rest.trim().parse::<u32>().ok();
        }
    }

    match (major, minor, patch) {
        (Some(maj), Some(min), Some(pat)) => Some(format!("{maj}.{min}.{pat}")),
        _ => None,
    }
}

fn assert_gmp_safe(version_str: &str) {
    let parts: Vec<u32> = version_str
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();

    let major = parts.first().copied().unwrap_or(0);
    let minor = parts.get(1).copied().unwrap_or(0);

    // GMP 6.2.0 added a Baillie-PSW test inside mpz_probab_prime_p, making it
    // resistant to adversarially crafted composite inputs. Prior versions relied
    // solely on Miller-Rabin, which can be defeated regardless of round count.
    // See: https://eprint.iacr.org/2018/749.pdf ("Prime and Prejudice")
    if major < 6 || (major == 6 && minor < 2) {
        panic!(
            "\n\n\
             GMP version {} is too old.\n\
             GMP >= 6.2.0 is required because earlier versions use only Miller-Rabin\n\
             primality tests without Baillie-PSW, making hash_prime vulnerable to\n\
             adversarially crafted inputs.\n\
             See: https://eprint.iacr.org/2018/749.pdf\n\n",
            version_str
        );
    }
}
