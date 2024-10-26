use std::collections::HashMap;

/// Print a hexdump with some width and a label
pub fn annotated_hex_dump(label: &str, bytes: &[u8], max_octets: Option<usize>, show_addr: bool) {
    let width = max_octets.unwrap_or(bytes.len());

    // TODO: should be trace log
    println!("{} [{}]:", label, bytes.len());
    for (line_number, chunk) in bytes.chunks(width).enumerate() {
        let offset = line_number * width;
        // TODO: should be trace log
        println!(
            "    {}{}",
            show_addr
                .then(|| format!("{offset:04x} | "))
                .unwrap_or_default(),
            hex_dump(chunk)
        );
    }
}

/// Turn a byte slice into space-separated hex octets
#[must_use]
pub fn hex_dump(x: &[u8]) -> String {
    x.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stores cookies on incoming requests
#[derive(Debug)]
pub struct CookieJar<'a> {
    cookies: HashMap<&'a str, &'a str>,
}

impl<'a> CookieJar<'a> {
    /// Get a cookie with some name (names are normalized to be all lowercase)
    #[must_use]
    pub fn get_cookie_named(&self, name: &str) -> Option<&'a str> {
        self.cookies.get(name).copied()
    }
}

impl<'a> TryFrom<&'a str> for CookieJar<'a> {
    type Error = ();

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            // TODO: get rid of this pointless allocation in case there are no cookies
            return Ok(CookieJar {
                cookies: HashMap::new(),
            });
        }

        let mut cookies = HashMap::new();

        for cookie in cookie::Cookie::split_parse(value) {
            let cookie = cookie.unwrap();
            let cookie_name = cookie.name_raw().unwrap();
            let cookie_value = cookie.value_raw().unwrap();

            if cookies.try_insert(cookie_name, cookie_value).is_err() {
                // TODO: determine if this is actually an error, or if the last value is supposed to
                //       take precedence.
                eprintln!("duplicate cookie key");
                return Err(());
            }
        }

        Ok(CookieJar { cookies })
    }
}
