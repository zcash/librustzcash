use payment_uri::{Error, Network, PaymentRequest, SolanaRequest};

/// Parses `input` and returns the [`Error`] it must produce, panicking if it instead succeeds.
fn err(input: &str) -> Error {
    match PaymentRequest::parse(input) {
        Ok(_) => panic!("expected {input:?} to be rejected"),
        Err(e) => e,
    }
}

#[test]
fn parses_bitcoin_request() {
    let request = PaymentRequest::parse(
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=20.3&label=Luke-Jr",
    )
    .unwrap();
    let PaymentRequest::Bitcoin(request) = request else {
        panic!("expected Bitcoin request");
    };
    assert_eq!(request.network(), Network::Mainnet);
    assert_eq!(request.amount().unwrap().as_str(), "20.3");
    assert_eq!(request.label(), Some("Luke-Jr"));
}

#[test]
fn rejects_unsupported_required_bitcoin_extension() {
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-unknown=true"),
        Error::UnsupportedRequiredParameter(key) if key == "req-unknown"
    ));
}

#[test]
fn rejects_duplicate_bitcoin_amount_parameter() {
    // Bitcoin (BIP-321) parameter keys are case-insensitive, so "AMOUNT" collides with "amount"
    // as a duplicate rather than being treated as a distinct, unrecognised key -- contrast with
    // Litecoin's case-sensitive behavior below.
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=1&AMOUNT=2"),
        Error::DuplicateParameter(key) if key == "amount"
    ));
}

// The following two duplicate-parameter vectors are BIP-321's own "Invalid Payment Request URIs"
// examples (using this file's known-valid address in place of the BIP's own example address,
// which the BIP notes is deliberately checksum-invalid "to prevent accidental transactions").
#[test]
fn rejects_duplicate_bitcoin_label_per_bip321_example() {
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?label=Luke-Jr&label=Matt"),
        Error::DuplicateParameter(key) if key == "label"
    ));
}

#[test]
fn rejects_duplicate_bitcoin_amount_per_bip321_example_even_with_matching_values() {
    // BIP-321 explicitly calls out that a duplicate is invalid even when both occurrences carry
    // the same value -- it is not just a conflict-detection convenience.
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=42&amount=42"),
        Error::DuplicateParameter(key) if key == "amount"
    ));
}

#[test]
fn ignores_unimplemented_optional_bip321_extensions_but_rejects_them_when_required() {
    // BIP-321 defines several alternate-payment-method extensions this crate deliberately does
    // not implement (lightning invoices, BOLT 12 offers, silent payments, segwit fallback
    // addresses, proof-of-payment). As plain optional parameters they must be safely ignorable
    // by a wallet that doesn't support them...
    assert!(
        PaymentRequest::parse(
            "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?lightning=lnbc420bogusinvoice"
        )
        .is_ok()
    );
    // ...but marked `req-`, the same unimplemented extension must make the whole URI invalid,
    // per the `req-` contract both BIP-21 and BIP-321 define.
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-lno=lno1bogusoffer"),
        Error::UnsupportedRequiredParameter(key) if key == "req-lno"
    ));
}

#[test]
fn parses_litecoin_request_with_a_valid_litecoin_address() {
    let request = PaymentRequest::parse(
        "litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?amount=1.25&message=Coffee",
    )
    .unwrap();
    let PaymentRequest::Litecoin(request) = request else {
        panic!("expected Litecoin request");
    };
    assert_eq!(request.network(), Network::Mainnet);
    assert_eq!(request.amount().unwrap().as_str(), "1.25");
    assert_eq!(request.message(), Some("Coffee"));
}

#[test]
fn parses_solana_native_and_spl_transfer_requests() {
    let native = PaymentRequest::parse(
        "solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=1&label=Michael",
    )
    .unwrap();
    let PaymentRequest::Solana(SolanaRequest::Transfer(native)) = native else {
        panic!("expected Solana transfer");
    };
    assert_eq!(native.amount().unwrap().as_str(), "1");
    assert_eq!(native.label(), Some("Michael"));
    assert_eq!(native.spl_token(), None);

    let spl = PaymentRequest::parse(
        "solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=0.01&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();
    let PaymentRequest::Solana(SolanaRequest::Transfer(spl)) = spl else {
        panic!("expected SPL transfer");
    };
    assert_eq!(spl.amount().unwrap().as_str(), "0.01");
    assert_eq!(
        spl.spl_token(),
        Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    );
}

#[test]
fn parses_solana_transaction_link() {
    // Two forms from the Solana Pay spec's own examples: a bare link with no query string
    // needs no escaping, while one with a query string must be percent-encoded so its `?`
    // doesn't collide with the outer `solana:` URI's own grammar.
    let bare = PaymentRequest::parse("solana:https://example.com/solana-pay").unwrap();
    let PaymentRequest::Solana(SolanaRequest::Transaction(bare)) = bare else {
        panic!("expected Solana transaction request");
    };
    assert_eq!(bare.link(), "https://example.com/solana-pay");

    let encoded =
        PaymentRequest::parse("solana:https%3A%2F%2Fexample.com%2Fsolana-pay%3Forder%3D12345")
            .unwrap();
    let PaymentRequest::Solana(SolanaRequest::Transaction(encoded)) = encoded else {
        panic!("expected Solana transaction request");
    };
    assert_eq!(encoded.link(), "https://example.com/solana-pay?order=12345");
}

#[test]
fn rejects_unescaped_solana_transaction_link_with_query_string() {
    assert!(matches!(
        err("solana:https://example.com/solana-pay?order=12345"),
        Error::InvalidTransactionLink(link) if link == "https://example.com/solana-pay?order=12345"
    ));
}

#[test]
fn rejects_solana_request_with_invalid_public_key() {
    // "0OIl" are excluded from the base58 alphabet used by Solana public keys, same as Bitcoin.
    assert!(matches!(
        err("solana:not-a-valid-base58-pubkey0OIl"),
        Error::InvalidAddress(_)
    ));
    // Valid base58, but the wrong length to be a 32-byte Ed25519 public key.
    assert!(matches!(
        err("solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?spl-token=tooshort"),
        Error::InvalidAddress(_)
    ));
}

#[test]
fn delegates_ethereum_to_eip681() {
    let request =
        PaymentRequest::parse("ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18")
            .unwrap();
    let PaymentRequest::Ethereum(request) = request else {
        panic!("expected Ethereum request");
    };
    let native = request.as_native().expect("expected a native ETH transfer");
    assert_eq!(
        native.recipient_address(),
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    );
    assert_eq!(
        native.value_atomic(),
        Some(eip681::U256::from(1_000_000_000_000_000_000u64))
    );
}

#[test]
fn wraps_ethereum_parse_errors() {
    assert!(matches!(err("ethereum:not-an-address"), Error::Ethereum(_)));
}

#[test]
fn rejects_bitcoin_address_with_bad_checksum() {
    // Last character changed from the valid address used elsewhere in this file, breaking the
    // base58check checksum while staying within the base58 alphabet.
    assert!(matches!(
        err("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mX"),
        Error::InvalidAddress(addr) if addr == "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mX"
    ));
}

#[test]
fn rejects_bitcoin_address_with_invalid_characters() {
    // '0', 'O', 'I', 'l' are excluded from the base58 alphabet.
    assert!(matches!(
        err("bitcoin:0IOl0000000000000000000000000000"),
        Error::InvalidAddress(addr) if addr == "0IOl0000000000000000000000000000"
    ));
}

#[test]
fn rejects_address_from_the_wrong_currency() {
    // A real Litecoin address (version byte 48) is not a valid Bitcoin address.
    assert!(matches!(
        err("bitcoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?amount=1"),
        Error::InvalidAddress(addr) if addr == "LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA"
    ));
    // A real Bitcoin bech32 address (hrp "bc") is not a valid Litecoin address.
    assert!(matches!(
        err("litecoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=1"),
        Error::InvalidAddress(addr) if addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    ));
}

#[test]
fn rejects_missing_recipient() {
    assert!(matches!(err("bitcoin:?amount=1"), Error::MissingRecipient));
}

#[test]
fn rejects_input_without_a_scheme() {
    assert!(matches!(err("not-a-uri-at-all"), Error::MissingScheme));
}

#[test]
fn rejects_unsupported_scheme() {
    assert!(matches!(
        err("dogecoin:D5tSf59fmS6WTv60ug7Mo4vD5rMkKtFqTP"),
        Error::UnsupportedScheme(scheme) if scheme == "dogecoin"
    ));
}

#[test]
fn rejects_invalid_percent_encoding() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    // 'z' is not a hex digit, so "%zz" is not a valid percent-encoded byte.
    assert!(matches!(
        err(&format!("{base}?label=%zz")),
        Error::InvalidEncoding(value) if value == "%zz"
    ));
    // A '%' with fewer than two following characters can't be a complete escape sequence.
    assert!(matches!(
        err(&format!("{base}?label=abc%4")),
        Error::InvalidEncoding(value) if value == "abc%4"
    ));
}

#[test]
fn rejects_negative_and_non_numeric_amounts() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    for (query, expected) in [
        ("amount=-1", "-1"),
        ("amount=1e5", "1e5"),
        ("amount=", ""),
        ("amount=abc", "abc"),
    ] {
        assert!(matches!(
            err(&format!("{base}?{query}")),
            Error::InvalidAmount(value) if value == expected
        ));
    }
}

#[test]
fn rejects_amount_with_too_many_fractional_digits() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    // Bitcoin/Litecoin cap fractional precision at 8 digits (satoshis/litoshis).
    assert!(matches!(
        err(&format!("{base}?amount=1.123456789")),
        Error::InvalidAmount(value) if value == "1.123456789"
    ));
    assert!(PaymentRequest::parse(&format!("{base}?amount=1.12345678")).is_ok());
}

#[test]
fn rejects_amount_that_overflows_atomic_value() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    // Too many digits to parse as u64 at all.
    assert!(matches!(
        err(&format!("{base}?amount=999999999999999999999")),
        Error::InvalidAmount(value) if value == "999999999999999999999"
    ));
    // Parses as u64, but overflows once scaled by 10^8 (satoshi precision).
    assert!(matches!(
        err(&format!("{base}?amount=200000000000000000")),
        Error::InvalidAmount(value) if value == "200000000000000000"
    ));
}

#[test]
fn litecoin_parameter_matching_is_case_sensitive_per_bip21() {
    // Unlike Bitcoin (BIP-321, case-insensitive keys), Litecoin follows the original
    // case-sensitive BIP-21. "AMOUNT" is therefore a distinct, unrecognised key: it neither
    // collides with "amount" as a duplicate nor is treated as the amount itself.
    let request =
        PaymentRequest::parse("litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?amount=1&AMOUNT=2")
            .unwrap();
    let PaymentRequest::Litecoin(request) = request else {
        panic!("expected Litecoin request");
    };
    assert_eq!(request.amount().unwrap().as_str(), "1");

    // Case-sensitivity cuts the other way for `req-`, too: an uppercase "REQ-" prefix is not
    // recognised as a required extension, so an unsupported one is silently ignored rather
    // than rejected the way lowercase "req-unknown" is for Bitcoin.
    assert!(
        PaymentRequest::parse("litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?REQ-unknown=true")
            .is_ok()
    );
    assert!(matches!(
        err("litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?req-unknown=true"),
        Error::UnsupportedRequiredParameter(key) if key == "req-unknown"
    ));
}

#[test]
fn rejects_adversarial_input() {
    let always_invalid = [
        "",
        "bitcoin:",
        "bitcoin:%",
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=%",
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-=true",
        "solana:",
        "solana:\u{0}",
        "solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?reference=\\..\\..\\etc\\passwd",
        "ethereum:",
        "ethereum:\u{0}",
        "🦀:not-a-real-scheme",
        "bitcoin://1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo",
        ":",
        "::::",
    ];
    for input in always_invalid {
        assert!(
            PaymentRequest::parse(input).is_err(),
            "expected {input:?} to be rejected"
        );
    }

    // Two large, fixed (non-random) inputs -- rejected deterministically, same as the list
    // above, but kept separate because the point of including them is performance/hang safety
    // (no '&' separators at all in the first, a 100KB single field in the second), not the
    // specific rejection reason.
    assert!(
        PaymentRequest::parse(&"bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=".repeat(10_000))
            .is_err()
    );
    assert!(PaymentRequest::parse(&format!("solana:{}", "a".repeat(100_000))).is_err());

    // These three are *not* rejected, and that's correct, not a gap: emoji are legitimate
    // free-form label text; a NUL byte in a link's hostname doesn't make the link syntactically
    // invalid by this crate's own contract (it parses and categorizes a transaction-request
    // link, it doesn't itself resolve or connect to it -- see solana.rs's module doc); and
    // URI schemes are case-insensitive per RFC 3986, so an uppercase "HTTPS" is exactly as
    // valid as lowercase. Each is still asserted Ok here so a future change to any of this
    // reasoning is a deliberate decision, not a silent regression.
    assert!(
        PaymentRequest::parse(
            "solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?label=\u{1F600}\u{1F600}\u{1F600}"
        )
        .is_ok()
    );
    assert!(PaymentRequest::parse("solana:https://exa\u{0}mple.com").is_ok());
    assert!(PaymentRequest::parse("solana:HTTPS://EXAMPLE.COM/SOLANA-PAY").is_ok());
}

#[cfg(feature = "json")]
#[test]
fn encodes_a_versioned_binding_representation() {
    let encoded = payment_uri::parse_to_json(
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=20.3&label=Luke-Jr",
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value["version"], payment_uri::JSON_VERSION);
    assert_eq!(value["type"], "bitcoin");
    assert_eq!(value["amount"], "20.3");

    let encoded = payment_uri::parse_to_json(
        "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18",
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value["type"], "ethereum_native");
    assert_eq!(
        value["recipient_address"],
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    );
    assert_eq!(value["value_hex"], "0xde0b6b3a7640000");
}
