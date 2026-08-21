use payment_uri::{Network, PaymentRequest, SolanaRequest};

#[test]
fn parses_bitcoin_request_and_rejects_unsafe_extensions() {
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

    assert!(
        PaymentRequest::parse("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-unknown=true")
            .is_err()
    );
    assert!(
        PaymentRequest::parse("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=1&AMOUNT=2")
            .is_err()
    );
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
fn categorizes_solana_transaction_requests_without_treating_them_as_transfers() {
    let request =
        PaymentRequest::parse("solana:https%3A%2F%2Fexample.com%2Fsolana-pay%3Forder%3D12345")
            .unwrap();
    let PaymentRequest::Solana(SolanaRequest::Transaction(request)) = request else {
        panic!("expected Solana transaction request");
    };
    assert_eq!(request.link(), "https://example.com/solana-pay?order=12345");
    assert!(PaymentRequest::parse("solana:https://example.com/solana-pay?order=12345").is_err());
}

#[test]
fn delegates_ethereum_to_eip681() {
    let request =
        PaymentRequest::parse("ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18")
            .unwrap();
    assert!(matches!(request, PaymentRequest::Ethereum(_)));
}

#[test]
fn rejects_bitcoin_address_with_bad_checksum() {
    // Last character changed from the valid address used elsewhere in this file, breaking the
    // base58check checksum while staying within the base58 alphabet.
    assert!(PaymentRequest::parse("bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mX").is_err());
}

#[test]
fn rejects_bitcoin_address_with_invalid_characters() {
    // '0', 'O', 'I', 'l' are excluded from the base58 alphabet.
    assert!(PaymentRequest::parse("bitcoin:0IOl0000000000000000000000000000").is_err());
}

#[test]
fn rejects_address_from_the_wrong_currency() {
    // A real Litecoin address (version byte 48) is not a valid Bitcoin address.
    assert!(PaymentRequest::parse("bitcoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?amount=1").is_err());
    // A real Bitcoin bech32 address (hrp "bc") is not a valid Litecoin address.
    assert!(
        PaymentRequest::parse("litecoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=1")
            .is_err()
    );
}

#[test]
fn rejects_missing_recipient() {
    assert!(PaymentRequest::parse("bitcoin:?amount=1").is_err());
}

#[test]
fn rejects_negative_and_non_numeric_amounts() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    assert!(PaymentRequest::parse(&format!("{base}?amount=-1")).is_err());
    assert!(PaymentRequest::parse(&format!("{base}?amount=1e5")).is_err());
    assert!(PaymentRequest::parse(&format!("{base}?amount=")).is_err());
    assert!(PaymentRequest::parse(&format!("{base}?amount=abc")).is_err());
}

#[test]
fn rejects_amount_with_too_many_fractional_digits() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    // Bitcoin/Litecoin cap fractional precision at 8 digits (satoshis/litoshis).
    assert!(PaymentRequest::parse(&format!("{base}?amount=1.123456789")).is_err());
    assert!(PaymentRequest::parse(&format!("{base}?amount=1.12345678")).is_ok());
}

#[test]
fn rejects_amount_that_overflows_atomic_value() {
    let base = "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo";
    // Too many digits to parse as u64 at all.
    assert!(PaymentRequest::parse(&format!("{base}?amount=999999999999999999999")).is_err());
    // Parses as u64, but overflows once scaled by 10^8 (satoshi precision).
    assert!(PaymentRequest::parse(&format!("{base}?amount=200000000000000000")).is_err());
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
    assert!(
        PaymentRequest::parse("litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?req-unknown=true")
            .is_err()
    );
}

#[test]
fn does_not_panic_on_adversarial_input() {
    let adversarial = [
        "",
        "bitcoin:",
        "bitcoin:%",
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=%",
        "bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-=true",
        "solana:",
        "solana:\u{0}",
        "ethereum:",
        &"bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=".repeat(10_000),
        "🦀:not-a-real-scheme",
    ];
    for input in adversarial {
        // The only contract under test is "does not panic"; every one of these is expected to
        // be rejected, but that's incidental -- a future relaxation that lets one parse
        // successfully would still be fine as long as it doesn't do so by panicking.
        let _ = PaymentRequest::parse(input);
    }
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
