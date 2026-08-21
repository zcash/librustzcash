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
