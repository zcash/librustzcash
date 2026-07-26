//! Cross-implementation PCZT wire-compatibility with the Keystone 3 firmware.
//!
//! This test is a reviewer's aid for PR #2769 (issue #2768): it confirms that
//! the minimal-encoding `Pczt::serialize()` restored by this PR produces bytes
//! that the deployed firmware (which uses the `pczt` 0.2.1 crate) already
//! parses and produces.
//!
//! The vector below is the canonical Orchard->transparent PCZT embedded in the
//! keystone3-firmware source, produced by the firmware's `pczt` 0.2.1. It is a
//! **v1** encoding (`PCZT` magic + little-endian version `1`). Keeping the
//! exact bytes here and in the firmware test makes this a shared encoding
//! vector: if either side's v1 layout drifts, one of the two round-trip
//! assertions fails.
//!
//! Source of the vector (KeystoneHQ/keystone3-firmware, pinned commit):
//! <https://github.com/KeystoneHQ/keystone3-firmware/blob/8420703ad8674745ca8f086590371661747b7dca/rust/apps/zcash/src/pczt/sign.rs#L214>
//!
//! The crucial claim is on the DEFAULT `serialize()` path a wallet SDK calls.
//! Before this PR that default emitted v2 (2748 bytes) and diverged from the
//! firmware; with this PR it emits minimal-encoding v1 (2731 bytes) that is
//! byte-identical to the firmware vector.

fn encoding_version(bytes: &[u8]) -> u32 {
    assert_eq!(&bytes[..4], b"PCZT", "not a PCZT (bad magic)");
    u32::from_le_bytes(bytes[4..8].try_into().unwrap())
}

/// Byte-for-byte the same constant used by the firmware unit test
/// (`PCZT_V1_ORCHARD_TO_TRANSPARENT`). Do not regenerate casually: a change
/// here is a wire-format change that must be mirrored in the firmware.
const FIRMWARE_V1_VECTOR: &str = "50435a5401000000058ace9cb502d5a09cc70c0100f083ae0185010000000180ade2041976a91467f7aa14f177a7e0058c66c7242e086488bd3d1088ac000001237431544d4c4a376b324e344e6172716b3546643575556f38324e58534d624b5267436300000000fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e010000000000000000000000000000000000000000000000000000000000000000024d2eeb083d7c168f64239c3186d53c72e2b1a3a5140f5250f0963689c08cd61c0999baea13f0be05dc6a2554bb2f8f093f4d20911202567a5ab9fd17bce5142b3f79838a71d14757fcff03ba16486a3efb26c9773ec9596821d1e5f32039fe220001d5d3506f152f62c45198446223abf29e06da700990a779fb60a460712fb666a0ff1fab61e2b2b3566b263d0180b6dc05014b2225d5521d6dbb55ae03d22567ce98b242ba5520bc4e2493ec36fb9211c6350194215c2aa089dfa317c61bab4b9747f4e45abca855e45e00710a3dc5caa40a570186f6f9e818f6674c2df92918a55d20f340944de5c67c1c4a9ee347c2c2d6d71d4753d765f2859a3157f7b05cc3bc7089e3f2c9d5abb3fcb1708e74c790985d3dd90cfe2ed03276dfda527c6e8c08d9a1fdeedcb6aef59d9e5bf0ae5d9477ed030001872727f23f40a96896b66d04de905791bae2bc7ee9dc1f4e4ec5ae493dc2fc1001afb475105f1f5b477c52aa3c32ccf131b0c556b80f55ac555460e6b5148bf85303a0808080088581808008808080800800002585b32c42aa5a12b2763953f09aafed13450eda0c416e32d0978260c4171c375413b91e25fa826399623b6716ae8bbb0b4a1099de22478944627af7e5969aa0c404ffab4d35664c1dafd2d2c0cecf4fb3c8b054179f84b2d35d207077b3d256b429acdee34963c573b55ae20fffce73e0e3e575c8fde9d115e7ffab50b3bee60d2436b72c17677e1d7db141fafa72c7f89002908a7a8de3320e5ad3d1ed0bb545235e136904c5c5e4adfa5a100420ceb2196e5e197e919aeaeefa7cb2a1d98e011539af52d618bfb3ba1dfc2d2c01e9bd67523bb6787eb5a0d28e30ad483c6303efd4796795082cc67ea94ba8548a33da1a5ec7c56174bd6b260f548e83a924b7cdd32980ca489b44e981aa1d81cefe2581eebf3a585fb80542aea4a27862f593203b560a412ba4e737c8f678f239f3d1d07c5a82367435f0a0921c46600eb4f6f7387b3cb5984af98b1337f5148ad6388b62dab7cdc48c66ff81685894c2d1d0fe41716b7cb457fb5bd6ff13e321d2f91c15d431f942d7869955dfeadfff61638266ba38d7ba4db7ffe5ee03550d345715cebd9b378181b5769c22e1b20328165da02eeb5d246c70c008ac0c7f7b1bba2cf8270f013eb99cbc5d534270180f34892fdf08d8c16c518d8b7f62d832d676c65fcae34c640ff30d5bd9d65afeab509117a98374b4b9b016228a65bdd803d6c601d2ad6a654c2fe4487d9c7b088d886c36a6afe63d33f8c474f096500acabbb63968e7408c620cc8139331cf7227e9bdbf4b7bae292e15d310e66186b730f28d0515ac5bb71fcc5de09995fe89d005cc2c7afd0fb8f01b315815d38366ebeb6de9ed565b5d1f2ce14b7795b9ad784851f357beacc454be41aaec506f0148461ba5907043ab8618114bbbede979d7f0e0e0af914750df648079e3625e4f309d13ff74d4ada783203bb3652137abd8327cdd06b9332591c9abdcc0cc16f7fec2e0afd849bef8927b3b0ceeca2b90af7611875b78cf525852ee83e10c8f4cb2c80045cbf33c0801a55eeb15c9dca6e53b3dde8a12daf820f1f76624ee48e3128aaa0ef6f6fb32a0303d89e88be288be1b92a301e893790179ec07711e275f48de2f5f8e0ee7b000091c9d96159746d46f353e67463d7052000000000118c5796d39cd2bc56b0a062c20ebd32feb0b57cc231c262d6703520f8de603211edcf51f6084e3288cbdb02957a02cd68fb84973a6a98260fb60f30951dedb2e1240275687c0bd82a2653a2c212bd3c0ea75cd294f5a4d31dcf507c15461402760282899f6b560858c0b6bd95c708f62d1e856480a52401d0d7d6a642fa1c2a10176072c6147735b785ea4ad9276378885704a44c6246f4630ef1df59438562e055bba6c1411a790727ab27421e6c418df8b65cb636d6786ce9e5b632659f5d32401caffe6271e2d77d8634e67a116926d7566b5eb2f2aadba6498d7a1e120f27f52379bb3f8781090ae47e30b0100011a78b2abbab21b29d79141fdff8a389c2eacde5be75c69ae4c4fabc175aec10a0142b202630def2df1f7cd23fcf362c68194829282c57b0c4d5f0ca023b51a571f01bd466676b53cfc27ba4a94bb4ab3ed19d8db336042e09e1e756b560b5ce7fc05d5dc3269236828f541662db5bfd4ab6e07c4dac2682906ee85eca2d12b6522013dd286fc499141cfebfb53175ea4321e08e8a504604bbc2e9d3e59706a1fa439000130febcd5d0c57c6e3780d6fe1f6c07f01a9d5d7a053ac5562f29304418d33a20000000f7fa16a612e422c34d61c44ae692b255c921239547172fcd26519928a3abb10d22548d840b466f1fed5ccb4c442d97b4b59d1a728455ee1598bae8e316f819bac404c9112693c57e0733d550ddc984d82ecc9047721e7e7bc6f283ba00852e49a4d3cda4dad343a366650b1d75b26025eadc5200113ebcc2a4a7db9ac2291083d76e7a8c04831764caf35e4c18bfc58e58699b4a651ca3686a95a6db7133611b5ce80a14225cdac643311869ea0c4a6d760379f285fa9c396c435361044da7e077f236d589a3eb962129988ea6ccde694cb72fa986748fc106981320f478a1c5402fe75a26dee31ec9fad4240aa19932fa8361c43798aa381c63b0c0b17657ccf37792a28456cfe6562e15d9e4aa26ed2660b6c8fc8a92cd352a6025dabcbed5eba82d88b9df3ba73270ff2f9c44fca8b0c1df8ed4cbfa2a4ebe7d0bcc6e5ce73e43b51e054860d7939ca13d77813b372070fd24cdd9c0e2fad7567471c0279bba19a76f0cdbd3107220821dd676c1df6524c15b87c1318eda418d65f8c66d2a77a65f6894199d44611e60c0291c330d1692bd521aef0e316e2b3f8c377b0d6873b3b645196ba74a79c6e0509869ac66276c3e2dfefd54a12365b5945406e7b673321ed36e89a14a194ae8b864e9ac4684655bae7fcd3123a226f282ac6ac82ca88d6a383d8be90f87f4cb85225f697932abfb4c05cda3b6dadb003621fee663f3fcb8f1c96320a3f148bc106ec231961a8f5142dd614317eef16b81492668a8b8795b85d7b0f737fa8d79e9dc3d78840d158a73dc6d1700ce3a8de2a9f93ff1bc8108703b94fd5bd230a19dd0fd821b832d3508b335e07bac28e95c3ab0eb637334bf166fa2a440ea35c0372bb5a745ee86c727a80f0d0d080fef6642ae7aae1407d6a25c3050c498a52ae300105bded1f19829b10df00e7ba301a9aef2c99ad7c5338b0e259ab97ea852630606b8d59709ca067d32698c8761e0f7d5b76ac07d4860b0fe2992010ba88827bb37cf4e3436488580e79101b366d454f29aa2bdf76725130baa08b38af3a71c251521809c84fe3d086943f39f01d760884b6342fac60c010001c54930d4f4f9946dfe91ac3e94cf5b513871c4a5c0c21137959482da796d2d280000000001c4666732084baff2e402ed7d3e457303c73b77dbd4aa5bc943ac7ca96f3779070398a2e304004aed48232c44dbd0b0b5404063ecc4679436f28c6251cbba91e29388fcd98d0e0001dc2be19f4118dbb7500df3a95e304733b247cea7f8c681f6aaafceb8fc1d7d28";

/// The firmware's v1 vector parses under this PR.
#[test]
fn parses_firmware_v1_vector() {
    let bytes = hex::decode(FIRMWARE_V1_VECTOR).expect("valid hex");
    assert_eq!(
        encoding_version(&bytes),
        1,
        "vector must be the v1 encoding"
    );
    pczt::Pczt::parse(&bytes).expect("PR must parse the firmware v1 vector");
}

/// The core claim of PR #2769: the DEFAULT `serialize()` (the path a wallet SDK
/// calls) emits minimal-encoding v1 that is byte-identical to the firmware
/// vector. Pre-fix this default emitted v2 and diverged, breaking deployed
/// signers.
#[test]
fn default_serialize_matches_firmware_bytes() {
    let bytes = hex::decode(FIRMWARE_V1_VECTOR).expect("valid hex");
    let pczt = pczt::Pczt::parse(&bytes).expect("parse");

    let serialized = pczt.serialize().expect("serialize");

    assert_eq!(
        encoding_version(&serialized),
        1,
        "the fix must select the v1 minimal encoding for this content",
    );
    assert_eq!(
        serialized, bytes,
        "default serialize() must be byte-identical to the firmware v1 vector",
    );
}

/// The explicit `v1::Pczt` path also reproduces the firmware bytes exactly,
/// and the v2 path (the pre-fix default) does not, documenting the divergence
/// the fix removes.
#[test]
fn v1_matches_and_v2_differs() {
    let bytes = hex::decode(FIRMWARE_V1_VECTOR).expect("valid hex");
    let pczt = pczt::Pczt::parse(&bytes).expect("parse");

    let v1 = pczt::v1::Pczt::try_from(pczt.clone())
        .expect("firmware PCZT is v1-representable")
        .serialize();
    assert_eq!(encoding_version(&v1), 1);
    assert_eq!(
        v1, bytes,
        "explicit v1 encoding matches the firmware vector"
    );

    let v2 = pczt::v2::Pczt::try_from(pczt)
        .expect("v2 encode")
        .serialize();
    assert_eq!(encoding_version(&v2), 2);
    assert_ne!(
        v2, bytes,
        "the v2 encoding differs from the firmware v1 bytes (the pre-fix default)",
    );
}

/// The bytes the PR emits re-parse and re-serialize stably (idempotent),
/// so a device that echoes the PCZT back does not perturb the encoding.
#[test]
fn default_serialize_is_idempotent() {
    let bytes = hex::decode(FIRMWARE_V1_VECTOR).expect("valid hex");
    let once = pczt::Pczt::parse(&bytes)
        .expect("parse")
        .serialize()
        .expect("serialize");
    let twice = pczt::Pczt::parse(&once)
        .expect("re-parse")
        .serialize()
        .expect("re-serialize");
    assert_eq!(
        once, twice,
        "serialize() must be idempotent across a parse round-trip"
    );
}
