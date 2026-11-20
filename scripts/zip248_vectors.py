#!/usr/bin/env python3
"""Recompute fixed ZIP 248 digest fixtures using only the Python standard library.

Usage and coverage: scripts/zip248_vectors.md.
No Rust implementation, build product, network access, or random source is used.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

# ZIP 248 draft revision defining the digest encodings implemented below.
SPEC = (
    "https://raw.githubusercontent.com/zcash/zips/"
    "825c98effcd7b11eefa4c70aa2fca8d67a15c85f/zips/zip-0248.rst"
)
# Provisional identifiers and header fields used by the Rust fixtures.
VERSION = 0x80000007
VERSION_GROUP_ID = 0x6E755F38
BRANCH_ID = 0xFFFFFFFB
LOCK_TIME = 0
EXPIRY_HEIGHT = 100
# Fixed byte widths from the bundle definitions.
HASH_SIZE = 32
SIGNATURE_SIZE = 64
SAPLING_PROOF_SIZE = 192
ORCHARD_PROOF_BASE_SIZE = 2720
ORCHARD_PROOF_PER_ACTION_SIZE = 2272
POLL_DIGEST_SIZE = 16
# Orchard flags: enable spends and outputs, without cross-address transfers.
ORCHARD_FLAGS = 0b00000011
# Every signature here uses compactSize(1) || sighashVariant(0).
SIGHASH_INFO = b"\x01\x00"
# The coinbase fixtures' block subsidy less their lockbox deposit.
COINBASE_DELTA = 281_250_000
# Raw S.2 input captured from sighash_tx() using proptest seed 0x5A17 and the
# locked dependencies at 513278d39880c3bf4dc74bc04e6c4b3d2732f6ca.
# Production-derived fixture input, not an independent txid expectation.
MIXED_SIGNATURE_TXID = bytes.fromhex(
    "00ecad3af855c839f20e0d9a383d78239b4449fd5e00c0d6dcfbc6a990293d03"
)


def le(value, width, signed=False):
    return value.to_bytes(width, "little", signed=signed)


def compact_size(value):
    """Canonical compactSize, including the full unsigned 64-bit range."""
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("compactSize outside uint64")
    if value < 0xFD:
        return bytes([value])
    for marker, width in ((0xFD, 2), (0xFE, 4), (0xFF, 8)):
        if value < 1 << (8 * width):
            return bytes([marker]) + le(value, width)
    raise ValueError("unreachable compactSize range")


def vector(data):
    return compact_size(len(data)) + data


def repeat(byte, count=HASH_SIZE):
    return bytes([byte]) * count


def h(personal, data=b""):
    # BLAKE2b personalizations shorter than 16 bytes are zero-padded by hashlib.
    # Several test-only supplied-digest domains are 15 bytes long.
    if len(personal) > 16:
        raise ValueError("BLAKE2b personalization exceeds 16 bytes")
    return hashlib.blake2b(data, digest_size=HASH_SIZE, person=personal).digest()


def tagged(entries):
    """T.3 / A.1 entries omit map counts and payload lengths."""
    return b"".join(
        compact_size(kind) + compact_size(variant) + digest
        for kind, variant, digest in entries
    )


def header(expiry_height=EXPIRY_HEIGHT):
    """T.1: all five fixed-width common transaction fields."""
    return b"".join(
        le(value, 4)
        for value in (VERSION, VERSION_GROUP_ID, BRANCH_ID, LOCK_TIME, expiry_height)
    )


def transaction(deltas=(), effects=(), auth=(), expiry_height=EXPIRY_HEIGHT):
    """T.1–T.3, txid, A.1, and the authorizing-data commitment."""
    vp = b"".join(
        compact_size(kind) + compact_size(variant) + le(value, 8, signed=True)
        for kind, variant, value in deltas
    )
    nodes = {
        "header": h(b"ZTxIdHeadersHash", header(expiry_height)),
        "value-pool-deltas": h(b"ZTxIdVPDeltaHash", vp),
        "effects-bundles": h(b"ZTxIdEffBnd_Hash", tagged(effects)),
        "auth-bundles": h(b"ZTxAuthBnd__Hash", tagged(auth)),
    }
    nodes["txid"] = h(
        b"ZcashTxHash_" + le(BRANCH_ID, 4),
        nodes["header"] + nodes["value-pool-deltas"] + nodes["effects-bundles"],
    )
    nodes["auth"] = h(
        b"ZTxAuthHash_" + le(BRANCH_ID, 4), nodes["auth-bundles"]
    )
    return nodes


def outpoint(byte, index):
    return repeat(byte) + le(index, 4)


def transparent_effects(inputs, outputs):
    """T.3.0: inputs are (outpoint, sequence); outputs are (value, script)."""
    return h(
        b"ZTxIdTranspaHash",
        h(b"ZTxIdPrevoutHash", b"".join(prevout for prevout, _ in inputs))
        + h(b"ZTxIdSequencHash", b"".join(le(seq, 4) for _, seq in inputs))
        + h(
            b"ZTxIdOutputsHash",
            b"".join(le(value, 8, signed=True) + vector(script)
                     for value, script in outputs),
        ),
    )


def transparent_auth(scripts):
    """A.1.0: per-input sighashInfo followed by length-prefixed scriptSig."""
    return h(
        b"ZTxAuthTransHash",
        b"".join(SIGHASH_INFO + vector(script) for script in scripts),
    )


def sapling_spends(spends):
    """T.3.2a: each fixture spend gives (cv, nullifier, rk) fill bytes."""
    children = b""
    if spends:
        children = (
            h(b"ZTxIdSSpendCHash", b"".join(repeat(nf) for _, nf, _ in spends))
            + h(b"ZTxIdSSpendNH_v6",
                b"".join(repeat(cv) + repeat(rk) for cv, _, rk in spends))
        )
    return h(b"ZTxIdSSpendsHash", children)


def sapling_effects(spends, outputs):
    """T.3.2: outputs give (cv, cmu, ephemeral key, enc, out) fill bytes."""
    children = b""
    if outputs:
        children = (
            h(b"ZTxIdSOutC__Hash",
                b"".join(repeat(cmu) + repeat(epk) + repeat(enc, 52)
                         for _, cmu, epk, enc, _ in outputs))
            + h(b"ZTxIdSOutM__Hash",
                b"".join(repeat(enc, 512) for _, _, _, enc, _ in outputs))
            + h(b"ZTxIdSOutN__Hash",
                b"".join(repeat(cv) + repeat(enc, 16) + repeat(out, 80)
                         for cv, _, _, enc, out in outputs))
        )
    return h(
        b"ZTxIdSaplingH_v7",
        sapling_spends(spends) + h(b"ZTxIdSOutputHash", children),
    )


def signature(byte):
    return SIGHASH_INFO + repeat(byte, SIGNATURE_SIZE)


def sapling_auth(spend_proofs, spend_sigs, output_proofs):
    """A.1.2: anchor iff spends, then proofs/signatures in their field order."""
    return h(
        b"ZTxAuthSapliH_v7",
        (repeat(0x33) if spend_proofs else b"")
        + b"".join(repeat(byte, SAPLING_PROOF_SIZE) for byte in spend_proofs)
        + b"".join(signature(byte) for byte in spend_sigs)
        + b"".join(repeat(byte, SAPLING_PROOF_SIZE) for byte in output_proofs)
        + signature(0xDD),
    )


def orchard_effects(count, flags=ORCHARD_FLAGS, ironwood=False):
    """T.3.3 / T.3.4 over repeated action() bytes from bytes/tests.rs."""
    domains = (
        (b"ZTxIdIronwd_Hash", b"ZTxIdIrnActCH_v6",
         b"ZTxIdIrnActMH_v6", b"ZTxIdIrnActNH_v6")
        if ironwood else
        (b"ZTxIdOrchardH_v7", b"ZTxIdOrcActCHash",
         b"ZTxIdOrcActMHash", b"ZTxIdOrcActNHash")
    )
    compact = repeat(0x22) + repeat(0x55) + repeat(0x66) + repeat(0x88, 52)
    memos = repeat(0x88, 512)
    noncompact = repeat(0x11) + repeat(0x44) + repeat(0x88, 16) + repeat(0x99, 80)
    return h(
        domains[0],
        h(domains[1], compact * count)
        + h(domains[2], memos * count)
        + h(domains[3], noncompact * count)
        + bytes([flags]),
    )


def orchard_auth(spend_sigs, proof_byte=0xAA, ironwood=False):
    """A.1.3 / A.1.4: aggregated proof has no compactSize prefix in the hash."""
    proof_size = (
        ORCHARD_PROOF_BASE_SIZE + ORCHARD_PROOF_PER_ACTION_SIZE * len(spend_sigs)
    )
    return h(
        b"ZTxAuthIrnwdHash" if ironwood else b"ZTxAuthOrchaH_v7",
        repeat(0x33)
        + repeat(proof_byte, proof_size)
        + b"".join(signature(byte) for byte in spend_sigs)
        + signature(0xCC),
    )


def coinbase(signals=()):
    """T.3.1, with the exact multi_signal_coinbase fixture inputs."""
    preimage = (
        le(123_456, 4) + le(312_500_000, 8) + le(31_250_000, 8)
        + vector(b"miner") + compact_size(len(signals))
        + b"".join(bytes(signal) for signal in signals)
    )
    if signals:
        preimage += repeat(0x7E, POLL_DIGEST_SIZE)
    return h(b"ZTxIdCoinbasHash", preimage)


def signature_vectors(txid, values, scripts, contexts):
    """S.1–S.7; txid is a raw digest, not display-byte-reversed hex."""
    amounts = h(b"ZTxTrAmountsHash", b"".join(le(v, 8, signed=True) for v in values))
    scriptkeys = h(b"ZTxTrScriptsHash", b"".join(vector(s) for s in scripts))
    nodes = {"txid-input": txid, "amounts": amounts, "scriptpubkeys": scriptkeys}
    for name, kind, context in contexts:
        preimage = b"\x00" + txid + amounts + scriptkeys
        preimage += compact_size(kind) + compact_size(0) + context
        nodes[name] = h(b"ZcashSigHash_v7_", preimage)
    return nodes


def signature_contexts():
    """Exact S.3, S.4, and S.7 inputs from v7_signature_digest_vectors."""
    values = [1000, 2000]
    scripts = [bytes.fromhex("515253"), bytes.fromhex("76a914") + repeat(0xAB, 22)]
    inputs = [(outpoint(0x11, 3), 0x01020304), (outpoint(0x22, 0), 0xFFFFFFFF)]
    contexts = []
    for index, ((prevout, seq), value, script) in enumerate(zip(inputs, values, scripts)):
        context = prevout + le(value, 8, signed=True) + vector(script)
        context += le(seq, 4) + le(index, 2)
        contexts.append((f"transparent-{index}", 0, context))
    for kind, pool, operation in (
        (2, "sapling", "spend"), (3, "orchard", "action"), (4, "ironwood", "action")
    ):
        for index in range(2):
            contexts.append((f"{pool}-{operation}-{index}", kind, le(index, 2)))
        contexts.append((f"{pool}-binding", kind, b""))
    return values, scripts, inputs, contexts


def generate():
    fixtures = {"empty": transaction(), "fee": transaction([(5, 0, -10_000)])}

    def bundle(name, kind, delta, effects, auth=None):
        nodes = transaction(
            [(kind, 0, delta)],
            [(kind, 0, effects)],
            [] if auth is None else [(kind, 0, auth)],
        )
        nodes["effects-leaf"] = effects
        if auth is not None:
            nodes["auth-leaf"] = auth
        fixtures[name] = nodes

    transparent = transparent_effects([(outpoint(1, 2), 3)], [(1000, b"\x51\x52")])
    bundle("transparent", 0, -1000, transparent, transparent_auth([b"\x51"]))
    # The one-spend/one-output fixture puts 0x55 in cv and 0x66 in cmu;
    # the multi-element and directional fixtures use 0x66 in cv, 0x55 in cmu.
    spend = (0x11, 0x22, 0x44)
    output = (0x55, 0x66, 0x77, 0x88, 0x99)
    bundle("sapling", 2, -1, sapling_effects([spend], [output]),
           sapling_auth([0xAA], [0xBB], [0xCC]))
    fixtures["sapling"]["spends"] = sapling_spends([spend])
    for name, kind, ironwood in (("orchard", 3, False), ("ironwood", 4, True)):
        bundle(name, kind, -1, orchard_effects(1, ironwood=ironwood),
               orchard_auth([0xBB], ironwood=ironwood))
    bundle("coinbase", 1, COINBASE_DELTA, coinbase())
    bundle("coinbase-signals", 1, COINBASE_DELTA, coinbase([(2, 0x20), (9, 0x90)]))

    for name, kind, variant, delta, domain in (
        ("unknown-indexer", 99, 0, 500, b"test_unknown_efx"),
        ("unknown-keys", 99, 7, 5, b"test_supplied__"),
    ):
        fixtures[name] = transaction(
            [(kind, variant, delta)],
            [(kind, variant, h(domain, b"\x11"))],
            [(kind, variant, h(domain, b"\x22"))],
        )
    # Supplied digests are inputs to the envelope algorithm, not opaque-payload hashes
    # defined by ZIP 248. These domains reproduce the Rust tests' mock resolver.
    fixtures["multibyte-keys"] = transaction(
        [(300, 260, 5)],
        [(300, 260, h(b"test_effects_dgt", repeat(0xAA, 253)))],
        [(300, 260, h(b"test_auth_digest", repeat(0xBB, 253)))],
    )
    directional_output = (0x66, 0x55, 0x77, 0x88, 0x99)
    bundle("sapling-spend-only", 2, -1, sapling_effects([spend], []),
           sapling_auth([0xAA], [0xBB], []))
    bundle("sapling-output-only", 2, -1, sapling_effects([], [directional_output]),
           sapling_auth([], [], [0xCC]))
    bundle("transparent-input-only", 0, -1000,
           transparent_effects([(outpoint(1, 2), 3)], []), transparent_auth([b"\x61"]))
    bundle("transparent-output-only", 0, 1000,
           transparent_effects([], [(1000, b"\x51")]))
    fixtures["multi-bundle"] = transaction(
        [(0, 0, -1000), (2, 0, -1), (3, 0, 1), (5, 0, -1)],
        [
            (0, 0, transparent_effects(
                [(outpoint(1, 2), 3), (outpoint(3, 4), 5)],
                [(1000, b"\x51"), (2000, b"\x52\x53")])),
            (2, 0, sapling_effects(
                [spend, (0x12, 0x23, 0x45)],
                [directional_output, (0x66, 0x56, 0x77, 0x88, 0x99)])),
            (3, 0, orchard_effects(2)),
        ],
        [
            (0, 0, transparent_auth([b"\x61\x62", b"\x63"])),
            (2, 0, sapling_auth([0xAA, 0xAB], [0xBB, 0xBC], [0xCC, 0xCD])),
            (3, 0, orchard_auth([0xBB, 0xBC], proof_byte=0)),
        ],
    )
    no_input_txid = transaction([(5, 0, -500)])["txid"]
    fixtures["signature-no-inputs"] = signature_vectors(
        no_input_txid, [], [],
        [("sapling-binding", 2, b""), ("ironwood-binding", 4, b"")],
    )
    # Encoding-only S.1–S.7 vectors: use a fully specified transparent-only
    # envelope instead of the Rust mixed fixture's proptest-generated S.2.
    # The shielded contexts below do not assert bundle existence or validity.
    values, scripts, inputs, contexts = signature_contexts()
    reference_txid = transaction(
        [(0, 0, -3000), (5, 0, -500)],
        [(0, 0, transparent_effects(inputs, [(2500, b"")]))],
    )["txid"]
    fixtures["signature-encoding"] = signature_vectors(
        reference_txid, values, scripts, contexts
    )
    fixtures["signature-mixed"] = signature_vectors(
        MIXED_SIGNATURE_TXID, values, scripts, contexts
    )
    # Null-prevout regression fixture: no deltas, outputs, shielded bundles,
    # or lock/expiry heights. Sapling binding has an empty S.7 context.
    null_prevout_effects = transparent_effects(
        [(outpoint(0, 0xFFFFFFFF), 0xFFFFFFFF)], []
    )
    null_prevout_txid = transaction(
        effects=[(0, 0, null_prevout_effects)], expiry_height=0
    )["txid"]
    fixtures["signature-null-prevout"] = signature_vectors(
        null_prevout_txid, [7000], [b""], [("sapling-binding", 2, b"")]
    )
    return fixtures


# Literal expectations in transaction/tests.rs and transaction/bytes/tests.rs.
# The directional and multi-element Rust tests assemble preimages instead of
# spelling out hex literals; --json also prints their reproducible outputs.
EXPECTED = {
    "empty.txid": "600c2dd76c15b3683691259781ce79a3757cc7f95714cfbccdb49f69ddf15958",
    "empty.auth": "d3a128d379cd32a6ec49acb8e5da337ed38e80c068fa0e33e4baf2786867241a",
    "fee.txid": "0778b29c2439d15380c97f32c02c0430fdfcbc94ecde260f4503a7fee547191e",
    "transparent.effects-leaf": "d5e1d1105b9afedeb5315f87b47d62c64083697993e3407e9cb8b0521cde5fd0",
    "transparent.auth-leaf": "39c5b754b5ea79a3c9f982923b10240a128f7bd04e5c2a76c1dc4a857ea6b417",
    "transparent.txid": "618a5eff3fc2a1fd94216c7ce75a3b17019cdb8ff8e2474835e4930e765f6e32",
    "transparent.auth": "77868f75aa62e6f7e0e9e736000bc9ab8483bd202ff4e6728bd4a99cc6ea0041",
    "sapling.effects-leaf": "16a3caaed6dfd7632ded63cb25e46c1d03ee5ac04839e47c402097dbde20e063",
    "sapling.auth-leaf": "5a94a38f38984169af8bf7379e580376b76ad791917dc46fcc92c893d738aca6",
    "sapling.spends": "c1402185efee34caedd8e93cb2194686cd7b1e4373499257c7b8a74f85e5f381",
    "sapling.txid": "79ceb169c87bdcf27e397e12dbddb4c42c346f5782b512e01666651ff64480f5",
    "orchard.effects-leaf": "8e23f072161182cd7092de2a0946cc6a0f00fc6ba0b8e3aa8cb5cb69768bf082",
    "ironwood.effects-leaf": "03dd472b7bcb192019f7d53b7cea9441b41fb3addb703017671b41db790977b8",
    "orchard.auth-leaf": "8b1dd1f5eb913f7d065bea12e2e6fb55a0974286e0599b1cf1dccceaeb42cf66",
    "ironwood.auth-leaf": "83bd702b9532a4831b9d07b33efa6d7df6f9a0e34f188a89035d00a8c24f5a90",
    "orchard.txid": "c2daa1b9128ec906e6630684658a7ab0547637f178c82fcc0d3e5e12f8ef8d6a",
    "orchard.auth": "c2175c1e2aeba736e72f4a825a9208e04083959a1086fe5183e6cbf566024209",
    "ironwood.txid": "00f1da46807b218826bc344c5a9da4e304b88b951e9c3d43d6bf81c16ce8b633",
    "ironwood.auth": "57079939a115f14c962e5db9173f1a70b8655835343353d46ea0004b7a77e924",
    "coinbase.effects-leaf": "46ceb73aec96091718b895e0d8827e0e572e8cf167bde5c729393559ff4ee266",
    "coinbase.txid": "94dea93bc55b986319501d8f1ffa1a1afba28225860a44a236bc82c23461cf2e",
    "coinbase-signals.effects-leaf": "0c44da6933fba7caf184dbc6f6f17aa19cf50bd1d466f07d5cfa088247c432fe",
    "coinbase-signals.txid": "06132e9f4307940a230e2eded484c4b7a6d53276b41cedbe23a72c07a1e3dc93",
    "unknown-indexer.txid": "f17b15b75a33457fe06a44d5f766e5c2d1c61e78cc63cd256c9bbc0cbdbdb17c",
    "unknown-indexer.auth": "63ffe5f3ffdecda1785d62fbcb0095b59c250c2916747f7bea373e0e9c4ea24e",
    "unknown-keys.txid": "9e0ce041a90710b351466c93ed469f4937a72411c9421c4a96216a9dbaa2629a",
    "unknown-keys.auth": "3c5a403d2d8f734925f9a56a7a63049bfdc7b0d7673a1241556f268cb90be8e1",
}

# Python-generated outputs for the Rust preimage-only fixtures and for the
# encoding-only signature inputs. These are not additional Rust hex literals.
PREIMAGE_EXPECTED = {
    "multibyte-keys.txid": "c44d4c6f1a1ec6654cbc4ef4af8eeb543ca4c158832d14a8b06e334d4a79c5c4",
    "multibyte-keys.auth": "232f0cd144b2c55d2c82c4b606175ae0112ee7fc08debaeaa7095f1c01f0b04d",
    "sapling-spend-only.txid": "ac597d1dfdbefceea30bd27bcfd3e1913413fc7a6a8167253e2907dca136142c",
    "sapling-spend-only.auth": "687e3af27cf0e631c16fd141f085c1c0e858dfa756b5d199d982641caf11b728",
    "sapling-output-only.txid": "7648d71cb0539eb2edc44bdb09f966aeec91b3e6f1c90db8ec90e4e702926838",
    "sapling-output-only.auth": "ff39305034f480f5ee7a145fee3b5b590ab9d65ca0ed09f0dfe0b4227483aa53",
    "transparent-input-only.txid": "8d7c8a88430f0d2a88d766b8d5d9235125974213b381164d3f9bb65414868e10",
    "transparent-input-only.auth": "4e04a439f3dc90ab8e1eefd7df9e8f3239a8b415276c8bb03dbd3743b5cdef01",
    "transparent-output-only.txid": "0caec7455630287b64875c58f62be72daf447f7fae33f31856295c6c4cf5d0d6",
    "transparent-output-only.auth": "d3a128d379cd32a6ec49acb8e5da337ed38e80c068fa0e33e4baf2786867241a",
    "multi-bundle.txid": "de832452363d1f93fdf6704d52d0398008048513c478e6359aa12ccb75c90ac9",
    "multi-bundle.auth": "1fe422a25a96ecdb839683316f76ef1bf73dd9c5f9e0465b653bd86f3ed0f215",
    "signature-no-inputs.sapling-binding": "c2971e82722cd3d08ac344dd5a28ac38e7350be62e853ab3d231c57387980ae3",
    "signature-no-inputs.ironwood-binding": "c00985d76f40d56be0aefae528b8d2b59b1d76e757c73d1a7ea1c6d5a8b568c6",
    "signature-encoding.transparent-0": "8230739cf8da95abf54a0dcb0499665de91f1a139c1ffd0f6db58d052e5f5b59",
    "signature-encoding.transparent-1": "83bcb85c0ca15afac6b128fe6f981ac9be39a4683e2664ddf6041007fac425a4",
    "signature-encoding.sapling-spend-0": "57d22b7b9a03ccec047e52afcd1891e86e242c890fa3ae2e83d7c7fce468b252",
    "signature-encoding.sapling-spend-1": "08acd07d62eca358549cf3de7a4a3d7da70d3a2aa0af0f57d36998e5db2cf53f",
    "signature-encoding.sapling-binding": "5668c48b15213c0fcbd59c833b43a19910c81c1ed1bb4cfaf5213c33c62c222f",
    "signature-encoding.orchard-action-0": "e14d5014dfe7aba705d83d047d5146cf9ca543437b35582aa49d3b8d6ca8b5b2",
    "signature-encoding.orchard-action-1": "00b5343a37ffc93340c2eb4578b92725cd79f18bb2274bc2851a2557eb395462",
    "signature-encoding.orchard-binding": "f80811a16432e00e52221e5b6b88a61b8783ed8423279e9498554b7b12f5b493",
    "signature-encoding.ironwood-action-0": "62455c8b520a58c35646b4517ef249fcd88df3c60d3fd9253dcf5dbc6e85db13",
    "signature-encoding.ironwood-action-1": "c4991db36d132ac1c12a48e4f4ac2e4c2b242df32dbbc459487b33d7ec754d26",
    "signature-encoding.ironwood-binding": "0d2869e9f93b57763b4ab7fb67462f434d29e58bf2ae758e1cbcc16bde4ba1a8",
}

# Existing Rust S.1–S.7 expectations, checked using the mixed fixture's S.2 input.
SIGNATURE_EXPECTED = {
    "transparent-0": "71d4bbdfcf13027cdb7e26ddf1dfb3ab3a102f6f849f80f5d998158c09def3c0",
    "transparent-1": "7639ff9222b7ec04ba1756ae017b3128d00a5da1720a37d9d50b0dd6ad546188",
    "sapling-spend-0": "ac3d66182997040c7be5764919ad6fc52c63e6af13caadd79159bd81d6a69d23",
    "sapling-spend-1": "6f4418263a74d677dfba3c02f9eb260d2cbebfcdb7f184fe4fe1841633835582",
    "sapling-binding": "1e44b7992dffff7c8af203b0581da56e853d248a0cc4fbd47e014d3f3d9933dd",
    "orchard-action-0": "065518b371b7736a0bc7dac5e5734d3feae22185b9dc327ffaad0dae2f64291b",
    "orchard-action-1": "67aca543774a75b8fdb5acc51a84b6105b8da89c0ae7b645a5ee01c36d9f5841",
    "orchard-binding": "f4a373af063185388287b3609728e5edc538bce3dd4d76df80d231e0919cd6bf",
    "ironwood-action-0": "850e20797a7be38c009ed429ee9e5257ba4d5f16db7e874c1b0aa31244cf1d8e",
    "ironwood-action-1": "7dded93e8cd9b091c24961d61f7a273718a6a0fb3cc510c28a50b2ab0d53b0fa",
    "ironwood-binding": "1fbb13ec4c63f79193bfab281f0dd740895d2ef8004fb5de0224edd1c7656250",
}

# Existing sighash.rs context_tests::v7_null_prevout_commits_input_amounts_and_scripts
# expectations; S.2 is recomputed from the explicit envelope, not supplied.
NULL_PREVOUT_EXPECTED = {
    "signature-null-prevout.txid-input": "85148ab86193ca6e87e022a63bc4594ed6916169325c48fde5bb959217fcb788",
    "signature-null-prevout.amounts": "159131ef4b3c5ecf0a3af9e77cf3413e82d1a8c7316456f76c31228a382420b6",
    "signature-null-prevout.scriptpubkeys": "7483749f88de7959e1b406eb5064410a2324b83bf1f51d17e1cb7e8b5c3038de",
    "signature-null-prevout.sapling-binding": "b36da24bb839b289ce3adc410bade676d6a4e30099429a4d77a8589f6313de26",
}


def check_expected(generated, expected):
    for name, wanted in expected.items():
        actual = generated[name]
        if actual != wanted:
            raise ValueError(f"{name}: expected {wanted}, generated {actual}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print every generated digest")
    parser.add_argument("--check", "--check-rust", dest="check_rust", action="store_true",
                        help="check the inventory of v7 Rust hex literals")
    parser.add_argument("--signature-txid",
                        help="raw 32-byte S.2 hex input for the mixed signature fixture")
    args = parser.parse_args()
    fixtures = generate()
    expected = {
        **EXPECTED,
        **PREIMAGE_EXPECTED,
        **NULL_PREVOUT_EXPECTED,
        **{f"signature-mixed.{name}": digest
           for name, digest in SIGNATURE_EXPECTED.items()},
    }
    if args.signature_txid:
        try:
            txid = bytes.fromhex(args.signature_txid)
        except ValueError:
            parser.error("--signature-txid must be hexadecimal")
        if len(txid) != HASH_SIZE:
            parser.error("--signature-txid must be exactly 32 bytes")
        values, scripts, _, contexts = signature_contexts()
        fixtures["signature-mixed"] = signature_vectors(txid, values, scripts, contexts)
    generated = {
        f"{fixture}.{node}": digest.hex()
        for fixture, nodes in fixtures.items() for node, digest in nodes.items()
    }
    check_expected(generated, expected)
    if args.check_rust:
        root = Path(__file__).resolve().parent.parent
        typed = (root / "zcash_primitives/src/transaction/tests.rs").read_text()
        byte_tests = (root / "zcash_primitives/src/transaction/bytes/tests.rs").read_text()
        # Scope the inventory to v7-only literal-vector sections. The first
        # part of tests.rs also holds pre-v7 fixtures outside this generator.
        typed = typed[typed.index("fn v7_empty_transaction_matches_zip248_digests"):]
        literals = set(re.findall(r'"([0-9a-f]{64})"', typed + byte_tests))
        inventory = set(EXPECTED.values()) | set(SIGNATURE_EXPECTED.values())
        # This fixture can be integrated independently of the original vectors.
        # Always verify its outputs; check its source literals when present.
        sighash = (root / "zcash_primitives/src/transaction/sighash.rs").read_text()
        null_test = "fn v7_null_prevout_commits_input_amounts_and_scripts"
        if null_test in sighash:
            null_source = sighash[sighash.index(null_test):].split("\n    #[test]", 1)[0]
            literals.update(re.findall(r'"([0-9a-f]{64})"', null_source))
            inventory.update(NULL_PREVOUT_EXPECTED.values())
        if literals != inventory:
            raise ValueError(
                f"Rust literal inventory changed: added={sorted(literals - inventory)}, "
                f"absent={sorted(inventory - literals)}"
            )
    if args.json:
        print(json.dumps(generated, indent=2, sort_keys=True))
    else:
        rust_count = len(EXPECTED) + len(SIGNATURE_EXPECTED) + len(NULL_PREVOUT_EXPECTED)
        print(f"Verified {rust_count} named Rust hex constants and "
              f"{len(PREIMAGE_EXPECTED)} Python reference outputs; "
              f"generated {len(generated)} digests.")
        print("Directional and multi-element preimage fixtures: use --json for outputs.")


if __name__ == "__main__":
    main()
