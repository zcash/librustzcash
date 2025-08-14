use zcash_protocol::consensus::NetworkType;

pub enum VectorKind {
    Privkey { is_compressed: bool },
    Pubkey,
}

pub struct TestVector {
    pub base58_encoding: &'static str,
    pub raw_bytes_hex: &'static str,
    pub kind: VectorKind,
    pub network: NetworkType,
}

// These are sourced from https://github.com/zcash/zcash/blob/b65b008a7b334a2f7c2eaae1b028e011f2e21dd1/src/test/data/base58_keys_valid.json
pub const VALID: &[TestVector] = &[
    TestVector {
        base58_encoding: "t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF",
        raw_bytes_hex: "76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3VDyGHn9mbyCf448m2cHTu5uXvsJpKHbiZ",
        raw_bytes_hex: "a91474f209f6ea907e2ea48f74fae05782ae8a66525787",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmHMBeeYRuc2eVicLNfP15YLxbQsooCA6jb",
        raw_bytes_hex: "76a91453c0307d6851aa0ce7825ba883c6bd9ad242b48688ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2Fbo6DBKKVYw1SfrY8bEgz56hYEhywhEN6",
        raw_bytes_hex: "a9146349a418fc4578d10a372b54b45c280cc8c4382f87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
        raw_bytes_hex: "eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD",
        raw_bytes_hex: "55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
        raw_bytes_hex: "36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
        raw_bytes_hex: "b9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f3",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1TpfguJj5zxKUfWcsNTrh6eod2XXsTKtvB",
        raw_bytes_hex: "76a9146d23156cbbdcc82a5a47eee4c2c7c583c18b6bf488ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3hc9Y2stuEWjS2dRDtGdiu3enMpxAbeUiK",
        raw_bytes_hex: "a914fcc5460dd6e2487c7d75b1963625da0e8f4c597587",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmXm2g5ouU8Pzksmqx3KYmeoeaWrAvj3rB5",
        raw_bytes_hex: "76a914f1d470f9b02370fdec2e6b708b08ac431bf7a5f788ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2QYxHjM8btztWTsMnFnZNurm7RXENk9ZhR",
        raw_bytes_hex: "a914c579342c2c4c9220205e2cdc285617040c924a0a87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5K494XZwps2bGyeL71pWid4noiSNA2cfCibrvRWqcHSptoFn7rc",
        raw_bytes_hex: "a326b95ebae30164217d7a7f57d72ab2b54e3be64928a19da0210b9568d4015e",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
        raw_bytes_hex: "7d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb4",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "93DVKyFYwSN6wEo3E2fCrFPUp17FtrtNi2Lf7n4G3garFb16CRj",
        raw_bytes_hex: "d6bca256b5abc5602ec2e1c121a08b0da2556587430bcf7e1898af2224885203",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cTDVKtMGVYWTHCb1AFjmVbEbWjvKpKqKgMaR3QJxToMSQAhmCeTN",
        raw_bytes_hex: "a81ca4e8f90181ec4b61b6a7eb998af17b2cb04de8a03b504b9e34c4c61db7d9",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1UxCT4RrCbGH36etfQaPF1svNtZVhsqs5A",
        raw_bytes_hex: "76a9147987ccaa53d02c8873487ef919677cd3db7a691288ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3Teyxv1gF8FZ9MW8WN4MvTxQ4JScABsKfL",
        raw_bytes_hex: "a91463bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmXYBLe2Q9MbXfgGb2QqdN7RWdi7tQ2z8ya",
        raw_bytes_hex: "76a914ef66444b5b17f14e8fae6e7e19b045a78c54fd7988ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2QQcXALz4745JEgzuAEsJNgt6nBQpsqegu",
        raw_bytes_hex: "a914c3e55fceceaa4391ed2a9677f4a4d34eacd021a087",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5KaBW9vNtWNhc3ZEDyNCiXLPdVPHCikRxSBWwV9NrpLLa4LsXi9",
        raw_bytes_hex: "e75d936d56377f432f404aabb406601f892fd49da90eb6ac558a733c93b47252",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "L1axzbSyynNYA8mCAhzxkipKkfHtAXYF4YQnhSKcLV8YXA874fgT",
        raw_bytes_hex: "8248bd0375f2f75d7e274ae544fb920f51784480866b102384190b1addfbaa5c",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "927CnUkUbasYtDwYwVn2j8GdTuACNnKkjZ1rpZd2yBB1CLcnXpo",
        raw_bytes_hex: "44c4f6a096eac5238291a94cc24c01e3b19b8d8cef72874a079e00a242237a52",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cUcfCMRjiQf85YMzzQEk9d1s5A4K7xL5SmBCLrezqXFuTVefyhY7",
        raw_bytes_hex: "d1de707020a9059d6d3abaf85e17967c6555151143db13dbb06db78df0f15c69",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1ZiM4oLF7hvboF4LPqhbBg7RLgJCCJC6Tj",
        raw_bytes_hex: "76a914adc1cc2081a27206fae25792f28bbc55b831549d88ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3LoV8q8R44fSbe84DBKDk3sAEoYum4hQYj",
        raw_bytes_hex: "a914188f91a931947eddd7432d6e614387e32b24470987",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmBmkeJmwF3UgVXqJLzEin49ftK1HmsqYup",
        raw_bytes_hex: "76a9141694f5bc1a7295b600f40018a618a6ea48eeb49888ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2Byypnbxh2Pfk7VqLMzYfiNeD72o6yvtqX",
        raw_bytes_hex: "a9143b9b3fd7a50d4f08d1a5b0f62f644fa7115ae2f387",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5HtH6GdcwCJA4ggWEL1B3jzBBUB8HPiBi9SBc5h9i4Wk4PSeApR",
        raw_bytes_hex: "091035445ef105fa1bb125eccfb1882f3fe69592265956ade751fd095033d8d0",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "L2xSYmMeVo3Zek3ZTsv9xUrXVAmrWxJ8Ua4cw8pkfbQhcEFhkXT8",
        raw_bytes_hex: "ab2b4bcdfc91d34dee0ae2a8c6b6668dadaeb3a88b9859743156f462325187af",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
        raw_bytes_hex: "b4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cVM65tdYu1YK37tNoAyGoJTR13VBYFva1vg9FLuPAsJijGvG6NEA",
        raw_bytes_hex: "e7b230133f1b5489843260236b06edca25f66adb1be455fbd38d4010d48faeef",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1boxWWuUs3dVUFeUMiPqCdwD4QtL1AMx9G",
        raw_bytes_hex: "76a914c4c1b72491ede1eedaca00618407ee0b772cad0d88ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3h5bvzkCXkiMttmQScK56UjVcqeD3NnReW",
        raw_bytes_hex: "a914f6fe69bcb548a829cce4c57bf6fff8af3a5981f987",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmDBvm2S5yAj5pVAvB4th1DDVpLq3KuN8S1",
        raw_bytes_hex: "76a914261f83568a098a8638844bd7aeca039d5f2352c088ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2TooyZ7BmQTBkgCVhdNQsPfeVdQoWqsHQa",
        raw_bytes_hex: "a914e930e1834a4d234702773951d627cce82fbb5d2e87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5KQmDryMNDcisTzRp3zEq9e4awRmJrEVU1j5vFRTKpRNYPqYrMg",
        raw_bytes_hex: "d1fab7ab7385ad26872237f1eb9789aa25cc986bacc695e07ac571d6cdac8bc0",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "L39Fy7AC2Hhj95gh3Yb2AU5YHh1mQSAHgpNixvm27poizcJyLtUi",
        raw_bytes_hex: "b0bbede33ef254e8376aceb1510253fc3550efd0fcf84dcd0c9998b288f166b3",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "91cTVUcgydqyZLgaANpf1fvL55FH53QMm4BsnCADVNYuWuqdVys",
        raw_bytes_hex: "037f4192c630f399d9271e26c575269b1d15be553ea1a7217f0cb8513cef41cb",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cQspfSzsgLeiJGB2u8vrAiWpCU4MxUT6JseWo2SjXy4Qbzn2fwDw",
        raw_bytes_hex: "6251e205e8ad508bab5596bee086ef16cd4b239e0cc0c5d7c4e6035441e7d5de",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1SWDbHDTatR1ag8yTFLdVWd1erfu7Pbbjk",
        raw_bytes_hex: "76a9145eadaf9bb7121f0f192561a5a62f5e5f5421029288ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3QKR6mLBwPY6DeqHwjJCxUwSsGUToB5sWJ",
        raw_bytes_hex: "a9143f210e7277c899c3a155cc1c90f4106cbddeec6e87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "tmU1EeoNHCfmWpeZWeRnKmNeVdHJgZjse5G",
        raw_bytes_hex: "76a914c8a3c2a09a298592c3e180f02487cd91ba3400b588ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t2LZVwB5A2n5U9odwMbLd1g5Bz9Z3ZFoCJH",
        raw_bytes_hex: "a91499b31df7c9068d1481b596578ddbb4d3bd90baeb87",

        kind: VectorKind::Pubkey,
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "5KL6zEaMtPRXZKo1bbMq7JDjjo1bJuQcsgL33je3oY8uSJCR5b4",
        raw_bytes_hex: "c7666842503db6dc6ea061f092cfb9c388448629a6fe868d068c42a488b478ae",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
        raw_bytes_hex: "07f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV",
        raw_bytes_hex: "ea577acfb5d1d14d3b7b195c321566f12f87d2b77ea3a53f68df7ebf8604a801",
        kind: VectorKind::Privkey {
            is_compressed: false,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "cMxXusSihaX58wpJ3tNuuUcZEQGt6DKJ1wEpxys88FFaQCYjku9h",
        raw_bytes_hex: "0b3b34f0958d8a268193a9814da92c3e8b58b4a4378a542863e34ac289cd830c",
        kind: VectorKind::Privkey {
            is_compressed: true,
        },
        network: NetworkType::Test,
    },
    TestVector {
        base58_encoding: "t1Lgcj4m5r7eDWctWQM7ete85hHivQxMjBZ",
        raw_bytes_hex: "76a9141ed467017f043e91ed4c44b4e8dd674db211c4e688ac",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
    TestVector {
        base58_encoding: "t3TCuHUxH3LGnsFYTUbSwHrRXxTaEA8hAaf",
        raw_bytes_hex: "a9145ece0cadddc415b1980f001785947120acdb36fc87",
        kind: VectorKind::Pubkey,
        network: NetworkType::Main,
    },
];

// Sourced from https://github.com/zcash/zcash/blob/b65b008a7b334a2f7c2eaae1b028e011f2e21dd1/src/test/data/base58_keys_invalid.json
pub const INVALID: &[&str] = &[
    "",
    "x",
    "37qgekLpCCHrQuSjvX3fs496FWTGsHFHizjJAs6NPcR47aefnnCWECAhHV6E3g4YN7u7Yuwod5Y",
    "dzb7VV1Ui55BARxv7ATxAtCUeJsANKovDGWFVgpTbhq9gvPqP3yv",
    "MuNu7ZAEDFiHthiunm7dPjwKqrVNCM3mAz6rP9zFveQu14YA8CxExSJTHcVP9DErn6u84E6Ej7S",
    "rPpQpYknyNQ5AEHuY6H8ijJJrYc2nDKKk9jjmKEXsWzyAQcFGpDLU2Zvsmoi8JLR7hAwoy3RQWf",
    "4Uc3FmN6NQ6zLBK5QQBXRBUREaaHwCZYsGCueHauuDmJpZKn6jkEskMB2Zi2CNgtb5r6epWEFfUJq",
    "7aQgR5DFQ25vyXmqZAWmnVCjL3PkBcdVkBUpjrjMTcghHx3E8wb",
    "17QpPprjeg69fW1DV8DcYYCKvWjYhXvWkov6MJ1iTTvMFj6weAqW7wybZeH57WTNxXVCRH4veVs",
    "KxuACDviz8Xvpn1xAh9MfopySZNuyajYMZWz16Dv2mHHryznWUp3",
    "7nK3GSmqdXJQtdohvGfJ7KsSmn3TmGqExug49583bDAL91pVSGq5xS9SHoAYL3Wv3ijKTit65th",
    "cTivdBmq7bay3RFGEBBuNfMh2P1pDCgRYN2Wbxmgwr4ki3jNUL2va",
    "gjMV4vjNjyMrna4fsAr8bWxAbwtmMUBXJS3zL4NJt5qjozpbQLmAfK1uA3CquSqsZQMpoD1g2nk",
    "emXm1naBMoVzPjbk7xpeTVMFy4oDEe25UmoyGgKEB1gGWsK8kRGs",
    "7VThQnNRj1o3Zyvc7XHPRrjDf8j2oivPTeDXnRPYWeYGE4pXeRJDZgf28ppti5hsHWXS2GSobdqyo",
    "1G9u6oCVCPh2o8m3t55ACiYvG1y5BHewUkDSdiQarDcYXXhFHYdzMdYfUAhfxn5vNZBwpgUNpso",
    "31QQ7ZMLkScDiB4VyZjuptr7AEc9j1SjstF7pRoLhHTGkW4Q2y9XELobQmhhWxeRvqcukGd1XCq",
    "DHqKSnpxa8ZdQyH8keAhvLTrfkyBMQxqngcQA5N8LQ9KVt25kmGN",
    "2LUHcJPbwLCy9GLH1qXmfmAwvadWw4bp4PCpDfduLqV17s6iDcy1imUwhQJhAoNoN1XNmweiJP4i",
    "7USRzBXAnmck8fX9HmW7RAb4qt92VFX6soCnts9s74wxm4gguVhtG5of8fZGbNPJA83irHVY6bCos",
    "1DGezo7BfVebZxAbNT3XGujdeHyNNBF3vnficYoTSp4PfK2QaML9bHzAMxke3wdKdHYWmsMTJVu",
    "2D12DqDZKwCxxkzs1ZATJWvgJGhQ4cFi3WrizQ5zLAyhN5HxuAJ1yMYaJp8GuYsTLLxTAz6otCfb",
    "8AFJzuTujXjw1Z6M3fWhQ1ujDW7zsV4ePeVjVo7D1egERqSW9nZ",
    "163Q17qLbTCue8YY3AvjpUhotuaodLm2uqMhpYirsKjVqnxJRWTEoywMVY3NbBAHuhAJ2cF9GAZ",
    "2MnmgiRH4eGLyLc9eAqStzk7dFgBjFtUCtu",
    "461QQ2sYWxU7H2PV4oBwJGNch8XVTYYbZxU",
    "2UCtv53VttmQYkVU4VMtXB31REvQg4ABzs41AEKZ8UcB7DAfVzdkV9JDErwGwyj5AUHLkmgZeobs",
    "cSNjAsnhgtiFMi6MtfvgscMB2Cbhn2v1FUYfviJ1CdjfidvmeW6mn",
    "gmsow2Y6EWAFDFE1CE4Hd3Tpu2BvfmBfG1SXsuRARbnt1WjkZnFh1qGTiptWWbjsq2Q6qvpgJVj",
    "nksUKSkzS76v8EsSgozXGMoQFiCoCHzCVajFKAXqzK5on9ZJYVHMD5CKwgmX3S3c7M1U3xabUny",
    "L3favK1UzFGgdzYBF2oBT5tbayCo4vtVBLJhg2iYuMeePxWG8SQc",
    "7VxLxGGtYT6N99GdEfi6xz56xdQ8nP2dG1CavuXx7Rf2PrvNMTBNevjkfgs9JmkcGm6EXpj8ipyPZ",
    "2mbZwFXF6cxShaCo2czTRB62WTx9LxhTtpP",
    "dB7cwYdcPSgiyAwKWL3JwCVwSk6epU2txw",
    "HPhFUhUAh8ZQQisH8QQWafAxtQYju3SFTX",
    "4ctAH6AkHzq5ioiM1m9T3E2hiYEev5mTsB",
    "Hn1uFi4dNexWrqARpjMqgT6cX1UsNPuV3cHdGg9ExyXw8HTKadbktRDtdeVmY3M1BxJStiL4vjJ",
    "Sq3fDbvutABmnAHHExJDgPLQn44KnNC7UsXuT7KZecpaYDMU9Txs",
    "6TqWyrqdgUEYDQU1aChMuFMMEimHX44qHFzCUgGfqxGgZNMUVWJ",
    "giqJo7oWqFxNKWyrgcBxAVHXnjJ1t6cGoEffce5Y1y7u649Noj5wJ4mmiUAKEVVrYAGg2KPB3Y4",
    "cNzHY5e8vcmM3QVJUcjCyiKMYfeYvyueq5qCMV3kqcySoLyGLYUK",
    "37uTe568EYc9WLoHEd9jXEvUiWbq5LFLscNyqvAzLU5vBArUJA6eydkLmnMwJDjkL5kXc2VK7ig",
    "EsYbG4tWWWY45G31nox838qNdzksbPySWc",
    "nbuzhfwMoNzA3PaFnyLcRxE9bTJPDkjZ6Rf6Y6o2ckXZfzZzXBT",
    "cQN9PoxZeCWK1x56xnz6QYAsvR11XAce3Ehp3gMUdfSQ53Y2mPzx",
    "1Gm3N3rkef6iMbx4voBzaxtXcmmiMTqZPhcuAepRzYUJQW4qRpEnHvMojzof42hjFRf8PE2jPde",
    "2TAq2tuN6x6m233bpT7yqdYQPELdTDJn1eU",
    "ntEtnnGhqPii4joABvBtSEJG6BxjT2tUZqE8PcVYgk3RHpgxgHDCQxNbLJf7ardf1dDk2oCQ7Cf",
    "Ky1YjoZNgQ196HJV3HpdkecfhRBmRZdMJk89Hi5KGfpfPwS2bUbfd",
    "2A1q1YsMZowabbvta7kTy2Fd6qN4r5ZCeG3qLpvZBMzCixMUdkN2Y4dHB1wPsZAeVXUGD83MfRED",
];
