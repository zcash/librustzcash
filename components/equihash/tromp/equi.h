// Equihash solver
// Copyright (c) 2016-2016 John Tromp, The Zcash developers

#ifndef ZCASH_POW_TROMP_EQUI_H
#define ZCASH_POW_TROMP_EQUI_H

#include <stdbool.h> // for type bool
#include <stdint.h> // for types uint32_t,uint64_t
#include <string.h> // for functions memset
#include <stdlib.h> // for function qsort

#include "blake2b.h"

typedef uint32_t u32;
typedef unsigned char uchar;

// algorithm parameters, prefixed with W to reduce include file conflicts

#ifndef WN
#define WN	200
#endif

#ifndef WK
#define WK	9
#endif

#define NDIGITS		(WK+1)
#define DIGITBITS	(WN/(NDIGITS))

#define PROOFSIZE (1<<WK)
static const u32 BASE = 1<<DIGITBITS;
static const u32 NHASHES = 2*BASE;
static const u32 HASHESPERBLAKE = 512/WN;
static const u32 HASHOUT = HASHESPERBLAKE*WN/8;

typedef u32 proof[PROOFSIZE];


enum verify_code { POW_OK, POW_DUPLICATE, POW_OUT_OF_ORDER, POW_NONZERO_XOR };
const char *errstr[] = { "OK", "duplicate index", "indices out of order", "nonzero xor" };

int compu32(const void *pa, const void *pb) {
  u32 a = *(u32 *)pa, b = *(u32 *)pb;
  return a<b ? -1 : a==b ? 0 : +1;
}

#endif // ZCASH_POW_TROMP_EQUI_H
