/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

// CUDA Kernel main function
// Compute SecpK1 keys and calculate RIPEMD160(SHA256(key)) then check address
// For the kernel, we use a 16 bits address lookup table which correspond to ~3 Base58 characters
// A second level lookup table contains 32 bits address (if used)
// (The CPU computes the full address and check the full address)
//
// We use affine coordinates for elliptic curve point (ie Z=1)

#include "GPUBloom.h"


__device__ __noinline__ void CheckPoint(uint32_t *_h, int32_t incr, address_t *address, uint32_t *lookup32, const uint8_t *bloom, uint32_t *out, uint32_t maxFound) {

  uint32_t   off;
  address_t   pr0;
  address_t   hit;
  uint32_t   pos;


    // Bloom filter ON-FILTRE: 17.9M adres icin cogu key burada eler.
    // Bloom yoksa atla, eski mantik calisir.
    if (bloom) {
        if (!bloomCheck(_h, bloom)) return;
    }

    // Lookup table
    pr0 = *(address_t *)(_h);
    hit = address[pr0];

    if (hit) {

        if (lookup32) {
            off = lookup32[pr0];
            // 8-byte lAddress: each entry occupies 2 consecutive uint32 slots (lo, hi).
            // False-positive rate: 17.9M / 2^64 ≈ 0 -- output buffer never overflows.
            uint64_t l64 = ((uint64_t)_h[1] << 32) | (uint64_t)_h[0];
            uint32_t lo = 0u, hi = (uint32_t)hit - 1u;
            while (lo <= hi) {
                uint32_t mid = (lo + hi) / 2u;
                uint32_t slot = off + mid * 2u;
                uint64_t lmi64 = ((uint64_t)lookup32[slot + 1] << 32) | (uint64_t)lookup32[slot];
                if (l64 < lmi64) {
                    if (mid == 0u) break;
                    hi = mid - 1u;
                } else if (l64 == lmi64) {
                    goto addItem;
                } else {
                    lo = mid + 1u;
                }
            }
            return;
        }

    addItem:

        pos = atomicAdd(out, 1);
        if (pos < maxFound) {
            uint32_t   tid = (blockIdx.x * blockDim.x) + threadIdx.x;
            out[pos * ITEM_SIZE32 + 1] = tid;
            out[pos * ITEM_SIZE32 + 2] = (uint32_t)(incr << 16) | (uint32_t)(1 << 15);
            out[pos * ITEM_SIZE32 + 3] = _h[0];
            out[pos * ITEM_SIZE32 + 4] = _h[1];
            out[pos * ITEM_SIZE32 + 5] = _h[2];
            out[pos * ITEM_SIZE32 + 6] = _h[3];
            out[pos * ITEM_SIZE32 + 7] = _h[4];
        }

    }

}

 //-----------------------------------------------------------------------------------------
