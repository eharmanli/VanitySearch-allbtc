/*
 * GPUBloom.h
 * GPU Bloom Filter hizli on-eleme.
 * 256MB bit array (~2.15B bit) - 17.9M adres icin tipik false-positive orani ~%0.3.
 * Cogu key bloom kontrolunden erken cikis yapar, binary search maliyeti azalir.
 */

#ifndef GPUBLOOMH
#define GPUBLOOMH

#include <stdint.h>

#define BLOOM_SIZE_BYTES_GPU (256ULL * 1024 * 1024)
#define BLOOM_BITS_GPU       (BLOOM_SIZE_BYTES_GPU * 8ULL)  // 2^31 bit
#define BLOOM_MASK_GPU       (BLOOM_BITS_GPU - 1ULL)        // 2^31 - 1 → % yerine & ile maskele

/**
 * bloomCheck: Hash160 bloom'da olabilir mi?
 * @return true  → olabilir (binary search ile dogrula)
 *         false → kesinlikle yok (erken cikis)
 *
 * Yalnizca CUDA derleyicisi (nvcc) icin derlenir — MSVC cpp uzantilarinda
 * __device__ anahtar kelimesini tanimaz, o yuzden korumali.
 */
#ifdef __CUDACC__
__device__ __forceinline__ bool bloomCheck(const uint32_t* h, const uint8_t* bloom) {
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    uint64_t hash;

    hash = ((uint64_t)h0 * 0x517cc1b727220a95ULL ^ (uint64_t)h1) & BLOOM_MASK_GPU;
    if (!(bloom[hash >> 3] & (1u << (hash & 7)))) return false;

    hash = ((uint64_t)h1 * 0x9e3779b97f4a7c15ULL ^ (uint64_t)h2) & BLOOM_MASK_GPU;
    if (!(bloom[hash >> 3] & (1u << (hash & 7)))) return false;

    hash = ((uint64_t)h2 * 0x6c62272e07bb0142ULL ^ (uint64_t)h3) & BLOOM_MASK_GPU;
    if (!(bloom[hash >> 3] & (1u << (hash & 7)))) return false;

    hash = ((uint64_t)h3 * 0xc3a5c85c97cb3127ULL ^ (uint64_t)h4) & BLOOM_MASK_GPU;
    if (!(bloom[hash >> 3] & (1u << (hash & 7)))) return false;

    return true;
}
#endif // __CUDACC__

/**
 * bloomAdd: CPU tarafinda bloom'a hash160 ekle.
 * hash160 -> 5 adet uint32_t.
 */
inline void bloomAdd(uint8_t* bloom, const uint32_t* h) {
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    uint64_t hash;

    hash = ((uint64_t)h0 * 0x517cc1b727220a95ULL ^ (uint64_t)h1) & BLOOM_MASK_GPU;
    bloom[hash >> 3] |= (1u << (hash & 7));

    hash = ((uint64_t)h1 * 0x9e3779b97f4a7c15ULL ^ (uint64_t)h2) & BLOOM_MASK_GPU;
    bloom[hash >> 3] |= (1u << (hash & 7));

    hash = ((uint64_t)h2 * 0x6c62272e07bb0142ULL ^ (uint64_t)h3) & BLOOM_MASK_GPU;
    bloom[hash >> 3] |= (1u << (hash & 7));

    hash = ((uint64_t)h3 * 0xc3a5c85c97cb3127ULL ^ (uint64_t)h4) & BLOOM_MASK_GPU;
    bloom[hash >> 3] |= (1u << (hash & 7));
}

#endif // GPUBLOOMH
