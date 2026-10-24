// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_RANDOM_H
#define BITCOIN_TEST_UTIL_RANDOM_H

#include <consensus/amount.h>
#include <random.h>
#include <uint256.h>

#include <cstdint>

/**
 * This global and the helpers that use it are not thread-safe.
 *
 * If thread-safety is needed, the global could be made thread_local (given
 * that thread_local is supported on all architectures we support) or a
 * per-thread instance could be used in the multi-threaded test.
 */
extern FastRandomContext g_insecure_rand_ctx;

/**
 * Flag to make GetRand in random.h return the same number
 */
extern bool g_mock_deterministic_tests;

enum class SeedRand {
    ZEROS, //!< Seed with a compile time constant of zeros
    SEED,  //!< Call the Seed() helper
};

/** Seed the given random ctx or use the seed passed in via an environment var */
void Seed(FastRandomContext& ctx);

static inline void SeedInsecureRand(SeedRand seed = SeedRand::SEED)
{
    if (seed == SeedRand::ZEROS) {
        g_insecure_rand_ctx = FastRandomContext(/*fDeterministic=*/true);
    } else {
        Seed(g_insecure_rand_ctx);
    }
}

static inline uint32_t InsecureRand32()
{
    return g_insecure_rand_ctx.rand32();
}

static inline uint256 InsecureRand256()
{
    return g_insecure_rand_ctx.rand256();
}

static inline uint64_t InsecureRandBits(int bits)
{
    return g_insecure_rand_ctx.randbits(bits);
}

static inline uint64_t InsecureRandRange(uint64_t range)
{
    return g_insecure_rand_ctx.randrange(range);
}

static inline bool InsecureRandBool()
{
    return g_insecure_rand_ctx.randbool();
}

static inline CAmount InsecureRandMoneyAmount()
{
    // DigitalGold's MAX_MONEY spans the whole int64 range, but CompressAmount() (used by the
    // coins database) only round-trips amounts below 2^64 / 9, so keep random amounts within
    // the range the code can actually store. (This also avoids MAX_MONEY + 1 overflowing
    // CAmount, which MSVC reports as C4307.)
    static constexpr CAmount MAX_COMPRESSIBLE_AMOUNT{2'000'000'000'000'000'000};
    return static_cast<CAmount>(InsecureRandRange(static_cast<uint64_t>(MAX_COMPRESSIBLE_AMOUNT) + 1));
}

#endif // BITCOIN_TEST_UTIL_RANDOM_H
