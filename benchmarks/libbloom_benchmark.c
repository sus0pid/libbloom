#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bloom.h"

enum {
    kPeerCount = 10,
    kBitmapBytes = 32,
    kHashProbes = 13,
    kMaxKeyLen = 32
};

static const double kTargetFalsePositive = 0.0001; /* 0.01% */
static const size_t kMemberBatches = 1u << 18;
static const size_t kRandomTrials = 1u << 20;

static inline double elapsed_ns(const struct timespec start,
                                const struct timespec end) {
    const double sec = (double)(end.tv_sec - start.tv_sec) * 1e9;
    const double nsec = (double)(end.tv_nsec - start.tv_nsec);
    return sec + nsec;
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int init_custom_filter(struct bloom *filter) {
    memset(filter, 0, sizeof(*filter));
    filter->entries = kPeerCount;
    filter->error = kTargetFalsePositive;
    filter->bits = (unsigned long)kBitmapBytes * 8;
    filter->bytes = kBitmapBytes;
    filter->hashes = kHashProbes;
    filter->bpe = (double)filter->bits / (double)filter->entries;
    filter->bf = calloc(filter->bytes, sizeof(unsigned char));
    if (filter->bf == NULL) {
        return 1;
    }
    filter->ready = 1;
    filter->major = BLOOM_VERSION_MAJOR;
    filter->minor = BLOOM_VERSION_MINOR;
    return 0;
}

int main(void) {
    struct bloom filter;
    if (init_custom_filter(&filter) != 0) {
        fprintf(stderr, "Failed to initialize libbloom benchmark filter\n");
        return EXIT_FAILURE;
    }

    char peers[kPeerCount][kMaxKeyLen];
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (uint64_t i = 0; i < kPeerCount; ++i) {
        snprintf(peers[i], sizeof(peers[i]), "peer-%02" PRIu64, i);
        int rc = bloom_add(&filter, peers[i], (int)strlen(peers[i]));
        if (rc < 0) {
            fprintf(stderr, "Insert failed for %s\n", peers[i]);
            bloom_free(&filter);
            return EXIT_FAILURE;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double insert_ns = elapsed_ns(start, end) / kPeerCount;

    for (uint64_t i = 0; i < kPeerCount; ++i) {
        if (bloom_check(&filter, peers[i], (int)strlen(peers[i])) != 1) {
            fprintf(stderr, "Membership check failed for %s\n", peers[i]);
            bloom_free(&filter);
            return EXIT_FAILURE;
        }
    }

    const size_t total_member_checks = kMemberBatches * kPeerCount;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t batch = 0; batch < kMemberBatches; ++batch) {
        for (uint64_t i = 0; i < kPeerCount; ++i) {
            (void)bloom_check(&filter, peers[i], (int)strlen(peers[i]));
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double member_lookup_ns = elapsed_ns(start, end) / total_member_checks;

    size_t false_hits = 0;
    uint64_t rng_state = 0xfeed1234567890abULL;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t trial = 0; trial < kRandomTrials; ++trial) {
        uint64_t candidate = xorshift64(&rng_state);
        char key[kMaxKeyLen];
        snprintf(key, sizeof(key), "noise-%016" PRIx64, candidate);
        if (bloom_check(&filter, key, (int)strlen(key)) == 1) {
            ++false_hits;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    const double random_lookup_ns = elapsed_ns(start, end) / (double)kRandomTrials;
    const double observed_fpr = (double)false_hits / (double)kRandomTrials;

    printf("libbloom benchmark\n");
    printf(" peers: %d\n bitmap: %d bytes (%u bits)\n hashes: %d\n target FPR: %.5f%%\n",
           kPeerCount,
           kBitmapBytes,
           (unsigned)(kBitmapBytes * 8),
           kHashProbes,
           kTargetFalsePositive * 100.0);
    printf(" inserts: %.2f ns/op for %d peers\n", insert_ns, kPeerCount);
    printf(" member lookups: %.2f ns/op over %zu checks\n",
           member_lookup_ns, total_member_checks);
    printf(" random lookups: %.2f ns/op over %zu checks\n",
           random_lookup_ns, (size_t)kRandomTrials);
    printf(" observed FPR: %.6f%% (%zu / %zu)\n",
           observed_fpr * 100.0,
           false_hits,
           (size_t)kRandomTrials);

    bloom_free(&filter);
    return EXIT_SUCCESS;
}
