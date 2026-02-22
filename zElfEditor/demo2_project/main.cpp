#include <cstdint>
#include <cstdio>
#include <cstring>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

#ifdef __GNUC__
#define USED __attribute__((used))
#else
#define USED
#endif

int a = 1;
static int b = 2;
volatile int g_tick = 7;
const char* str = "hello";

static const char kWords[][8] = {
        "alpha", "beta", "gamma", "delta", "omega"
};

static const uint64_t kSeedTable[12] = {
        0x9E3779B97F4A7C15ULL, 0xC2B2AE3D27D4EB4FULL,
        0x165667B19E3779F9ULL, 0x85EBCA77C2B2AE63ULL,
        0x27D4EB2F165667C5ULL, 0xD6E8FEB86659FD93ULL,
        0xA5A5A5A5A5A5A5A5ULL, 0x5A5A5A5A5A5A5A5AULL,
        0x1122334455667788ULL, 0x8877665544332211ULL,
        0x0101010101010101ULL, 0xFEDCBA9876543210ULL,
};

static uint32_t gState[10] = {
        1u, 3u, 5u, 7u, 11u,
        13u, 17u, 19u, 23u, 29u,
};

struct Record {
    const char* name;
    int weight;
    uint32_t mask;
};

static Record gRecords[] = {
        {"r0", 5, 0x00FF00FFu},
        {"r1", 7, 0x0F0F0F0Fu},
        {"r2", 11, 0x3333CCCCu},
        {"r3", 13, 0x55AA55AAu},
};

extern "C" NOINLINE USED uint64_t mix_round(uint64_t x, uint64_t y) {
    x ^= y + 0x9E3779B97F4A7C15ULL + (x << 6) + (x >> 2);
    x = (x << 13) | (x >> (64 - 13));
    return x;
}

extern "C" NOINLINE USED int hash_words(const char* salt) {
    int score = 0;
    for (size_t i = 0; i < sizeof(kWords) / sizeof(kWords[0]); ++i) {
        char buffer[32] = {0};
        std::snprintf(buffer, sizeof(buffer), "%s:%s", salt, kWords[i]);
        score += static_cast<int>(std::strlen(buffer)) * static_cast<int>(i + 1);
        score ^= static_cast<int>(buffer[0]);
    }
    return score;
}

extern "C" NOINLINE USED uint64_t fold_records(int seed) {
    uint64_t acc = static_cast<uint64_t>(seed) ^ static_cast<uint64_t>(g_tick);
    for (size_t i = 0; i < sizeof(gRecords) / sizeof(gRecords[0]); ++i) {
        acc = mix_round(acc, kSeedTable[i]);
        acc ^= static_cast<uint64_t>(gRecords[i].weight * (int)(i + 3));
        acc ^= static_cast<uint64_t>(gRecords[i].mask);
        if (std::strcmp(gRecords[i].name, "r2") == 0) {
            acc ^= 0x1234000012340000ULL;
        }
    }
    return acc;
}

extern "C" NOINLINE USED void mutate_state(int delta) {
    for (size_t i = 0; i < sizeof(gState) / sizeof(gState[0]); ++i) {
        gState[i] += static_cast<uint32_t>(delta + (int)i * 2);
    }
    g_tick += delta;
}

extern "C" NOINLINE USED void test2() {
    mutate_state(4);
    const int word_hash = hash_words("demo2");
    const uint64_t folded = fold_records(word_hash + a + b + static_cast<int>(gState[3]));
    std::printf("test2 %s %d %d | fold=%llu hash=%d tick=%d\n",
                str,
                a,
                b,
                static_cast<unsigned long long>(folded),
                word_hash,
                static_cast<int>(g_tick));
}

int main() {
    test2();
    return 0;
}
