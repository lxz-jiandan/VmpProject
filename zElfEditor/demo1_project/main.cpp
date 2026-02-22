#include <cstdint>
#include <cstdio>

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
volatile int g_counter = 3;
const char* str = "hello";

static const char kBanner[] = "demo1-rodata-banner";
static const uint32_t kConstTable[16] = {
        0x13579BDFu, 0x2468ACE0u, 0x0F0F0F0Fu, 0xAAAAAAAAu,
        0x55AA55AAu, 0x11223344u, 0x89ABCDEFu, 0x10203040u,
        0x01020304u, 0x7F7F7F7Fu, 0xDEADBEEFu, 0xC001D00Du,
        0x31415926u, 0x27182818u, 0xABCDEF01u, 0xFACEB00Cu,
};

static uint64_t gMutableTable[8] = {
        3ULL, 5ULL, 8ULL, 13ULL,
        21ULL, 34ULL, 55ULL, 89ULL,
};

struct Node {
    int id;
    const char* name;
    uint64_t seed;
};

static Node gNodes[] = {
        {11, "alpha", 0x1111111111111111ULL},
        {17, "beta", 0x2222222222222222ULL},
        {23, "gamma", 0x3333333333333333ULL},
        {29, "delta", 0x4444444444444444ULL},
};

extern "C" NOINLINE USED int add_impl(int left, int right) {
    return left + right;
}

extern "C" NOINLINE USED int mul_impl(int left, int right) {
    return left * right;
}

extern "C" NOINLINE USED int xor_impl(int left, int right) {
    return left ^ right;
}

using MathOp = int (*)(int, int);
static MathOp gMathOps[] = {add_impl, mul_impl, xor_impl};

extern "C" NOINLINE USED uint64_t calc_mix(int base) {
    uint64_t acc = static_cast<uint64_t>(base) + static_cast<uint64_t>(g_counter);
    for (size_t i = 0; i < 16; ++i) {
        const uint64_t k = static_cast<uint64_t>(kConstTable[i]);
        const uint64_t m = gMutableTable[i % 8];
        acc ^= (k + (m << (i % 5)));
        acc = (acc << 7) | (acc >> (64 - 7));
    }
    return acc;
}

extern "C" NOINLINE USED int walk_nodes() {
    int score = 0;
    for (size_t i = 0; i < sizeof(gNodes) / sizeof(gNodes[0]); ++i) {
        score = gMathOps[i % 3](score + gNodes[i].id, static_cast<int>(gNodes[i].seed & 0xFF));
        score ^= static_cast<int>(gNodes[i].name[0]);
    }
    return score;
}

extern "C" NOINLINE USED void mutate_state(int round) {
    for (size_t i = 0; i < 8; ++i) {
        gMutableTable[i] += static_cast<uint64_t>((round + 1) * (i + 3));
    }
    g_counter += round + static_cast<int>(kBanner[0] & 0x7);
}

extern "C" NOINLINE USED void test1() {
    mutate_state(2);
    const int node_score = walk_nodes();
    const uint64_t signature = calc_mix(node_score + a + b);
    std::printf("test1 %s %d %d | sig=%llu nodes=%d counter=%d\n",
                str,
                a,
                b,
                static_cast<unsigned long long>(signature),
                node_score,
                static_cast<int>(g_counter));
}

int main() {
    test1();
    return 0;
}
