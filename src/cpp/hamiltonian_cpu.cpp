#include "hamiltonian_cpu.h"
#include "graph_generator.h"
#include "hugepage_alloc.h"
#include <chrono>
#include <cstring>
#include <algorithm>
#include <unordered_set>
#include <cstdio>
#include <random>
#include <atomic>
#include <thread>
#include <openssl/sha.h>

// Global shutdown flag for fast exit.
static std::atomic<bool> g_shutdown{false};

// Forward declarations
static void reduce_to_ground_state_worker(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[][2048]
);

// ============================================================================
// SHA256 implementation
// ============================================================================

namespace {

constexpr uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// Global lookup table: hex char -> value
constexpr uint8_t HEX_LOOKUP[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 0-15
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 16-31
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 32-47
    0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, // 48-63: '0'-'9'
    0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0, // 64-79: 'A'-'F'
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 80-95
    0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0, // 96-111: 'a'-'f'
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 112-127
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

constexpr char HEX_CHARS[] = "0123456789abcdef";

// Fast SHA256 via OpenSSL
inline void sha256_openssl(const uint8_t* data, size_t len, uint8_t* hash) {
    SHA256(data, len, hash);
}

void sha256_transform(uint32_t* state, const uint8_t* block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

} // anonymous namespace

// ============================================================================
// Bloom filter implementation (outside the anonymous namespace for reuse).
// ============================================================================
class BloomFilter {
private:
    // Expand to 16M bits = 2MB
    static constexpr size_t NUM_BITS = 16777216;  // 2^24 = 16M
    static constexpr size_t NUM_WORDS = NUM_BITS / 64;  // 262144 uint64_t words
    static constexpr size_t NUM_HASHES = 1;  // 1 hash to reduce false positives
    
    // Use thread_local storage to avoid repeated allocations.
    static thread_local uint64_t s_bits[NUM_WORDS];
    
    uint64_t* bits_;  // Points to the thread_local storage
    
    // Better hash: MurmurHash3-style finalization.
    inline size_t hash_path(const uint16_t* path, uint16_t len, uint64_t seed) const {
        // Combine two independent hashes for better distribution.
        uint64_t h1 = seed;
        uint64_t h2 = seed ^ 0xc4ceb9fe1a85ec53ULL;
        
        for (uint16_t i = 0; i < len; i++) {
            uint64_t k = path[i];
            // MurmurHash3-like mixing
            k *= 0x87c37b91114253d5ULL;
            k = (k << 31) | (k >> 33);
            k *= 0x4cf5ad432745937fULL;
            h1 ^= k;
            h1 = (h1 << 27) | (h1 >> 37);
            h1 = h1 * 5 + 0x52dce729;
            
            h2 ^= k;
            h2 = (h2 << 33) | (h2 >> 31);
            h2 = h2 * 5 + 0x38495ab5;
        }
        
        // Finalization mix
        h1 ^= len;
        h2 ^= len;
        h1 += h2;
        h2 += h1;
        
        // Final avalanche
        h1 ^= h1 >> 33;
        h1 *= 0xff51afd7ed558ccdULL;
        h1 ^= h1 >> 33;
        h1 *= 0xc4ceb9fe1a85ec53ULL;
        h1 ^= h1 >> 33;
        
        return h1 % NUM_BITS;
    }
    
public:
    BloomFilter() : bits_(s_bits) {
        // Zero the storage (required when reusing thread-local storage).
        std::memset(bits_, 0, NUM_WORDS * sizeof(uint64_t));
    }
    
    // Ignore constructor params; use fixed size storage.
    BloomFilter(size_t /*expected_items*/, double /*fp_rate*/ = 0.01) : bits_(s_bits) {
        std::memset(bits_, 0, NUM_WORDS * sizeof(uint64_t));
    }
    
    ~BloomFilter() = default;
    
    // Disable copying
    BloomFilter(const BloomFilter&) = delete;
    BloomFilter& operator=(const BloomFilter&) = delete;
    
    void insert(const uint16_t* path, uint16_t len) {
        for (size_t i = 0; i < NUM_HASHES; i++) {
            size_t pos = hash_path(path, len, i * 0x517cc1b727220a95ULL);
            bits_[pos / 64] |= (1ULL << (pos % 64));
        }
    }
    
    bool possibly_contains(const uint16_t* path, uint16_t len) const {
        for (size_t i = 0; i < NUM_HASHES; i++) {
            size_t pos = hash_path(path, len, i * 0x517cc1b727220a95ULL);
            if (!(bits_[pos / 64] & (1ULL << (pos % 64)))) {
                return false;
            }
        }
        return true;
    }
    
    // Check and add: if absent, insert and report whether it's new.
    bool check_and_add(const uint16_t* path, uint16_t len) {
        if (possibly_contains(path, len)) {
            return false;  // Possibly already present
        }
        insert(path, len);
        return true;  // New path
    }
};

// BloomFilter thread_local static member definition
thread_local uint64_t BloomFilter::s_bits[BloomFilter::NUM_WORDS] = {0};

// ============================================================================
// HamiltonianSearcherCPU implementation
// ============================================================================

HamiltonianSearcherCPU::HamiltonianSearcherCPU() {}

HamiltonianSearcherCPU::~HamiltonianSearcherCPU() {}

uint64_t HamiltonianSearcherCPU::get_time_ms() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

void HamiltonianSearcherCPU::hex_to_bytes(const std::string& hex, uint8_t* out, size_t* out_len) {
    size_t len = hex.length() / 2;
    for (size_t i = 0; i < len; i++) {
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    *out_len = len;
}

std::string HamiltonianSearcherCPU::bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex_chars[(data[i] >> 4) & 0xf]);
        result.push_back(hex_chars[data[i] & 0xf]);
    }
    return result;
}

void HamiltonianSearcherCPU::sha256(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t block_pos = 0;
    uint64_t total_bits = len * 8;
    
    // Process full blocks
    for (size_t i = 0; i < len; i++) {
        block[block_pos++] = data[i];
        if (block_pos == 64) {
            sha256_transform(state, block);
            block_pos = 0;
        }
    }
    
    // Padding
    block[block_pos++] = 0x80;
    if (block_pos > 56) {
        while (block_pos < 64) block[block_pos++] = 0;
        sha256_transform(state, block);
        block_pos = 0;
    }
    while (block_pos < 56) block[block_pos++] = 0;
    
    // Append length (big-endian)
    for (int i = 7; i >= 0; i--) {
        block[56 + (7 - i)] = (total_bits >> (i * 8)) & 0xff;
    }
    sha256_transform(state, block);
    
    // Output hash (big-endian)
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = state[i] & 0xff;
    }
}

bool HamiltonianSearcherCPU::meets_target(const std::string& hash_hex, const std::string& target_hex) {
    // Simple hex string comparison (both are little-endian reversed hex).
    // hash must be <= target
    if (hash_hex.length() != target_hex.length()) {
        return hash_hex.length() < target_hex.length();
    }
    return hash_hex <= target_hex;
}

uint64_t HamiltonianSearcherCPU::extract_seed_from_hash_hex(const std::string& hash_hex) {
    uint8_t bytes[64];
    size_t bytes_len;
    hex_to_bytes(hash_hex, bytes, &bytes_len);
    // Reverse the entire byte array (to match the Rust implementation).
    for (size_t i = 0; i < bytes_len / 2; i++) {
        uint8_t tmp = bytes[i];
        bytes[i] = bytes[bytes_len - 1 - i];
        bytes[bytes_len - 1 - i] = tmp;
    }
    // Take the first 8 bytes as a little-endian u64.
    uint64_t seed = 0;
    for (int i = 0; i < 8 && i < (int)bytes_len; i++) {
        seed |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return seed;
}

uint16_t HamiltonianSearcherCPU::get_worker_grid_size(const std::string& hash_hex) {
    // Convert the first 8 hex characters to u64.
    std::string segment = hash_hex.substr(0, 8);
    uint64_t val = 0;
    for (size_t i = 0; i < 8; i++) {
        val = (val << 4) | HEX_LOOKUP[(uint8_t)segment[i]];
    }
    constexpr uint64_t min_grid_size = 1892;
    constexpr uint64_t max_grid_size = 1920;
    return static_cast<uint16_t>(min_grid_size + (val % (max_grid_size - min_grid_size)));
}

uint16_t HamiltonianSearcherCPU::get_queen_bee_grid_size(uint16_t worker_size) {
    return HC_GRAPH_SIZE - worker_size;
}

// Worker graph thread_local globals (allocated via HugepageAllocator).
static thread_local bool (*g_worker_edges)[2048] = nullptr;
static thread_local std::vector<uint16_t>* g_worker_node_edges = nullptr;
static thread_local bool* g_in_path = nullptr;
static thread_local uint16_t* g_pos_in_path = nullptr;
static thread_local uint16_t* g_rotation_candidates = nullptr;
static thread_local bool g_worker_use_hugepage = false;

// Ensure worker graph data is allocated.
static inline void ensure_worker_graph_allocated() {
    if (g_worker_edges == nullptr) {
        auto& alloc = HugepageAllocator::instance();
        
        // g_worker_edges: bool[2048][2048] = 4MB (largest array)
        constexpr size_t edges_size = 2048 * 2048 * sizeof(bool);
        void* edges_ptr = alloc.alloc(edges_size, 64);
        if (edges_ptr) {
            g_worker_edges = reinterpret_cast<bool(*)[2048]>(edges_ptr);
            std::memset(g_worker_edges, 0, edges_size);
            g_worker_use_hugepage = true;
        } else {
            g_worker_edges = new bool[2048][2048]();
        }
        
        // g_in_path: bool[2048] = 2KB
        constexpr size_t in_path_size = 2048 * sizeof(bool);
        void* in_path_ptr = alloc.alloc(in_path_size, 64);
        if (in_path_ptr) {
            g_in_path = reinterpret_cast<bool*>(in_path_ptr);
            std::memset(g_in_path, 0, in_path_size);
        } else {
            g_in_path = new bool[2048]();
        }
        
        // g_pos_in_path: uint16_t[2048] = 4KB
        constexpr size_t pos_size = 2048 * sizeof(uint16_t);
        void* pos_ptr = alloc.alloc(pos_size, 64);
        if (pos_ptr) {
            g_pos_in_path = reinterpret_cast<uint16_t*>(pos_ptr);
            std::memset(g_pos_in_path, 0, pos_size);
        } else {
            g_pos_in_path = new uint16_t[2048]();
        }
        
        // g_rotation_candidates: uint16_t[2048] = 4KB
        void* rot_ptr = alloc.alloc(pos_size, 64);
        if (rot_ptr) {
            g_rotation_candidates = reinterpret_cast<uint16_t*>(rot_ptr);
            std::memset(g_rotation_candidates, 0, pos_size);
        } else {
            g_rotation_candidates = new uint16_t[2048]();
        }
        
        // g_worker_node_edges: std::vector<uint16_t>[2048]
        // Note: std::vector needs proper construction; do not memset it.
        g_worker_node_edges = new std::vector<uint16_t>[2048]();
    }
}

// Worker graph generation + adjacency list build (merged optimized version).
static void generate_worker_graph_with_edges(
    uint64_t seed, uint16_t grid_size, uint16_t percentage_x10
) {
    ensure_worker_graph_allocated();
    size_t gs = static_cast<size_t>(grid_size);
    
    // Clear and reset
    for (size_t i = 0; i < gs; i++) {
        std::memset(g_worker_edges[i], 0, gs * sizeof(bool));
        g_worker_node_edges[i].clear();
    }
    
    constexpr uint64_t range = 1000;
    uint64_t threshold = (static_cast<uint64_t>(percentage_x10) * range) / 1000;
    
    // Inline PRNG to avoid virtual call overhead.
    std::mt19937_64 prng(seed);
    std::uniform_int_distribution<uint64_t> dist(0, range - 1);
    
    for (size_t i = 0; i < gs; i++) {
        for (size_t j = i + 1; j < gs; j++) {
            uint64_t random_value = dist(prng);
            if (random_value < threshold) {
                g_worker_edges[i][j] = true;
                g_worker_edges[j][i] = true;
                g_worker_node_edges[i].push_back(static_cast<uint16_t>(j));
                g_worker_node_edges[j].push_back(static_cast<uint16_t>(i));
            }
        }
    }
}

// Worker graph Posa rotation-extension algorithm.
static bool posa_rotation_extension_worker(
    uint16_t* path,
    uint16_t& path_len,
    uint16_t graph_size
) {
    static thread_local std::mt19937 rng(std::random_device{}());
    
    // Reset helper arrays
    std::memset(g_in_path, 0, graph_size * sizeof(bool));
    std::memset(g_pos_in_path, 0, graph_size * sizeof(uint16_t));
    
    uint16_t rotation_count = 0;
    
    path_len = 0;
    path[path_len++] = 0;
    g_in_path[0] = true;
    g_pos_in_path[0] = 0;
    
    const uint64_t max_iterations = static_cast<uint64_t>(graph_size) * graph_size * 100;
    uint64_t iteration_count = 0;
    size_t stuck_counter = 0;
    const size_t max_stuck = graph_size * 10;
    
    while (path_len < graph_size) {
        if (++iteration_count > max_iterations) {
            return false;
        }
        
        uint16_t endpoint = path[path_len - 1];
        bool extended = false;
        
        size_t neighbor_count = g_worker_node_edges[endpoint].size();
        size_t start_idx = neighbor_count == 0 ? 0 : rng() % neighbor_count;
        
        for (size_t i = 0; i < neighbor_count; i++) {
            uint16_t neighbor = g_worker_node_edges[endpoint][(start_idx + i) % neighbor_count];
            if (!g_in_path[neighbor]) {
                g_pos_in_path[neighbor] = path_len;
                path[path_len++] = neighbor;
                g_in_path[neighbor] = true;
                extended = true;
                stuck_counter = 0;
                break;
            }
        }
        
        if (extended) continue;
        
        rotation_count = 0;
        for (size_t ni = 0; ni < g_worker_node_edges[endpoint].size(); ni++) {
            uint16_t neighbor = g_worker_node_edges[endpoint][ni];
            if (!g_in_path[neighbor]) continue;
            uint16_t neighbor_pos = g_pos_in_path[neighbor];
            if (neighbor_pos < path_len - 2) {
                g_rotation_candidates[rotation_count++] = neighbor_pos;
            }
        }
        
        if (rotation_count == 0) {
            HamiltonianSearcherCPU::reverse_subpath(path, 0, path_len - 1);
            for (uint16_t k = 0; k < path_len; k++) {
                g_pos_in_path[path[k]] = k;
            }
            stuck_counter++;
            if (stuck_counter > max_stuck) {
                return false;
            }
            continue;
        }
        
        size_t rand_idx = rng() % rotation_count;
        uint16_t rotate_pos = g_rotation_candidates[rand_idx];
        
        HamiltonianSearcherCPU::reverse_subpath(path, rotate_pos + 1, path_len - 1);
        for (uint16_t k = rotate_pos + 1; k < path_len; k++) {
            g_pos_in_path[path[k]] = k;
        }
        stuck_counter = 0;
    }
    
    uint16_t first_node = path[0];
    uint16_t last_node = path[path_len - 1];
    
    if (g_worker_edges[last_node][first_node]) {
        return true;
    }
    
    for (size_t attempts = 0; attempts < static_cast<size_t>(graph_size) * 10; attempts++) {
        last_node = path[path_len - 1];
        first_node = path[0];
        
        if (g_worker_edges[last_node][first_node]) {
            return true;
        }
        
        rotation_count = 0;
        for (size_t ni = 0; ni < g_worker_node_edges[last_node].size(); ni++) {
            uint16_t neighbor = g_worker_node_edges[last_node][ni];
            uint16_t neighbor_pos = g_pos_in_path[neighbor];
            if (neighbor_pos < path_len - 2 && neighbor_pos > 0) {
                g_rotation_candidates[rotation_count++] = neighbor_pos;
            }
        }
        
        if (rotation_count == 0) {
            HamiltonianSearcherCPU::reverse_subpath(path, 0, path_len - 1);
            for (uint16_t k = 0; k < path_len; k++) {
                g_pos_in_path[path[k]] = k;
            }
            continue;
        }
        
        uint16_t best_rotate = g_rotation_candidates[rng() % rotation_count];
        
        for (uint16_t ci = 0; ci < rotation_count; ci++) {
            uint16_t candidate = g_rotation_candidates[ci];
            uint16_t potential_new_end = path[candidate + 1];
            if (g_worker_edges[potential_new_end][first_node]) {
                best_rotate = candidate;
                break;
            }
        }
        
        HamiltonianSearcherCPU::reverse_subpath(path, best_rotate + 1, path_len - 1);
        for (uint16_t k = best_rotate + 1; k < path_len; k++) {
            g_pos_in_path[path[k]] = k;
        }
    }
    
    return g_worker_edges[path[path_len - 1]][path[0]];
}

// Worker-graph DFS Hamiltonian cycle search (iterative, with timeout, for dense large graphs).
static bool search_hamiltonian_cycle_dfs_worker(
    uint16_t* path,
    uint16_t& path_len,
    uint16_t graph_size,
    uint64_t timeout_ms = 30  // Default timeout: 30ms
) {
    auto start_time = std::chrono::steady_clock::now();
    
    std::memset(g_in_path, 0, graph_size * sizeof(bool));
    // next_neighbor[i] stores the next neighbor index to try at depth i.
    std::memset(g_pos_in_path, 0, graph_size * sizeof(uint16_t));  // Reuse as next_neighbor
    
    path_len = 0;
    path[path_len++] = 0;
    g_in_path[0] = true;
    
    uint64_t iteration_count = 0;
    constexpr uint64_t CHECK_INTERVAL = 10000;  // Check timeout every 10,000 iterations
    
    while (path_len > 0) {
        // Periodically check timeout
        if (++iteration_count % CHECK_INTERVAL == 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
            if (static_cast<uint64_t>(elapsed) > timeout_ms) {
                return false;  // Timed out
            }
        }
        
        uint16_t current = path[path_len - 1];
        
        // Check whether a full cycle is found
        if (path_len == graph_size) {
            if (g_worker_edges[current][0]) {
                return true;  // Hamiltonian cycle found
            }
            // Backtrack
            path_len--;
            g_in_path[current] = false;
            continue;
        }
        
        // Try the next neighbor starting from next_neighbor[path_len - 1]
        bool found_next = false;
        for (uint16_t next = g_pos_in_path[path_len - 1]; next < graph_size; next++) {
            if (g_worker_edges[current][next] && !g_in_path[next]) {
                // Record where to continue next time
                g_pos_in_path[path_len - 1] = next + 1;
                // Descend to the next depth
                g_pos_in_path[path_len] = 0;
                path[path_len++] = next;
                g_in_path[next] = true;
                found_next = true;
                break;
            }
        }
        
        if (!found_next) {
            // No more neighbors; backtrack
            path_len--;
            if (path_len > 0) {
                g_in_path[current] = false;
            }
        }
    }
    
    return false;
}

uint16_t HamiltonianSearcherCPU::search_multi(
    const std::string& graph_hash_hex,
    uint16_t graph_size,
    uint16_t percentage_x10,
    uint16_t max_paths,
    uint16_t** out_paths,
    uint16_t* out_path_lens
) {
    (void)max_paths;  // Return only one path
    
    // Generate graph + adjacency lists (using global thread_local arrays).
    uint64_t seed = extract_seed_from_hash_hex(graph_hash_hex);
    generate_worker_graph_with_edges(seed, graph_size, percentage_x10);
    
    // Worker graph is dense (~50%): use DFS in ascending order; the first solution is the ground state.
    uint16_t base_path[MAX_WORKER_GRAPH_SIZE];
    uint16_t base_path_len = 0;
    
    // Try DFS (30ms timeout).
    // On timeout, return no-solution without falling back to Posa (Posa result cannot be reduced).
    if (!search_hamiltonian_cycle_dfs_worker(base_path, base_path_len, graph_size, 30)) {
        return 0;  // DFS timed out or failed; return no solution
    }
    
    // DFS succeeded; the result is already the ground state and needs no reduction.
    uint16_t result_count = 0;
    std::memcpy(out_paths[result_count], base_path, base_path_len * sizeof(uint16_t));
    out_path_lens[result_count] = base_path_len;
    result_count++;
    
    return result_count;
}

void HamiltonianSearcherCPU::generate_graph_v3_from_seed(
    uint64_t seed, uint16_t grid_size, uint16_t percentage_x10,
    bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    std::vector<uint16_t> node_edges_vec[MAX_QUEEN_GRAPH_SIZE]
) {
    size_t gs = static_cast<size_t>(grid_size);
    
    // Initialize
    for (size_t i = 0; i < gs; i++) {
        std::memset(edges[i], 0, gs * sizeof(bool));
        node_edges_vec[i].clear();
    }
    
    constexpr uint64_t range = 1000;
    uint64_t threshold = (static_cast<uint64_t>(percentage_x10) * range) / 1000;
    
    // Inline PRNG to avoid virtual call overhead.
    std::mt19937_64 prng(seed);
    std::uniform_int_distribution<uint64_t> dist(0, range - 1);
    
    for (size_t i = 0; i < gs; i++) {
        for (size_t j = i + 1; j < gs; j++) {
            uint64_t random_value = dist(prng);
            if (random_value < threshold) {
                edges[i][j] = true;
                edges[j][i] = true;
                node_edges_vec[i].push_back(static_cast<uint16_t>(j));
                node_edges_vec[j].push_back(static_cast<uint16_t>(i));
            }
        }
    }
}

void HamiltonianSearcherCPU::reverse_subpath(uint16_t* path, size_t i, size_t j) {
    while (i < j) {
        uint16_t tmp = path[i];
        path[i] = path[j];
        path[j] = tmp;
        i++;
        j--;
    }
}

// ============================================================================
// DFS Hamiltonian cycle search (iterative, avoids stack overflow).
// Matches the Rust implementation: visit nodes in ascending order.
// The first solution found is the ground state and needs no reduction.
// Suitable for dense small graphs (queen graph ~100 nodes).
// ============================================================================
static bool search_hamiltonian_cycle_dfs(
    uint16_t* path,
    uint16_t& path_len,
    uint16_t graph_size,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE]
) {
    (void)node_edges;  // Adjacency lists not used
    
    bool visited[MAX_QUEEN_GRAPH_SIZE] = {false};
    // next_neighbor[i] stores the next neighbor index to try at depth i.
    uint16_t next_neighbor[MAX_QUEEN_GRAPH_SIZE] = {0};
    
    path_len = 0;
    path[path_len++] = 0;
    visited[0] = true;
    
    while (path_len > 0) {
        uint16_t current = path[path_len - 1];
        
        // Check whether a full cycle is found
        if (path_len == graph_size) {
            if (edges[current][0]) {
                return true;  // Hamiltonian cycle found
            }
            // Backtrack
            path_len--;
            visited[current] = false;
            continue;
        }
        
        // Try the next neighbor starting from next_neighbor[path_len - 1]
        bool found_next = false;
        for (uint16_t next = next_neighbor[path_len - 1]; next < graph_size; next++) {
            if (edges[current][next] && !visited[next]) {
                // Record where to continue next time (after backtracking)
                next_neighbor[path_len - 1] = next + 1;
                // Descend to the next depth
                next_neighbor[path_len] = 0;
                path[path_len++] = next;
                visited[next] = true;
                found_next = true;
                break;
            }
        }
        
        if (!found_next) {
            // No more neighbors; backtrack
            path_len--;
            if (path_len > 0) {
                visited[current] = false;
            }
        }
    }
    
    return false;
}

// Posa's rotation-extension algorithm.
// Core idea:
// 1) Build a path starting from a vertex and extend as much as possible.
// 2) When extension is impossible, perform a "rotation":
//    If the endpoint connects to some internal vertex v[i],
//    reverse the suffix v[i+1..end] so the new endpoint changes.
// 3) This finds Hamiltonian paths with high probability in polynomial time.
bool HamiltonianSearcherCPU::posa_rotation_extension(
    uint16_t path[MAX_QUEEN_GRAPH_SIZE],
    uint16_t& path_len,
    const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE],
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    uint16_t graph_size
) {
    // Random number generator
    static thread_local std::mt19937 rng(std::random_device{}());
    
    // in_path: marks whether a node is in the current path
    bool in_path[MAX_QUEEN_GRAPH_SIZE] = {false};
    // pos_in_path: records each node's index within the path (for fast lookup)
    uint16_t pos_in_path[MAX_QUEEN_GRAPH_SIZE] = {0};
    
    // Collect candidate rotation points
    uint16_t rotation_candidates[MAX_QUEEN_GRAPH_SIZE];
    uint16_t rotation_count = 0;
    
    // Start from node 0
    path_len = 0;
    path[path_len++] = 0;
    in_path[0] = true;
    pos_in_path[0] = 0;
    
    // Maximum iteration limit
    const uint64_t max_iterations = static_cast<uint64_t>(graph_size) * graph_size * 100;
    uint64_t iteration_count = 0;
    size_t stuck_counter = 0;
    const size_t max_stuck = graph_size * 10;
    
    while (path_len < graph_size) {
        if (++iteration_count > max_iterations) {
            return false;
        }
        
        uint16_t endpoint = path[path_len - 1];
        bool extended = false;
        
        // Try to extend: find a neighbor not in the path.
        // Randomize order to increase exploration diversity.
        size_t neighbor_count = node_edges[endpoint].size();
        size_t start_idx = neighbor_count == 0 ? 0 : rng() % neighbor_count;
        
        for (size_t i = 0; i < neighbor_count; i++) {
            uint16_t neighbor = node_edges[endpoint][(start_idx + i) % neighbor_count];
            if (!in_path[neighbor]) {
                pos_in_path[neighbor] = path_len;
                path[path_len++] = neighbor;
                in_path[neighbor] = true;
                extended = true;
                stuck_counter = 0;
                break;
            }
        }
        
        if (extended) continue;
        
        // Cannot extend; rotate.
        // Collect all rotation points: nodes in the path adjacent to endpoint.
        rotation_count = 0;
        for (size_t ni = 0; ni < node_edges[endpoint].size(); ni++) {
            uint16_t neighbor = node_edges[endpoint][ni];
            if (!in_path[neighbor]) continue;
            uint16_t neighbor_pos = pos_in_path[neighbor];
            // neighbor cannot be the last or second-to-last node
            if (neighbor_pos < path_len - 2) {
                rotation_candidates[rotation_count++] = neighbor_pos;
            }
        }
        
        if (rotation_count == 0) {
            // No rotation point; reverse the whole path and try from the other end.
            reverse_subpath(path, 0, path_len - 1);
            for (uint16_t k = 0; k < path_len; k++) {
                pos_in_path[path[k]] = k;
            }
            
            stuck_counter++;
            if (stuck_counter > max_stuck) {
                // Both ends got stuck too many times; give up.
                return false;
            }
            continue;
        }
        
        // Randomly pick a rotation point
        size_t rand_idx = rng() % rotation_count;
        uint16_t rotate_pos = rotation_candidates[rand_idx];
        
        // Perform rotation: reverse [rotate_pos+1, path_len-1]
        reverse_subpath(path, rotate_pos + 1, path_len - 1);
        
        // Update pos_in_path
        for (uint16_t k = rotate_pos + 1; k < path_len; k++) {
            pos_in_path[path[k]] = k;
        }
        
        stuck_counter = 0;
    }
    
    // Path includes all nodes; check whether it can close into a cycle.
    // Note: path[0] may not be node 0 due to earlier reversals.
    uint16_t first_node = path[0];
    uint16_t last_node = path[path_len - 1];
    
    // Check whether last_node is adjacent to first_node
    if (edges[last_node][first_node]) {
        return true;
    }
    
    // Try multiple rotations to close the cycle
    for (size_t attempts = 0; attempts < static_cast<size_t>(graph_size) * 10; attempts++) {
        last_node = path[path_len - 1];
        first_node = path[0];
        
        if (edges[last_node][first_node]) {
            return true;
        }
        
        // Collect current rotation points
        rotation_count = 0;
        for (size_t ni = 0; ni < node_edges[last_node].size(); ni++) {
            uint16_t neighbor = node_edges[last_node][ni];
            uint16_t neighbor_pos = pos_in_path[neighbor];
            if (neighbor_pos < path_len - 2 && neighbor_pos > 0) {
                rotation_candidates[rotation_count++] = neighbor_pos;
            }
        }
        
        if (rotation_count == 0) {
            // Reverse the whole path and try the other end
            reverse_subpath(path, 0, path_len - 1);
            for (uint16_t k = 0; k < path_len; k++) {
                pos_in_path[path[k]] = k;
            }
            continue;
        }
        
        // Prefer a rotation that makes a neighbor of first_node closer to the end.
        uint16_t best_rotate = rotation_candidates[rng() % rotation_count];
        
        for (uint16_t ci = 0; ci < rotation_count; ci++) {
            uint16_t candidate = rotation_candidates[ci];
            // After rotation, the old path[candidate+1] becomes the new second-to-last node.
            // Check whether this rotation could get us closer to closing the cycle.
            uint16_t potential_new_end = path[candidate + 1];
            if (edges[potential_new_end][first_node]) {
                // This rotation puts us close to closing the cycle.
                best_rotate = candidate;
                break;
            }
        }
        
        // Perform rotation
        reverse_subpath(path, best_rotate + 1, path_len - 1);
        for (uint16_t k = best_rotate + 1; k < path_len; k++) {
            pos_in_path[path[k]] = k;
        }
    }
    
    return edges[path[path_len - 1]][path[0]];
}

// ============================================================================
// N^2 reduction: reduce a cycle to the ground state.
// Rule: if there exists (i, j) such that edges[path[i]][path[j]] && edges[path[i+1]][path[j+1]]
//       and path[j] < path[i+1], perform a 2-opt swap (reverse i+1..j).
// ============================================================================

// Check whether the cycle still has a reducible pair.
// Returns true if a reducible pair exists (not ground state).
// Returns false if it is already in ground state.
static bool has_reducible_pair(
    const uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE]
) {
    for (uint16_t i = 0; i < path_len - 1; i++) {
        uint16_t i_next = (i + 1) % path_len;
        uint16_t node_i = path[i];
        uint16_t node_i_next = path[i_next];
        
        for (uint16_t j = i + 1; j < path_len; j++) {
            uint16_t j_next = (j + 1) % path_len;
            uint16_t node_j = path[j];
            uint16_t node_j_next = path[j_next];
            
            // Check whether both edges exist
            if (edges[node_i][node_j] && edges[node_i_next][node_j_next]) {
                // Check whether the reduction condition holds
                if (node_j < node_i_next) {
                    // Reducible pair exists
                    // fprintf(stderr, "[DEBUG] Reducible pair found: i=%u, j=%u, path[i]=%u, path[i+1]=%u, path[j]=%u, path[j+1]=%u\n",
                    //         i, j, node_i, node_i_next, node_j, node_j_next);
                    return true;
                }
            }
        }
    }
    return false;
}

// Verify whether a path is reduced to the ground state.
// If it is not in ground state, print a warning and return false.
static bool verify_ground_state(
    const uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    const char* context = nullptr
) {
    if (has_reducible_pair(path, path_len, edges)) {
        if (context) {
            fprintf(stderr, "[VERIFY FAILED] %s: Path is NOT in ground state!\n", context);
        } else {
            fprintf(stderr, "[VERIFY FAILED] Path is NOT in ground state!\n");
        }
        return false;
    }
    return true;
}

// ============================================================================
// Doubly-linked list variant: straightforward design
// 1) Track node 0 and its forward direction (forward_next)
// 2) Traverse from node 0 along forward direction to find A and A_next
// 3) Continue from A_next to find B and B_next
// 4) If edges[A][B] && edges[A_next][B_next] && B < A_next, perform 2-opt
// 5) Repeat until no swappable pair remains
// ============================================================================

static void reduce_to_ground_state_doubly_linked(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    [[maybe_unused]] const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE],
    bool verify = false
) {
    // Each node stores two neighbors
    uint16_t neighbor[MAX_QUEEN_GRAPH_SIZE][2];
    
    // Build the linked structure from the initial path
    for (uint16_t i = 0; i < path_len; i++) {
        uint16_t node = path[i];
        neighbor[node][0] = path[(i + path_len - 1) % path_len];
        neighbor[node][1] = path[(i + 1) % path_len];
    }
    
    // Get the other neighbor
    auto get_other = [&neighbor](uint16_t node, uint16_t from) -> uint16_t {
        return (neighbor[node][0] == from) ? neighbor[node][1] : neighbor[node][0];
    };
    
    // Update neighbor: replace node's neighbor old_nbr with new_nbr
    auto update_neighbor = [&neighbor](uint16_t node, uint16_t old_nbr, uint16_t new_nbr) {
        if (neighbor[node][0] == old_nbr) {
            neighbor[node][0] = new_nbr;
        } else {
            neighbor[node][1] = new_nbr;
        }
    };
    
    // Node 0 is the fixed start; forward_next is the next node in the forward direction.
    const uint16_t start_node = 0;    // path[0] is always node 0
    uint16_t forward_next = path[1];  // path[1] is the forward direction
    
    bool changed = true;
    while (changed) {
        changed = false;
        
        // Outer loop: start from node 0 and traverse A along the forward direction
        uint16_t prev_a = neighbor[start_node][0];  // Reverse direction (path[n-1])
        if (prev_a == forward_next) {
            prev_a = neighbor[start_node][1];  // Use the other as reverse direction
        }
        uint16_t node_a = start_node;
        uint16_t node_a_next = forward_next;
        
        // Traverse all positions as A (from 0 to n-2)
        for (uint16_t pos_a = 0; pos_a < path_len - 1 && !changed; pos_a++) {
            // Inner loop: start from the node after A_next and traverse B
            uint16_t prev_b = node_a_next;
            uint16_t node_b = get_other(node_a_next, node_a);
            
            // Traverse up to the second-to-last position (cannot wrap back to A)
            for (uint16_t pos_b = pos_a + 2; pos_b < path_len && !changed; pos_b++) {
                uint16_t node_b_next = get_other(node_b, prev_b);
                
                // Check whether the two new edges exist and the reduction condition holds
                if (edges[node_a][node_b] && edges[node_a_next][node_b_next]) {
                    if (node_b < node_a_next) {
                        // Perform 2-opt: update 4 edges
                        update_neighbor(node_a, node_a_next, node_b);
                        update_neighbor(node_b, node_b_next, node_a);
                        update_neighbor(node_a_next, node_a, node_b_next);
                        update_neighbor(node_b_next, node_b, node_a_next);
                        
                        // If A is node 0, forward_next must be updated to B
                        if (node_a == start_node) {
                            forward_next = node_b;
                        }
                        
                        changed = true;
                    }
                }
                
                // Move to the next B
                prev_b = node_b;
                node_b = node_b_next;
            }
            
            // Move to the next A
            prev_a = node_a;
            node_a = node_a_next;
            node_a_next = get_other(node_a, prev_a);
        }
    }
    
    // Rebuild the path array from the linked structure (start at node 0, follow forward direction)
    uint16_t prev = neighbor[start_node][0];
    if (prev == forward_next) {
        prev = neighbor[start_node][1];
    }
    uint16_t curr = start_node;
    for (uint16_t i = 0; i < path_len; i++) {
        path[i] = curr;
        uint16_t next = get_other(curr, prev);
        prev = curr;
        curr = next;
    }
    
    // Verify the reduction result (controlled by parameter)
    if (verify && !verify_ground_state(path, path_len, edges, "reduce_to_ground_state_doubly_linked")) {
        fprintf(stderr, "[ERROR] Doubly-linked reduction failed to reach ground state!\n");
    }
}

// Optimized variant: use node_index reverse mapping + adjacency lists for speed.
// Core idea: traverse neighbors of path[i] instead of all j.
// verify: whether to verify after reduction (for debugging)
static void reduce_to_ground_state_optimized(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE],
    bool verify = false
) {
    // Build reverse mapping node -> position
    uint16_t node_index[MAX_QUEEN_GRAPH_SIZE];
    for (uint16_t i = 0; i < path_len; i++) {
        node_index[path[i]] = i;
    }
    
    bool changed = true;
    while (changed) {
        changed = false;
        for (uint16_t i = 0; i < path_len - 1; i++) {
            uint16_t i_next = (i + 1) % path_len;
            uint16_t node_i = path[i];
            uint16_t node_i_next = path[i_next];
            
            // Traverse neighbors of node_i (instead of all j)
            for (uint16_t neighbor : node_edges[node_i]) {
                uint16_t j = node_index[neighbor];
                
                // Require j > i (avoid duplicate checks)
                if (j <= i) continue;
                
                uint16_t j_next = (j + 1) % path_len;
                uint16_t node_j_next = path[j_next];
                
                // Check whether the other edge exists
                if (edges[node_i_next][node_j_next]) {
                    // Check whether reduction is needed (ground-state condition: path[j] < path[i_next])
                    if (neighbor < node_i_next) {
                        // Perform 2-opt: reverse path[i+1..j]
                        HamiltonianSearcherCPU::reverse_subpath(path, i_next, j);
                        
                        // Update node_index (positions within the reversed segment changed)
                        for (uint16_t k = i_next; k <= j; k++) {
                            node_index[path[k]] = k;
                        }
                        
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) break;
        }
    }
    
    // Verify the reduction result (controlled by parameter)
    if (verify && !verify_ground_state(path, path_len, edges, "reduce_to_ground_state_optimized")) {
        fprintf(stderr, "[ERROR] Optimized reduction failed to reach ground state!\n");
    }
}

// Original variant (no adjacency lists; kept as a fallback)
static void reduce_to_ground_state(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE]
) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (uint16_t i = 0; i < path_len - 1; i++) {
            for (uint16_t j = i + 1; j < path_len; j++) {
                uint16_t i_next = (i + 1) % path_len;
                uint16_t j_next = (j + 1) % path_len;
                
                // Check whether the new edges exist
                if (edges[path[i]][path[j]] && edges[path[i_next]][path[j_next]]) {
                    // Check whether reduction is needed
                    if (path[j] < path[i_next]) {
                        // Perform 2-opt: reverse path[i+1..j]
                        HamiltonianSearcherCPU::reverse_subpath(path, i_next, j);
                        changed = true;
                        break;  // Restart scanning from the beginning
                    }
                }
            }
            if (changed) break;
        }
    }
}

// ============================================================================
// Node-order reduction variant
// Strategy: outer loop iterates B by node id ascending (starting at 1), inner loop scans A from position 0.
// Advantage: smaller node ids get "fixed" earlier, reducing repeated checks.
// ============================================================================
static void reduce_to_ground_state_by_node_order(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    bool verify = false
) {
    // node_pos[node] = position of node within the path
    uint16_t node_pos[MAX_QUEEN_GRAPH_SIZE];
    for (uint16_t i = 0; i < path_len; i++) {
        node_pos[path[i]] = i;
    }
    
    bool changed = true;
    while (changed) {
        changed = false;
        
        // Outer loop: iterate B by node id ascending (start at 1; node 0 is always at position 0)
        for (uint16_t node_b = 1; node_b < path_len && !changed; node_b++) {
            uint16_t pos_b = node_pos[node_b];
            uint16_t pos_b_next = (pos_b + 1) % path_len;
            uint16_t node_b_next = path[pos_b_next];
            
            // Inner loop: scan A from position 0 up to position < pos_b
            for (uint16_t pos_a = 0; pos_a < pos_b && !changed; pos_a++) {
                uint16_t pos_a_next = pos_a + 1;  // No mod needed because pos_a < pos_b < path_len
                uint16_t node_a = path[pos_a];
                uint16_t node_a_next = path[pos_a_next];
                
                // Reduction condition: edges[A][B] && edges[A_next][B_next] && B < A_next
                if (edges[node_a][node_b] && edges[node_a_next][node_b_next]) {
                    if (node_b < node_a_next) {
                        // Perform 2-opt: reverse path[pos_a+1..pos_b]
                        HamiltonianSearcherCPU::reverse_subpath(path, pos_a_next, pos_b);
                        
                        // Update node_pos: positions within the reversed segment changed
                        for (uint16_t k = pos_a_next; k <= pos_b; k++) {
                            node_pos[path[k]] = k;
                        }
                        
                        changed = true;
                    }
                }
            }
        }
    }
    
    // Verify the reduction result (controlled by parameter)
    if (verify && !verify_ground_state(path, path_len, edges, "reduce_to_ground_state_by_node_order")) {
        fprintf(stderr, "[ERROR] Node-order reduction failed to reach ground state!\n");
    }
}

// Worker-graph reduction variant (uses global g_worker_edges).
// For large graphs (N≈1920), full reduction can be slow; use adjacency lists for speed.
static void reduce_to_ground_state_worker(
    uint16_t* path,
    uint16_t path_len,
    const bool edges[][2048]
) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (uint16_t i = 0; i < path_len - 1; i++) {
            uint16_t i_next = (i + 1) % path_len;
            uint16_t node_i = path[i];
            uint16_t node_i_next = path[i_next];
            
            for (uint16_t j = i + 2; j < path_len; j++) {
                uint16_t j_next = (j + 1) % path_len;
                uint16_t node_j = path[j];
                uint16_t node_j_next = path[j_next];
                
                // Check whether the 2-opt swap is feasible
                if (edges[node_i][node_j] && edges[node_i_next][node_j_next]) {
                    // Check whether reduction is needed (ground-state condition)
                    if (node_j < node_i_next) {
                        // Perform 2-opt: reverse path[i+1..j]
                        HamiltonianSearcherCPU::reverse_subpath(path, i_next, j);
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) break;
        }
    }
}

bool HamiltonianSearcherCPU::check_solution(
    const uint16_t* queen_path,
    uint16_t queen_path_len,
    const uint16_t* worker_path,
    uint16_t worker_path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    uint16_t graph_size,
    const std::string& data_hex,
    const std::string& target_hex,
    uint64_t& hash_count,
    uint16_t* out_combined_path,
    uint16_t& out_combined_path_len,
    std::string& out_solution_hex,
    SolutionCallback callback
) {
    // // ========== Cycle validity verification ==========
    // {
    //     // 1) Check path length
    //     if (queen_path_len != graph_size) {
    //         fprintf(stderr, "[check_solution] ERROR: path length %u != graph_size %u\n",
    //                 queen_path_len, graph_size);
    //         return false;
    //     }
        
    //     // 2) Check node uniqueness
    //     bool visited[MAX_QUEEN_GRAPH_SIZE] = {false};
    //     for (uint16_t i = 0; i < queen_path_len; i++) {
    //         uint16_t node = queen_path[i];
    //         if (node >= graph_size) {
    //             fprintf(stderr, "[check_solution] ERROR: node %u out of range\n", node);
    //             return false;
    //         }
    //         if (visited[node]) {
    //             fprintf(stderr, "[check_solution] ERROR: node %u duplicated\n", node);
    //             return false;
    //         }
    //         visited[node] = true;
    //     }
        
    //     // 3) Check path continuity (edge exists between adjacent nodes)
    //     for (uint16_t i = 0; i < queen_path_len - 1; i++) {
    //         if (!edges[queen_path[i]][queen_path[i + 1]]) {
    //             fprintf(stderr, "[check_solution] ERROR: no edge %u -> %u\n",
    //                     queen_path[i], queen_path[i + 1]);
    //             return false;
    //         }
    //     }
        
    //     // 4) Check cycle closure
    //     if (!edges[queen_path[queen_path_len - 1]][queen_path[0]]) {
    //         fprintf(stderr, "[check_solution] ERROR: no closing edge %u -> %u\n",
    //                 queen_path[queen_path_len - 1], queen_path[0]);
    //         return false;
    //     }
    // }
    // // ========== Verification passed ==========
    
    // Combine worker_path + queen_path
    uint16_t combined_path[HC_GRAPH_SIZE];
    uint16_t combined_len = 0;
    
    // Copy worker_path
    std::memcpy(combined_path, worker_path, worker_path_len * sizeof(uint16_t));
    combined_len = worker_path_len;
    
    // Append queen_path
    std::memcpy(combined_path + combined_len, queen_path, queen_path_len * sizeof(uint16_t));
    combined_len += queen_path_len;
    
    // Pad up to HC_GRAPH_SIZE
    for (uint16_t i = combined_len; i < HC_GRAPH_SIZE; i++) {
        combined_path[i] = 0xFFFF;
    }
    combined_len = HC_GRAPH_SIZE;
    
    // Convert to a little-endian hex string
    std::string solution_hex;
    solution_hex.reserve(HC_GRAPH_SIZE * 4);
    static const char hex_chars[] = "0123456789abcdef";
    for (uint16_t i = 0; i < HC_GRAPH_SIZE; i++) {
        uint16_t val = combined_path[i];
        uint8_t lo = val & 0xff;
        uint8_t hi = (val >> 8) & 0xff;
        solution_hex.push_back(hex_chars[lo >> 4]);
        solution_hex.push_back(hex_chars[lo & 0xf]);
        solution_hex.push_back(hex_chars[hi >> 4]);
        solution_hex.push_back(hex_chars[hi & 0xf]);
    }
    
    // Build full payload: data + solution
    std::string full_data_hex = data_hex + solution_hex;
    uint8_t data_bytes[8192];  // Large enough buffer
    size_t data_bytes_len;
    hex_to_bytes(full_data_hex, data_bytes, &data_bytes_len);
    
    // Compute SHA256
    uint8_t hash[32];
    sha256(data_bytes, data_bytes_len, hash);
    
    // Reverse hash (to match Rust's reversed behavior)
    uint8_t hash_reversed[32];
    for (int i = 0; i < 32; i++) {
        hash_reversed[i] = hash[31 - i];
    }
    std::string hash_hex = bytes_to_hex(hash_reversed, 32);
    
    hash_count++;
    
    // Check whether it meets the target difficulty
    if (meets_target(hash_hex, target_hex)) {
        std::memcpy(out_combined_path, combined_path, combined_len * sizeof(uint16_t));
        out_combined_path_len = combined_len;
        out_solution_hex = solution_hex;
        
        if (callback) {
            return callback(combined_path, combined_len, solution_hex);
        }
        return true;
    }
    
    return false;
}

// reduce_and_check_solution - copy the path, reduce to ground state, then check difficulty.
// Does not modify the original queen_path; makes an internal copy for reduction.
// Uses a bloom filter for deduplication to avoid redundant hashing.
static bool reduce_and_check_solution(
    const uint16_t* queen_path,
    uint16_t queen_path_len,
    const uint16_t* worker_path,
    uint16_t worker_path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE],
    const std::string& data_hex,
    const std::string& target_hex,
    uint64_t& hash_count,
    uint16_t* out_combined_path,
    uint16_t& out_combined_path_len,
    std::string& out_solution_hex,
    BloomFilter& bloom  // Bloom filter reference
) {
    // Copy queen_path because reduction mutates the path
    uint16_t reduced_path[MAX_QUEEN_GRAPH_SIZE];
    std::memcpy(reduced_path, queen_path, queen_path_len * sizeof(uint16_t));
    
    // Reduce to ground state (optimized variant)
    // reduce_to_ground_state_optimized(reduced_path, queen_path_len, edges, node_edges, true);
    reduce_to_ground_state_optimized(reduced_path, queen_path_len, edges, node_edges);
    
    // Use bloom filter to check whether this reduced path was already processed
    if (!bloom.check_and_add(reduced_path, queen_path_len)) {
        // Same ground-state path already processed; skip
        return false;
    }
    
    // Combine worker_path + reduced_path directly into combined_path
    uint16_t combined_path[HC_GRAPH_SIZE];
    
    // Copy worker_path
    std::memcpy(combined_path, worker_path, worker_path_len * sizeof(uint16_t));
    // Append reduced_path
    std::memcpy(combined_path + worker_path_len, reduced_path, queen_path_len * sizeof(uint16_t));
    // Pad the remaining part
    uint16_t combined_len = worker_path_len + queen_path_len;
    std::memset(combined_path + combined_len, 0xFF, (HC_GRAPH_SIZE - combined_len) * sizeof(uint16_t));
    
    // Decode data_hex directly into the data_bytes buffer
    uint8_t data_bytes[8192];
    size_t data_hex_len = data_hex.length();
    size_t data_bytes_len = data_hex_len / 2;
    const char* data_ptr = data_hex.data();
    
    for (size_t i = 0; i < data_bytes_len; i++) {
        data_bytes[i] = (HEX_LOOKUP[(uint8_t)data_ptr[i*2]] << 4) | 
                         HEX_LOOKUP[(uint8_t)data_ptr[i*2+1]];
    }
    
    // Append combined_path directly to data_bytes
    constexpr size_t solution_bytes_len = HC_GRAPH_SIZE * 2;
    std::memcpy(data_bytes + data_bytes_len, combined_path, solution_bytes_len);
    
    size_t total_bytes_len = data_bytes_len + solution_bytes_len;
    
    // Compute SHA256 (via OpenSSL)
    uint8_t hash[32];
    sha256_openssl(data_bytes, total_bytes_len, hash);
    
    // Check whether it meets the target difficulty
    uint8_t target_bytes[32];
    const char* target_ptr = target_hex.data();
    for (int i = 0; i < 32; i++) {
        target_bytes[i] = (HEX_LOOKUP[(uint8_t)target_ptr[i*2]] << 4) | 
                           HEX_LOOKUP[(uint8_t)target_ptr[i*2+1]];
    }
    
    bool meets = true;
    for (int i = 0; i < 32; i++) {
        uint8_t h = hash[31 - i];
        uint8_t t = target_bytes[i];
        if (h < t) {
            meets = true;
            break;
        } else if (h > t) {
            meets = false;
            break;
        }
    }
    
    hash_count++;
    
    if (meets) {
        // Build solution_hex
        std::string solution_hex;
        solution_hex.reserve(HC_GRAPH_SIZE * 4);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(combined_path);
        for (size_t i = 0; i < HC_GRAPH_SIZE * 2; i++) {
            solution_hex.push_back(HEX_CHARS[bytes[i] >> 4]);
            solution_hex.push_back(HEX_CHARS[bytes[i] & 0xf]);
        }
        
        std::memcpy(out_combined_path, combined_path, HC_GRAPH_SIZE * sizeof(uint16_t));
        out_combined_path_len = HC_GRAPH_SIZE;
        out_solution_hex = std::move(solution_hex);
        return true;
    }
    
    return false;
}

// check_solution2 - optimized version (OpenSSL SHA256)
bool HamiltonianSearcherCPU::check_solution2(
    const uint16_t* queen_path,
    uint16_t queen_path_len,
    const uint16_t* worker_path,
    uint16_t worker_path_len,
    const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
    uint16_t graph_size,
    const std::string& data_hex,
    const std::string& target_hex,
    uint64_t& hash_count,
    uint16_t* out_combined_path,
    uint16_t& out_combined_path_len,
    std::string& out_solution_hex,
    SolutionCallback callback
) {
    // Combine worker_path + queen_path directly into combined_path
    uint16_t combined_path[HC_GRAPH_SIZE];
    
    // Copy worker_path
    std::memcpy(combined_path, worker_path, worker_path_len * sizeof(uint16_t));
    // Append queen_path
    std::memcpy(combined_path + worker_path_len, queen_path, queen_path_len * sizeof(uint16_t));
    // Pad the remaining part (optimized with memset)
    uint16_t combined_len = worker_path_len + queen_path_len;
    std::memset(combined_path + combined_len, 0xFF, (HC_GRAPH_SIZE - combined_len) * sizeof(uint16_t));
    
    // Decode data_hex directly into the data_bytes buffer
    uint8_t data_bytes[8192];
    size_t data_hex_len = data_hex.length();
    size_t data_bytes_len = data_hex_len / 2;
    const char* data_ptr = data_hex.data();
    
    for (size_t i = 0; i < data_bytes_len; i++) {
        data_bytes[i] = (HEX_LOOKUP[(uint8_t)data_ptr[i*2]] << 4) | 
                         HEX_LOOKUP[(uint8_t)data_ptr[i*2+1]];
    }
    
    // Append combined_path directly to data_bytes.
    // x86/x64 is little-endian, so uint16_t[] is laid out as [low, high, low, high, ...].
    // This matches the previous loop logic and allows a direct memcpy.
    constexpr size_t solution_bytes_len = HC_GRAPH_SIZE * 2;  // 2 bytes per uint16_t
    std::memcpy(data_bytes + data_bytes_len, combined_path, solution_bytes_len);
    
    size_t total_bytes_len = data_bytes_len + solution_bytes_len;
    
    // Compute SHA256 (via OpenSSL)
    uint8_t hash[32];
    sha256_openssl(data_bytes, total_bytes_len, hash);
    
    // Check whether it meets the target difficulty by comparing bytes directly.
    // target_hex is 64 hex chars => 32 bytes
    // Decode target_hex into bytes for comparison.
    uint8_t target_bytes[32];
    const char* target_ptr = target_hex.data();
    for (int i = 0; i < 32; i++) {
        target_bytes[i] = (HEX_LOOKUP[(uint8_t)target_ptr[i*2]] << 4) | 
                           HEX_LOOKUP[(uint8_t)target_ptr[i*2+1]];
    }
    
    // Compare reversed hash bytes with target_bytes
    // hash_reversed[i] = hash[31-i]
    bool meets = true;
    for (int i = 0; i < 32; i++) {
        uint8_t h = hash[31 - i];  // reversed
        uint8_t t = target_bytes[i];
        if (h < t) {
            meets = true;
            break;
        } else if (h > t) {
            meets = false;
            break;
        }
        // If equal, continue to compare the next byte
    }
    
    hash_count++;
    
    if (meets) {
        // Build solution_hex (only when it meets difficulty)
        std::string solution_hex;
        solution_hex.reserve(HC_GRAPH_SIZE * 4);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(combined_path);
        for (size_t i = 0; i < HC_GRAPH_SIZE * 2; i++) {
            solution_hex.push_back(HEX_CHARS[bytes[i] >> 4]);
            solution_hex.push_back(HEX_CHARS[bytes[i] & 0xf]);
        }
        
        std::memcpy(out_combined_path, combined_path, HC_GRAPH_SIZE * sizeof(uint16_t));
        out_combined_path_len = HC_GRAPH_SIZE;
        out_solution_hex = std::move(solution_hex);
        
        if (callback) {
            return callback(combined_path, HC_GRAPH_SIZE, out_solution_hex);
        }
        return true;
    }
    
    return false;
}

SearchResult HamiltonianSearcherCPU::search_second(
    const std::string& graph_hash_hex,
    uint16_t graph_size,
    uint16_t percentage_x10,
    uint64_t timeout_ms,
    const uint16_t* worker_path,
    uint16_t worker_path_len,
    const std::string& data_hex,
    const std::string& target_hex,
    SolutionCallback callback,
    const uint64_t* job_version,
    uint64_t expected_version
) {
    SearchResult result;
    result.found = false;
    result.cancelled = false;
    result.path_len = 0;
    result.hash_count = 0;
    result.graph_gen_us = 0;
    result.dfs_us = 0;
    result.total_us = 0;
    
    // Helper macro: check job version change or global shutdown
    #define CHECK_JOB_CANCELLED() \
        if (g_shutdown.load(std::memory_order_relaxed) || \
            (job_version && __atomic_load_n(job_version, __ATOMIC_SEQ_CST) != expected_version)) { \
            result.cancelled = true; \
            return result; \
        }

    // Extract seed and generate graph + adjacency lists
    uint64_t seed = extract_seed_from_hash_hex(graph_hash_hex);
    bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE];
    std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE];
    generate_graph_v3_from_seed(seed, graph_size, percentage_x10, edges, node_edges);
    
    // Queen graph is sparse (~12.5%); use Posa rotation-extension search.
    uint16_t path[MAX_QUEEN_GRAPH_SIZE];
    uint16_t path_len = 0;
    
    if (!posa_rotation_extension(path, path_len, node_edges, edges, graph_size)) {
        return result;
    }
    
    // // ========== Cycle correctness validation ==========
    // {
    //     bool valid = true;
    //     std::string error_msg;
        
    //     // 1) Check whether path length equals graph_size
    //     if (path_len != graph_size) {
    //         valid = false;
    //         fprintf(stderr, "[C++ HC2] VALIDATION ERROR: path length %u != graph_size %u\n", 
    //                 path_len, graph_size);
    //     }
        
    //     // 2) Check each node appears exactly once (no duplicates, no missing)
    //     if (valid) {
    //         bool node_visited[MAX_QUEEN_GRAPH_SIZE] = {false};
    //         for (uint16_t i = 0; i < path_len; i++) {
    //             uint16_t node = path[i];
    //             if (node >= graph_size) {
    //                 valid = false;
    //                 fprintf(stderr, "[C++ HC2] VALIDATION ERROR: node %u at pos %u out of range [0,%u)\n",
    //                         node, i, graph_size);
    //                 break;
    //             }
    //             if (node_visited[node]) {
    //                 valid = false;
    //                 fprintf(stderr, "[C++ HC2] VALIDATION ERROR: node %u appears more than once (duplicate at pos %u)\n",
    //                         node, i);
    //                 break;
    //             }
    //             node_visited[node] = true;
    //         }
            
    //         // Check whether all nodes were visited
    //         if (valid) {
    //             for (uint16_t i = 0; i < graph_size; i++) {
    //                 if (!node_visited[i]) {
    //                     valid = false;
    //                     fprintf(stderr, "[C++ HC2] VALIDATION ERROR: node %u was not visited\n", i);
    //                     break;
    //                 }
    //             }
    //         }
    //     }
        
    //     // 3) Check path continuity (edge must exist between adjacent nodes)
    //     if (valid) {
    //         for (uint16_t i = 0; i < path_len - 1; i++) {
    //             if (!edges[path[i]][path[i + 1]]) {
    //                 valid = false;
    //                 fprintf(stderr, "[C++ HC2] VALIDATION ERROR: no edge between path[%u]=%u and path[%u]=%u\n",
    //                         i, path[i], i + 1, path[i + 1]);
    //                 break;
    //             }
    //         }
    //     }
        
    //     // 4) Check cycle closure (last node must connect to first node)
    //     if (valid) {
    //         if (!edges[path[path_len - 1]][path[0]]) {
    //             valid = false;
    //             fprintf(stderr, "[C++ HC2] VALIDATION ERROR: no closing edge between last node %u and first node %u\n",
    //                     path[path_len - 1], path[0]);
    //         }
    //     }
        
    //     if (!valid) {
    //         fprintf(stderr, "[C++ HC2] Hamiltonian cycle validation FAILED!\n");
    //         return result;
    //     }
    // }
    // // ========== Validation passed ==========
    
    // Precompute node_index: reverse map node id -> position in path
    uint16_t node_index[MAX_QUEEN_GRAPH_SIZE];
    for (uint16_t i = 0; i < path_len; i++) {
        node_index[path[i]] = i;
    }
    
    uint64_t hash_count_local = 0;
    uint16_t out_path[HC_GRAPH_SIZE];
    uint16_t out_path_len = 0;
    std::string out_hex;
    
    // Create a bloom filter for deduplicating reduced paths
    BloomFilter bloom;
    
    // ========== First, reduce the base path to ground state ==========
    // Copy path into base_reduced_path for reduction
    uint16_t base_reduced_path[MAX_QUEEN_GRAPH_SIZE];
    std::memcpy(base_reduced_path, path, path_len * sizeof(uint16_t));
    reduce_to_ground_state_by_node_order(base_reduced_path, path_len, edges, false);
    
    // Check the reduced base path first.
    // Directly check difficulty (no further reduction needed; already in ground state).
    {
        // Combine worker_path + base_reduced_path
        uint16_t combined_path[HC_GRAPH_SIZE];
        std::memcpy(combined_path, worker_path, worker_path_len * sizeof(uint16_t));
        std::memcpy(combined_path + worker_path_len, base_reduced_path, path_len * sizeof(uint16_t));
        uint16_t combined_len = worker_path_len + path_len;
        std::memset(combined_path + combined_len, 0xFF, (HC_GRAPH_SIZE - combined_len) * sizeof(uint16_t));
        
        // Add to bloom filter
        bloom.insert(base_reduced_path, path_len);
        
        // Decode data_hex
        uint8_t data_bytes[8192];
        size_t data_bytes_len = data_hex.length() / 2;
        const char* data_ptr = data_hex.data();
        for (size_t i = 0; i < data_bytes_len; i++) {
            data_bytes[i] = (HEX_LOOKUP[(uint8_t)data_ptr[i*2]] << 4) | 
                             HEX_LOOKUP[(uint8_t)data_ptr[i*2+1]];
        }
        
        // Append combined_path
        constexpr size_t solution_bytes_len = HC_GRAPH_SIZE * 2;
        std::memcpy(data_bytes + data_bytes_len, combined_path, solution_bytes_len);
        
        // Compute SHA256
        uint8_t hash[32];
        sha256_openssl(data_bytes, data_bytes_len + solution_bytes_len, hash);
        
        // Check difficulty
        uint8_t target_bytes[32];
        const char* target_ptr = target_hex.data();
        for (int i = 0; i < 32; i++) {
            target_bytes[i] = (HEX_LOOKUP[(uint8_t)target_ptr[i*2]] << 4) | 
                               HEX_LOOKUP[(uint8_t)target_ptr[i*2+1]];
        }
        
        bool meets = true;
        for (int i = 0; i < 32; i++) {
            uint8_t h = hash[31 - i];
            uint8_t t = target_bytes[i];
            if (h < t) { meets = true; break; }
            else if (h > t) { meets = false; break; }
        }
        
        hash_count_local++;
        
        if (meets) {
            // Build solution_hex
            std::string solution_hex;
            solution_hex.reserve(HC_GRAPH_SIZE * 4);
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(combined_path);
            for (size_t i = 0; i < HC_GRAPH_SIZE * 2; i++) {
                solution_hex.push_back(HEX_CHARS[bytes[i] >> 4]);
                solution_hex.push_back(HEX_CHARS[bytes[i] & 0xf]);
            }
            
            result.hash_count += hash_count_local;
            std::memcpy(result.path, combined_path, HC_GRAPH_SIZE * sizeof(uint16_t));
            result.path_len = HC_GRAPH_SIZE;
            result.solution_hex = std::move(solution_hex);
            result.found = true;
            return result;
        }
    }
    
    // Use the reduced base_reduced_path as the baseline for 2-opt.
    // Recompute node_index mapping based on the reduced path.
    for (uint16_t i = 0; i < path_len; i++) {
        node_index[base_reduced_path[i]] = i;
    }
    
    // Apply 2-opt transformations on the reduced path.
    // First-level 2-opt
    for (uint16_t i1 = 1; i1 < path_len - 1; i1++) {
        CHECK_JOB_CANCELLED();
        
        uint16_t node_before_i1 = base_reduced_path[i1 - 1];
        uint16_t node_i1 = base_reduced_path[i1];
        
        // Traverse neighbors of the node at position i1-1
        for (const auto& k1 : node_edges[node_before_i1]) {
            uint16_t j1 = node_index[k1];
            
            // Check position validity: j1 > i1 and j1 < path_len - 1
            if (j1 > i1 && j1 < path_len - 1) {
                uint16_t node_after_j1 = base_reduced_path[j1 + 1];
                
                // Check whether nodes at i1 and j1+1 are connected
                if (edges[node_i1][node_after_j1]) {
                    // Create the path after the first-level 2-opt
                    uint16_t path1[MAX_QUEEN_GRAPH_SIZE];
                    std::memcpy(path1, base_reduced_path, path_len * sizeof(uint16_t));
                    HamiltonianSearcherCPU::reverse_subpath(path1, i1, j1);
                    
                    // Reduce + difficulty check for the first-level result
                    if (reduce_and_check_solution(path1, path_len, worker_path, worker_path_len, edges, node_edges,
                                                   data_hex, target_hex, hash_count_local, out_path, out_path_len, out_hex, bloom)) {
                        result.hash_count += hash_count_local;
                        std::memcpy(result.path, out_path, out_path_len * sizeof(uint16_t));
                        result.path_len = out_path_len;
                        result.solution_hex = out_hex;
                        result.found = true;
                        return result;
                    }
                    
                    // ========== Second-level 2-opt ==========
                    // Apply second-level transformation based on path1 (first-level result).
                    // Recompute node_index2 mapping.
                    uint16_t node_index2[MAX_QUEEN_GRAPH_SIZE];
                    for (uint16_t idx = 0; idx < path_len; idx++) {
                        node_index2[path1[idx]] = idx;
                    }
                    
                    for (uint16_t i2 = 1; i2 < path_len - 1; i2++) {
                        // Periodically check whether the job was canceled
                        if ((i2 & 0xF) == 0) {  // Check every 16 iterations
                            CHECK_JOB_CANCELLED();
                        }
                        
                        uint16_t node_before_i2 = path1[i2 - 1];
                        uint16_t node_i2 = path1[i2];
                        
                        for (const auto& k2 : node_edges[node_before_i2]) {
                            uint16_t j2 = node_index2[k2];
                            
                            if (j2 > i2 && j2 < path_len - 1) {
                                uint16_t node_after_j2 = path1[j2 + 1];
                                
                                    if (edges[node_i2][node_after_j2]) {
                                    // Create the path after the second-level 2-opt
                                    uint16_t path2[MAX_QUEEN_GRAPH_SIZE];
                                    std::memcpy(path2, path1, path_len * sizeof(uint16_t));
                                    HamiltonianSearcherCPU::reverse_subpath(path2, i2, j2);
                                    
                                    // Reduce + difficulty check for the second-level result
                                    if (reduce_and_check_solution(path2, path_len, worker_path, worker_path_len, edges, node_edges,
                                                                   data_hex, target_hex, hash_count_local, out_path, out_path_len, out_hex, bloom)) {
                                        result.hash_count += hash_count_local;
                                        std::memcpy(result.path, out_path, out_path_len * sizeof(uint16_t));
                                        result.path_len = out_path_len;
                                        result.solution_hex = out_hex;
                                        result.found = true;
                                        return result;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    result.hash_count += hash_count_local;
    
    #undef CHECK_JOB_CANCELLED
    
    return result;
}

// ============================================================================
// search_full: run HC1 + HC2 sequentially
// ============================================================================

SearchResult HamiltonianSearcherCPU::search_full(
    const std::string& first_hash_hex,
    uint16_t worker_percentage_x10,
    uint16_t queen_percentage_x10,
    uint16_t max_worker_paths,
    const std::string& data_hex,
    const std::string& target_hex,
    const uint64_t* job_version,
    uint64_t expected_version
) {
    SearchResult result;
    result.found = false;
    result.cancelled = false;
    result.path_len = 0;
    result.hash_count = 0;
    result.graph_gen_us = 0;
    result.dfs_us = 0;
    result.total_us = 0;
    
    // Helper macro: check job version change or global shutdown
    #define CHECK_JOB_CANCELLED() \
        if (g_shutdown.load(std::memory_order_relaxed) || \
            (job_version && __atomic_load_n(job_version, __ATOMIC_SEQ_CST) != expected_version)) { \
            result.cancelled = true; \
            return result; \
        }
    
    // Get worker and queen graph sizes
    uint16_t worker_grid_size = get_worker_grid_size(first_hash_hex);
    uint16_t queen_bee_grid_size = get_queen_bee_grid_size(worker_grid_size);
    
    // HC1: search worker paths (heap allocation to avoid stack overflow)
    uint16_t actual_max_paths = std::min(max_worker_paths, (uint16_t)MAX_WORKER_PATHS);
    std::vector<uint16_t> worker_paths_flat(actual_max_paths * MAX_WORKER_GRAPH_SIZE);
    std::vector<uint16_t> worker_path_lens(actual_max_paths);
    std::vector<uint16_t*> worker_paths_ptrs(actual_max_paths);
    for (uint16_t i = 0; i < actual_max_paths; i++) {
        worker_paths_ptrs[i] = worker_paths_flat.data() + i * MAX_WORKER_GRAPH_SIZE;
    }
    
    uint16_t worker_path_count = search_multi(
        first_hash_hex, worker_grid_size, worker_percentage_x10, 
        actual_max_paths, worker_paths_ptrs.data(), worker_path_lens.data()
    );
    
    if (worker_path_count == 0) {
        // HC1 failed
        return result;
    }
    
    CHECK_JOB_CANCELLED();
    
    // Run HC2 for each worker path
    for (uint16_t wi = 0; wi < worker_path_count; wi++) {
        CHECK_JOB_CANCELLED();
        
        const uint16_t* worker_path = worker_paths_ptrs[wi];
        uint16_t worker_path_len = worker_path_lens[wi];
        
        // Compute queen graph hash (Bitcoin Core HashWriter serialization)
        // << worker_solution << first_hash
        std::vector<uint8_t> queen_hash_data;
        queen_hash_data.reserve(worker_path_len * 2 + 33);
        
        // Serialize vector size as compact integer (Bitcoin Core style)
        size_t size = worker_path_len;
        if (size < 0xfd) {
            queen_hash_data.push_back(static_cast<uint8_t>(size));
        } else if (size <= 0xffff) {
            queen_hash_data.push_back(0xfd);
            queen_hash_data.push_back(static_cast<uint8_t>(size & 0xff));
            queen_hash_data.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
        } else {
            queen_hash_data.push_back(0xfe);
            queen_hash_data.push_back(static_cast<uint8_t>(size & 0xff));
            queen_hash_data.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
            queen_hash_data.push_back(static_cast<uint8_t>((size >> 16) & 0xff));
            queen_hash_data.push_back(static_cast<uint8_t>((size >> 24) & 0xff));
        }
        
        // Serialize each uint16_t in little-endian format
        for (uint16_t i = 0; i < worker_path_len; i++) {
            uint16_t val = worker_path[i];
            queen_hash_data.push_back(static_cast<uint8_t>(val & 0xff));
            queen_hash_data.push_back(static_cast<uint8_t>((val >> 8) & 0xff));
        }
        
        // Append first_hash bytes (32 bytes, reversed)
        uint8_t first_hash_bytes[32];
        size_t first_hash_len;
        hex_to_bytes(first_hash_hex, first_hash_bytes, &first_hash_len);
        // Reverse the hash bytes
        for (size_t i = 0; i < 16; i++) {
            std::swap(first_hash_bytes[i], first_hash_bytes[31 - i]);
        }
        for (size_t i = 0; i < 32; i++) {
            queen_hash_data.push_back(first_hash_bytes[i]);
        }
        
        // Compute SHA256 (via OpenSSL)
        uint8_t queen_hash[32];
        sha256_openssl(queen_hash_data.data(), queen_hash_data.size(), queen_hash);
        
        // Reverse the hash and convert to hex
        uint8_t queen_hash_reversed[32];
        for (int i = 0; i < 32; i++) {
            queen_hash_reversed[i] = queen_hash[31 - i];
        }
        std::string queen_hash_hex = bytes_to_hex(queen_hash_reversed, 32);
        
        // Run HC2 via search_second
        SearchResult hc2_result = search_second(
            queen_hash_hex,
            queen_bee_grid_size,
            queen_percentage_x10,
            0,  // timeout_ms (unused)
            worker_path,
            worker_path_len,
            data_hex,
            target_hex,
            nullptr,
            job_version,
            expected_version
        );
        
        result.hash_count += hc2_result.hash_count;
        
        if (hc2_result.cancelled) {
            result.cancelled = true;
            return result;
        }
        
        if (hc2_result.found) {
            result.found = true;
            result.path_len = hc2_result.path_len;
            std::memcpy(result.path, hc2_result.path, hc2_result.path_len * sizeof(uint16_t));
            result.solution_hex = std::move(hc2_result.solution_hex);
            return result;
        }
        // HC2 didn't find a valid solution; continue to next worker path
    }
    
    #undef CHECK_JOB_CANCELLED
    
    // Exhausted all worker paths without finding a valid solution
    return result;
}

// ============================================================================
// C interface implementation
// ============================================================================

extern "C" {

// Initialize HugepageAllocator
int hc_cpu_init_hugepages(size_t pool_size_mb) {
    size_t pool_size = pool_size_mb * 1024 * 1024;
    bool is_hugepages = HugepageAllocator::instance().init(pool_size);
    return is_hugepages ? 1 : 0;
}

// Shutdown HugepageAllocator
void hc_cpu_shutdown_hugepages() {
    // First set shutdown flag so in-flight searches exit quickly
    g_shutdown.store(true, std::memory_order_release);
    
    // Wait briefly for threads to exit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    HugepageAllocator::instance().shutdown();
}

// Reset HugepageAllocator
void hc_cpu_reset_hugepages() {
    HugepageAllocator::instance().reset();
}

HamiltonianSearcherCPU* hc_cpu_create() {
    return new HamiltonianSearcherCPU();
}

void hc_cpu_destroy(HamiltonianSearcherCPU* searcher) {
    if (searcher) {
        delete searcher;
    }
}

int hc_cpu_search_multi(
    HamiltonianSearcherCPU* searcher,
    const char* graph_hash_hex,
    uint16_t graph_size,
    uint16_t percentage_x10,
    uint16_t max_paths,
    uint16_t* out_paths,
    uint16_t* out_path_lens
) {
    if (!searcher) return 0;
    
    // Clamp max_paths
    if (max_paths > MAX_WORKER_PATHS) {
        max_paths = MAX_WORKER_PATHS;
    }
    
    // Build pointer array into the output buffer
    std::vector<uint16_t*> path_ptrs(max_paths);
    for (uint16_t i = 0; i < max_paths; i++) {
        path_ptrs[i] = out_paths + i * MAX_WORKER_GRAPH_SIZE;
    }
    
    uint16_t count = searcher->search_multi(
        std::string(graph_hash_hex),
        graph_size,
        percentage_x10,
        max_paths,
        path_ptrs.data(),
        out_path_lens
    );
    
    return static_cast<int>(count);
}

int hc_cpu_search_second(
    HamiltonianSearcherCPU* searcher,
    const char* graph_hash_hex,
    uint16_t graph_size,
    uint16_t percentage_x10,
    uint64_t timeout_ms,
    const uint16_t* worker_path,
    size_t worker_path_len,
    const char* data_hex,
    const char* target_hex,
    uint16_t* out_path,
    size_t* out_path_len,
    char* out_solution_hex,
    uint64_t* out_hash_count,
    uint64_t* out_graph_gen_us,
    uint64_t* out_dfs_us,
    uint64_t* out_total_us,
    const uint64_t* job_version,
    uint64_t expected_version
) {
    if (!searcher) return 0;
    
    // Run search (pass pointers directly)
    SearchResult result = searcher->search_second(
        std::string(graph_hash_hex),
        graph_size,
        percentage_x10,
        timeout_ms,
        worker_path,
        static_cast<uint16_t>(worker_path_len),
        std::string(data_hex),
        std::string(target_hex),
        nullptr,
        job_version,
        expected_version
    );
    
    // Check cancellation
    if (result.cancelled) {
        *out_path_len = 0;
        if (out_solution_hex) out_solution_hex[0] = '\0';
        *out_hash_count = result.hash_count;
        *out_graph_gen_us = result.graph_gen_us;
        *out_dfs_us = result.dfs_us;
        *out_total_us = result.total_us;
        return 3; // Job changed; computation cancelled
    }
    
    // Fill outputs
    *out_hash_count = result.hash_count;
    *out_graph_gen_us = result.graph_gen_us;
    *out_dfs_us = result.dfs_us;
    *out_total_us = result.total_us;
    
    if (result.path_len == 0) {
        // DFS failed
        *out_path_len = 0;
        if (out_solution_hex) out_solution_hex[0] = '\0';
        return 0;
    }
    
    // Copy path
    *out_path_len = result.path_len;
    std::memcpy(out_path, result.path, result.path_len * sizeof(uint16_t));
    
    // Copy solution_hex
    if (out_solution_hex && !result.solution_hex.empty()) {
        std::strcpy(out_solution_hex, result.solution_hex.c_str());
    }
    
    return result.found ? 1 : 2;
}

int hc_cpu_search_full(
    HamiltonianSearcherCPU* searcher,
    const char* first_hash_hex,
    uint16_t worker_percentage_x10,
    uint16_t queen_percentage_x10,
    uint16_t max_worker_paths,
    const char* data_hex,
    const char* target_hex,
    uint16_t* out_path,
    size_t* out_path_len,
    char* out_solution_hex,
    uint64_t* out_hash_count,
    const uint64_t* job_version,
    uint64_t expected_version
) {
    if (!searcher) return 0;
    
    SearchResult result = searcher->search_full(
        std::string(first_hash_hex),
        worker_percentage_x10,
        queen_percentage_x10,
        max_worker_paths,
        std::string(data_hex),
        std::string(target_hex),
        job_version,
        expected_version
    );
    
    *out_hash_count = result.hash_count;
    
    if (result.cancelled) {
        *out_path_len = 0;
        if (out_solution_hex) out_solution_hex[0] = '\0';
        return 3;  // Job changed; cancelled
    }
    
    if (result.path_len == 0) {
        *out_path_len = 0;
        if (out_solution_hex) out_solution_hex[0] = '\0';
        return 0;  // HC1 failed
    }
    
    *out_path_len = result.path_len;
    std::memcpy(out_path, result.path, result.path_len * sizeof(uint16_t));
    
    if (out_solution_hex && !result.solution_hex.empty()) {
        std::strcpy(out_solution_hex, result.solution_hex.c_str());
    }
    
    return result.found ? 1 : 2;
}

} // extern "C"
