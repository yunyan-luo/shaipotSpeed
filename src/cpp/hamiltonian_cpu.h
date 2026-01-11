#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <vector>

// Constants
constexpr uint16_t HC_GRAPH_SIZE = 2008;
constexpr uint16_t MAX_QUEEN_GRAPH_SIZE = 128;   // Max queen graph size
constexpr uint16_t MAX_WORKER_GRAPH_SIZE = 1920; // Max worker graph size
constexpr uint16_t MAX_WORKER_PATHS = 1000;      // Max number of paths returned by HC1

// Search result structure
struct SearchResult {
    bool found;                     // Whether a difficulty-satisfying solution was found
    bool cancelled;                 // Whether the search was canceled due to a job change
    uint16_t path[HC_GRAPH_SIZE];   // Combined path (worker + queen)
    uint16_t path_len;              // Path length
    std::string solution_hex;       // Solution in hex format
    uint64_t hash_count;            // Number of hashes computed
    // Timing information (microseconds)
    uint64_t graph_gen_us;          // Graph generation time
    uint64_t dfs_us;                // DFS time
    uint64_t total_us;              // Total time
};

// Callback type used to validate difficulty and handle submission.
// Returns true if it meets the target difficulty, false otherwise.
using SolutionCallback = std::function<bool(
    const uint16_t* combined_path,    // Combined path
    uint16_t combined_path_len,       // Path length
    const std::string& solution_hex   // Solution in hex format
)>;

class HamiltonianSearcherCPU {
public:
    HamiltonianSearcherCPU();
    ~HamiltonianSearcherCPU();
    
    // Main search function mirroring Rust's find_hamiltonian_cycle_v3_hex_second.
    // Return value semantics:
    //   - found=false and cancelled=false: no base path found / no valid solution
    //   - found=true: a target-meeting solution was found
    //   - cancelled=true: canceled due to job version change
    SearchResult search_second(
        const std::string& graph_hash_hex,     // Queen graph hash
        uint16_t graph_size,                   // Queen graph size
        uint16_t percentage_x10,               // Edge probability (125 = 12.5%)
        uint64_t timeout_ms,                   // DFS timeout
        const uint16_t* worker_path,           // Worker path
        uint16_t worker_path_len,              // Worker path length
        const std::string& data_hex,           // Original data hex
        const std::string& target_hex,         // Target difficulty hex
        SolutionCallback callback = nullptr,   // Optional callback
        const uint64_t* job_version = nullptr, // Job version pointer (for detecting job changes)
        uint64_t expected_version = 0          // Expected version at start
    );
    
    // Extract seed from hash_hex.
    uint64_t extract_seed_from_hash_hex(const std::string& hash_hex);
    
    // Get worker graph size from hash_hex.
    uint16_t get_worker_grid_size(const std::string& hash_hex);
    
    // Get queen graph size.
    uint16_t get_queen_bee_grid_size(uint16_t worker_size);
    
    // HC1: find multiple worker paths (Posa rotation-extension + 2-opt).
    // Returns the number of paths found.
    uint16_t search_multi(
        const std::string& graph_hash_hex,
        uint16_t graph_size,
        uint16_t percentage_x10,
        uint16_t max_paths,
        uint16_t** out_paths,   // Pointer array; each points to a path buffer
        uint16_t* out_path_lens // Path length array
    );
    
    // Full search: run HC1 + HC2 sequentially.
    // Takes the initial data hash, executes the full pipeline, and returns the result.
    // Status:
    //   - status=0: HC1 failed (no worker path found)
    //   - status=1: target-meeting solution found
    //   - status=2: exhausted all paths without a valid solution
    //   - status=3: canceled due to job version change
    SearchResult search_full(
        const std::string& first_hash_hex,     // Hash after the first SHA256 (64 hex chars)
        uint16_t worker_percentage_x10,        // Worker graph edge probability (500 = 50%)
        uint16_t queen_percentage_x10,         // Queen graph edge probability (125 = 12.5%)
        uint16_t max_worker_paths,             // Max worker paths to try
        const std::string& data_hex,           // Original data hex
        const std::string& target_hex,         // Target difficulty hex
        const uint64_t* job_version = nullptr, // Job version pointer (for detecting job changes)
        uint64_t expected_version = 0          // Expected version at start
    );
    
    // Generate a graph (fixed-size arrays) and build adjacency lists.
    void generate_graph_v3_from_seed(
        uint64_t seed, 
        uint16_t grid_size, 
        uint16_t percentage_x10,
        bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
        std::vector<uint16_t> node_edges_vec[MAX_QUEEN_GRAPH_SIZE]
    );
    
    // Compute SHA256.
    static void sha256(const uint8_t* data, size_t len, uint8_t* hash);
    
    // Check whether the hash meets the target difficulty.
    static bool meets_target(const std::string& hash_hex, const std::string& target_hex);
    
    // Reverse a subpath (2-opt operation).
    static void reverse_subpath(uint16_t* path, size_t i, size_t j);
    
    // Posa's rotation-extension algorithm; more efficient than DFS for random graphs.
    bool posa_rotation_extension(
        uint16_t path[MAX_QUEEN_GRAPH_SIZE],
        uint16_t& path_len,
        const std::vector<uint16_t> node_edges[MAX_QUEEN_GRAPH_SIZE],
        const bool edges[MAX_QUEEN_GRAPH_SIZE][MAX_QUEEN_GRAPH_SIZE],
        uint16_t graph_size
    );
    
private:
    // Validate and handle a candidate solution.
    bool check_solution(
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
    );
    
    // check_solution2 - for comparison experiments.
    bool check_solution2(
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
    );
    
    // Hex helpers.
    static void hex_to_bytes(const std::string& hex, uint8_t* out, size_t* out_len);
    static std::string bytes_to_hex(const uint8_t* data, size_t len);
    
    // Get current time (ms).
    static uint64_t get_time_ms();
};

// ============================================================================
// C API (for Rust FFI)
// ============================================================================

extern "C" {
    // Initialize HugepageAllocator.
    // pool_size_mb: pool size (MB)
    // Returns: 1 if hugepages are used, 0 if it falls back to regular pages.
    int hc_cpu_init_hugepages(size_t pool_size_mb);
    
    // Shutdown HugepageAllocator.
    void hc_cpu_shutdown_hugepages();
    
    // Reset HugepageAllocator (free all allocated memory but keep the pool).
    void hc_cpu_reset_hugepages();
    
    // Create/destroy the searcher.
    HamiltonianSearcherCPU* hc_cpu_create();
    void hc_cpu_destroy(HamiltonianSearcherCPU* searcher);
    
    // HC1: search multiple worker paths.
    // Returns: number of paths found.
    int hc_cpu_search_multi(
        HamiltonianSearcherCPU* searcher,
        const char* graph_hash_hex,
        uint16_t graph_size,
        uint16_t percentage_x10,
        uint16_t max_paths,
        // Output parameters - path data (flattened array)
        uint16_t* out_paths,    // Size = max_paths * MAX_WORKER_GRAPH_SIZE
        uint16_t* out_path_lens // Size = max_paths
    );
    
    // Search function.
    // Returns: 0 = DFS failed, 1 = valid solution found, 2 = no valid solution, 3 = canceled due to job change
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
        // Output parameters
        uint16_t* out_path,       // Output path buffer (at least HC_GRAPH_SIZE)
        size_t* out_path_len,     // Output path length
        char* out_solution_hex,   // Output hex buffer (at least HC_GRAPH_SIZE*4+1)
        uint64_t* out_hash_count, // Output hash count
        // Timing output parameters (microseconds)
        uint64_t* out_graph_gen_us,
        uint64_t* out_dfs_us,
        uint64_t* out_total_us,
        // Job version check parameters
        const uint64_t* job_version, // Current job version pointer
        uint64_t expected_version    // Expected version
    );
    
    // Full search: run HC1 + HC2 sequentially.
    // Returns: 0 = HC1 failed, 1 = valid solution found, 2 = no valid solution, 3 = canceled due to job change
    int hc_cpu_search_full(
        HamiltonianSearcherCPU* searcher,
        const char* first_hash_hex,      // Hash after the first SHA256 (64 hex chars)
        uint16_t worker_percentage_x10,  // Worker graph edge probability (500 = 50%)
        uint16_t queen_percentage_x10,   // Queen graph edge probability (125 = 12.5%)
        uint16_t max_worker_paths,       // Max worker paths to try
        const char* data_hex,            // Original data hex
        const char* target_hex,          // Target difficulty hex
        // Output parameters
        uint16_t* out_path,        // Output path buffer (at least HC_GRAPH_SIZE)
        size_t* out_path_len,      // Output path length
        char* out_solution_hex,    // Output hex buffer (at least HC_GRAPH_SIZE*4+1)
        uint64_t* out_hash_count,  // Output hash count
        // Job version check parameters
        const uint64_t* job_version, // Current job version pointer
        uint64_t expected_version    // Expected version
    );
}
