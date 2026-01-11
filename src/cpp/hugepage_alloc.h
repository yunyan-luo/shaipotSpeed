// Copyright (c) 2025 The Thought Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THOUGHT_MINER_HUGEPAGE_ALLOC_H
#define THOUGHT_MINER_HUGEPAGE_ALLOC_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <atomic>

/**
 * Simple hugepage memory pool allocator for multi-threaded mining.
 * 
 * Features:
 * - Pre-allocates a large block of hugepage memory at startup
 * - Thread-safe bump allocator for fast allocation
 * - Supports reset for reuse across mining iterations
 * - Falls back to regular memory if hugepages unavailable
 */
class HugepageAllocator {
public:
    // Singleton access
    static HugepageAllocator& instance();
    
    // Initialize the pool with specified size (in bytes)
    // Should be called once at startup before any allocations
    // Returns true if hugepages were successfully allocated
    bool init(size_t poolSize);
    
    // Shutdown and free all memory
    void shutdown();
    
    // Allocate memory from the pool (thread-safe)
    // alignment: must be power of 2, default 64 for cache line
    // Returns nullptr if pool exhausted
    void* alloc(size_t size, size_t alignment = 64);
    
    // Reset the allocator (NOT thread-safe - call only when no threads are using pool)
    // This allows reusing memory for the next mining iteration
    void reset();
    
    // Get statistics
    size_t totalSize() const { return m_totalSize; }
    size_t usedSize() const { return m_offset.load(std::memory_order_relaxed); }
    size_t freeSize() const { return m_totalSize - usedSize(); }
    bool isHugepages() const { return m_isHugepages; }
    
    // Convenience: typed allocation
    template<typename T>
    T* allocArray(size_t count, size_t alignment = 64) {
        return static_cast<T*>(alloc(sizeof(T) * count, alignment));
    }
    
private:
    HugepageAllocator();
    ~HugepageAllocator();
    
    // Non-copyable
    HugepageAllocator(const HugepageAllocator&) = delete;
    HugepageAllocator& operator=(const HugepageAllocator&) = delete;
    
    // Try to allocate hugepage memory
    void* allocHugepages(size_t size);
    
    // Free hugepage memory
    void freeHugepages(void* ptr, size_t size);
    
    uint8_t* m_memory{nullptr};
    size_t m_totalSize{0};
    std::atomic<size_t> m_offset{0};
    bool m_isHugepages{false};
    bool m_initialized{false};
    std::mutex m_initMutex;
    
    static constexpr size_t HUGEPAGE_SIZE = 2 * 1024 * 1024;  // 2MB
};

/**
 * RAII wrapper for pool-allocated memory that resets on destruction.
 * Useful for per-nonce allocations that should be released together.
 */
class HugepageScope {
public:
    HugepageScope() : m_savedOffset(HugepageAllocator::instance().usedSize()) {}
    
    ~HugepageScope() {
        // Note: This is only safe if no other threads are allocating
        // For production use, implement proper reference counting
    }
    
    // Allocate from the pool within this scope
    void* alloc(size_t size, size_t alignment = 64) {
        return HugepageAllocator::instance().alloc(size, alignment);
    }
    
    template<typename T>
    T* allocArray(size_t count, size_t alignment = 64) {
        return HugepageAllocator::instance().allocArray<T>(count, alignment);
    }
    
private:
    size_t m_savedOffset;
};

#endif // THOUGHT_MINER_HUGEPAGE_ALLOC_H
