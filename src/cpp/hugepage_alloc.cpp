// Copyright (c) 2025 The Thought Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hugepage_alloc.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
#endif

// Align size up to the given alignment (must be power of 2)
static inline size_t alignUp(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

HugepageAllocator& HugepageAllocator::instance() {
    static HugepageAllocator instance;
    return instance;
}

HugepageAllocator::HugepageAllocator() = default;

HugepageAllocator::~HugepageAllocator() {
    shutdown();
}

void* HugepageAllocator::allocHugepages(size_t size) {
#ifdef __linux__
    // Round up to hugepage boundary
    size_t alignedSize = alignUp(size, HUGEPAGE_SIZE);
    
    // Try MAP_HUGETLB first (requires hugepage support)
    void* ptr = mmap(nullptr, alignedSize,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE,
                     -1, 0);
    
    if (ptr != MAP_FAILED) {
        // Lock the memory to prevent swapping
        if (mlock(ptr, alignedSize) == 0) {
            printf("[HugepageAllocator] Allocated %zu MB using MAP_HUGETLB (locked)\n", 
                   alignedSize / (1024 * 1024));
        } else {
            printf("[HugepageAllocator] Allocated %zu MB using MAP_HUGETLB (unlocked)\n", 
                   alignedSize / (1024 * 1024));
        }
        return ptr;
    }
    
    // Fallback: regular mmap with MADV_HUGEPAGE hint
    ptr = mmap(nullptr, alignedSize,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
               -1, 0);
    
    if (ptr != MAP_FAILED) {
        // Request transparent huge pages
        madvise(ptr, alignedSize, MADV_HUGEPAGE);
        madvise(ptr, alignedSize, MADV_WILLNEED);
        
        // Try to lock
        if (mlock(ptr, alignedSize) == 0) {
            printf("[HugepageAllocator] Allocated %zu MB using MADV_HUGEPAGE (locked)\n", 
                   alignedSize / (1024 * 1024));
        } else {
            printf("[HugepageAllocator] Allocated %zu MB using MADV_HUGEPAGE (unlocked)\n", 
                   alignedSize / (1024 * 1024));
        }
        return ptr;
    }
    
    return nullptr;
#else
    // Non-Linux: use aligned allocation
    void* ptr = nullptr;
    if (posix_memalign(&ptr, HUGEPAGE_SIZE, size) == 0) {
        printf("[HugepageAllocator] Allocated %zu MB using posix_memalign\n", 
               size / (1024 * 1024));
        return ptr;
    }
    return nullptr;
#endif
}

void HugepageAllocator::freeHugepages(void* ptr, size_t size) {
    if (!ptr) return;
    
#ifdef __linux__
    size_t alignedSize = alignUp(size, HUGEPAGE_SIZE);
    munlock(ptr, alignedSize);
    munmap(ptr, alignedSize);
#else
    free(ptr);
#endif
}

bool HugepageAllocator::init(size_t poolSize) {
    std::lock_guard<std::mutex> lock(m_initMutex);
    
    if (m_initialized) {
        printf("[HugepageAllocator] Already initialized\n");
        return m_isHugepages;
    }
    
    // Round up to hugepage boundary
    size_t alignedSize = alignUp(poolSize, HUGEPAGE_SIZE);
    
    printf("[HugepageAllocator] Initializing pool: requested=%zu MB, aligned=%zu MB\n",
           poolSize / (1024 * 1024), alignedSize / (1024 * 1024));
    
#ifdef __linux__
    // Check hugepage availability
    std::ifstream hpFile("/proc/sys/vm/nr_hugepages");
    if (hpFile.good()) {
        int nr_hugepages = 0;
        hpFile >> nr_hugepages;
        printf("[HugepageAllocator] System hugepages: %d (need %zu)\n", 
               nr_hugepages, alignedSize / HUGEPAGE_SIZE);
    }
#endif
    
    // Try hugepage allocation
    m_memory = static_cast<uint8_t*>(allocHugepages(alignedSize));
    
    if (m_memory) {
        m_isHugepages = true;
        m_totalSize = alignedSize;
    } else {
        // Final fallback: regular allocation
        printf("[HugepageAllocator] Falling back to regular allocation\n");
        m_memory = static_cast<uint8_t*>(aligned_alloc(64, poolSize));
        if (m_memory) {
            m_totalSize = poolSize;
            m_isHugepages = false;
        } else {
            printf("[HugepageAllocator] ERROR: Failed to allocate memory\n");
            return false;
        }
    }
    
    // Zero out the memory (also ensures pages are faulted in)
    std::memset(m_memory, 0, m_totalSize);
    
    m_offset.store(0, std::memory_order_relaxed);
    m_initialized = true;
    
    printf("[HugepageAllocator] Pool ready: %zu MB (%s)\n",
           m_totalSize / (1024 * 1024),
           m_isHugepages ? "HUGEPAGES" : "regular");
    
    return m_isHugepages;
}

void HugepageAllocator::shutdown() {
    std::lock_guard<std::mutex> lock(m_initMutex);
    
    if (!m_initialized) return;
    
    if (m_isHugepages) {
        freeHugepages(m_memory, m_totalSize);
    } else {
        free(m_memory);
    }
    
    m_memory = nullptr;
    m_totalSize = 0;
    m_offset.store(0, std::memory_order_relaxed);
    m_initialized = false;
    m_isHugepages = false;
    
    printf("[HugepageAllocator] Shutdown complete\n");
}

void* HugepageAllocator::alloc(size_t size, size_t alignment) {
    if (!m_initialized || !m_memory || size == 0) {
        return nullptr;
    }
    
    // Ensure alignment is at least 8 and power of 2
    alignment = std::max(alignment, size_t(8));
    
    // Atomic bump allocation with alignment
    size_t currentOffset, newOffset, alignedOffset;
    
    do {
        currentOffset = m_offset.load(std::memory_order_relaxed);
        
        // Align the current offset
        alignedOffset = alignUp(currentOffset, alignment);
        newOffset = alignedOffset + size;
        
        // Check if we have enough space
        if (newOffset > m_totalSize) {
            return nullptr;  // Pool exhausted
        }
        
    } while (!m_offset.compare_exchange_weak(currentOffset, newOffset,
                                              std::memory_order_acq_rel,
                                              std::memory_order_relaxed));
    
    return m_memory + alignedOffset;
}

void HugepageAllocator::reset() {
    // Warning: Only call when no threads are using the pool!
    m_offset.store(0, std::memory_order_release);
}
