#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 64 // Cache block size is fixed at 64 bytes

typedef struct {
    unsigned long long tag;
    int valid;
    int dirty; // For write-back
    int lru_counter; // For LRU policy
} CacheBlock;

typedef struct {
    CacheBlock *blocks; // Array of blocks (associativity number of blocks)
} CacheSet;

typedef struct {
    CacheSet *sets; // Array of sets
    int num_sets; // Number of sets
    int associativity;
    int block_size;
    int write_policy; // 0: write-through, 1: write-back
    int replacement_policy; // 0: LRU, 1: FIFO
    int reads, writes;
    int hits, misses;
} Cache;

// Function to initialize the cache
Cache *initialize_cache(int cache_size, int associativity, int replacement_policy, int write_policy) {
    int num_blocks = cache_size / BLOCK_SIZE; // Total number of blocks
    int num_sets = num_blocks / associativity; // Number of sets

    Cache *cache = (Cache *) malloc(sizeof(Cache));
    cache->sets = (CacheSet *) malloc(sizeof(CacheSet) * num_sets);
    cache->num_sets = num_sets;
    cache->block_size = BLOCK_SIZE;
    cache->associativity = associativity;
    cache->write_policy = write_policy;
    cache->replacement_policy = replacement_policy;
    cache->reads = cache->writes = 0;
    cache->hits = cache->misses = 0;

    for (int i = 0; i < num_sets; i++) {
        cache->sets[i].blocks = (CacheBlock *) malloc(sizeof(CacheBlock) * associativity);
        for (int j = 0; j < associativity; j++) {
            cache->sets[i].blocks[j].valid = 0;
            cache->sets[i].blocks[j].dirty = 0;
            cache->sets[i].blocks[j].lru_counter = 0;
        }
    }

    return cache;
}

// Helper function to find a block's index based on the replacement policy
int find_victim(Cache *cache, int set_index) {
    int victim_index = 0;
    if (cache->replacement_policy == 0) { // LRU
        int max_lru = -1;
        for (int i = 0; i < cache->associativity; i++) {
            if (!cache->sets[set_index].blocks[i].valid) {
                return i; // Empty block found
            }
            if (cache->sets[set_index].blocks[i].lru_counter > max_lru) {
                max_lru = cache->sets[set_index].blocks[i].lru_counter;
                victim_index = i;
            }
        }
    } else if (cache->replacement_policy == 1) { // FIFO
        for (int i = 0; i < cache->associativity; i++) {
            if (!cache->sets[set_index].blocks[i].valid) {
                return i; // Empty block found
            }
        }
        victim_index = 0; // Evict the first block by default
    }
    return victim_index;
}

// Update LRU counters
void update_lru(Cache *cache, int set_index, int block_index) {
    for (int i = 0; i < cache->associativity; i++) {
        if (cache->sets[set_index].blocks[i].valid) {
            cache->sets[set_index].blocks[i].lru_counter++;
        }
    }
    cache->sets[set_index].blocks[block_index].lru_counter = 0;
}

// Simulate cache access
void access_cache(Cache *cache, char operation, unsigned long long address) {
    int set_index = (address / cache->block_size) % cache->num_sets;
    unsigned long long tag = address / (cache->block_size * cache->num_sets);

    // Check if there's a hit
    for (int i = 0; i < cache->associativity; i++) {
        CacheBlock *block = &cache->sets[set_index].blocks[i];
        if (block->valid && block->tag == tag) {
            cache->hits++;
            if (operation == 'W') {
                if (cache->write_policy == 1) { // Write-back
                    block->dirty = 1;
                } else { // Write-through
                    cache->writes++;
                }
            }
            if (cache->replacement_policy == 0) { // LRU
                update_lru(cache, set_index, i);
            }
            return;
        }
    }

    // Miss occurred
    cache->misses++;
    int victim_index = find_victim(cache, set_index);
    CacheBlock *victim_block = &cache->sets[set_index].blocks[victim_index];

    // If the block to be evicted is dirty, write it back to memory
    if (victim_block->valid && victim_block->dirty) {
        cache->writes++;
    }

    // Load the new block
    victim_block->valid = 1;
    victim_block->tag = tag;
    victim_block->dirty = (operation == 'W' && cache->write_policy == 1) ? 1 : 0;

    cache->reads++;
    if (operation == 'W' && cache->write_policy == 0) {
        cache->writes++;
    }

    if (cache->replacement_policy == 0) { // LRU
        update_lru(cache, set_index, victim_index);
    }
}

// Parse memory trace file and simulate cache accesses
void run_simulation(Cache *cache, const char *trace_file) {
    FILE *file = fopen(trace_file, "r");
    if (!file) {
        printf("Error: Could not open trace file.\n");
        return;
    }

    char operation;
    unsigned long long address;
    char buffer[256]; // Buffer to store each line
    int line_number = 0;

    // Read file line by line
    while (fgets(buffer, sizeof(buffer), file)) {
        line_number++;
        // Try to parse the line based on the expected format
        if (sscanf(buffer, " %c %llx", &operation, &address) == 2) {
            access_cache(cache, operation, address);
        }
    }

    fclose(file);
}

// Free cache memory
void free_cache(Cache *cache) {
    for (int i = 0; i < cache->num_sets; i++) {
        free(cache->sets[i].blocks);
    }
    free(cache->sets);
    free(cache);
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <CACHE_SIZE> <ASSOC> <REPLACEMENT> <WB> <TRACE_FILE>\n", argv[0]);
        return 1;
    }

    int cache_size = atoi(argv[1]);
    int associativity = atoi(argv[2]);
    int replacement_policy = atoi(argv[3]);
    int write_policy = atoi(argv[4]);
    const char *trace_file = argv[5];

    Cache *cache = initialize_cache(cache_size, associativity, replacement_policy, write_policy);
    run_simulation(cache, trace_file);

    // Calculate the miss ratio
    int total_accesses = cache->hits + cache->misses;
    double miss_ratio = (total_accesses > 0) ? (double) cache->misses / total_accesses : 0.0;

    // Print output in the required format
    printf("Miss ratio: %.6f\n", miss_ratio);
    printf("Writes to memory: %d\n", cache->writes);
    printf("Reads from memory: %d\n", cache->reads);

    free_cache(cache);
    return 0;
}
