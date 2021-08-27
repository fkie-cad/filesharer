#ifndef SHARED_FIFO_H
#define SHARED_FIFO_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

/**
 * FIFO
 * vs 1.0.0
 */

//#define FIFO_ENTRY_HEADER_SIZE_32 (12)
//#define FIFO_ENTRY_HEADER_SIZE_64 (24)

typedef struct FifoEntry {
   struct FifoEntry* next;
   //struct FifoEntry* last;
   size_t size;
   unsigned char value[1];
} FifoEntry, * PFifoEntry;

typedef struct Fifo {
    struct FifoEntry* front;
    struct FifoEntry* head;
    size_t size;
    size_t entry_header_size; // size of entry header (next + size)
} Fifo, *PFifo;

/**
 * Initialize Fifo internals.
 */
bool Fifo_init(PFifo fifo);

/**
 * Clears and frees all elements in the fifo,
 * but does not free the fifo object itself.
 */
bool Fifo_clear(PFifo fifo);

/**
 * Clears and frees all elements in the fifo,
 * and frees the fifo object itself.
 */
bool Fifo_destroy(PFifo fifo);

/**
 * Push entry onto Fifo.
 */
size_t Fifo_push(PFifo fifo, const void* entry, size_t entry_size);

/**
 * Check if Fifo is empty.
 */
bool Fifo_empty(PFifo fifo);

/**
 * Get size of Fifo.
 */
size_t Fifo_size(PFifo fifo);

/**
 * Get (pointer to) front element of Fifo.
 */
PFifoEntry Fifo_front(PFifo fifo);

/**
 * Pop front element from Fifo.
 */
bool Fifo_pop_front(PFifo fifo);

#endif
