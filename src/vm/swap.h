#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include <stdbool.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"

#define ST_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)
#define ST_FREE true
#define ST_USED false

/* Tracks swap slot usage */
struct bitmap *swap_table_bitmap;

/* Block device for swapping */
struct block *swap_table_block;

/* Used to prevent race conditions performing swap tasks */
struct lock swap_table_lock;

/* Functions that perform that actual swapping */
void swap_init (void);
void swap_load (int index, void *frame);
int swap_store (void *frame);
#endif
