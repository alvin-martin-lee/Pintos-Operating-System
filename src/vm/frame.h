#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "vm/page.h"

/* Page pointer type. */
typedef void * pageptr_t;

/* Synchronize frame table access. */
struct lock frame_table_lock;
struct lock frame_lru_list_lock;

struct frame_table_entry {
  /* User virtual address of page that occupies this frame. */
  pageptr_t page_addr;

 /* Kernel virtual address of frame. */
  pageptr_t frame_addr;

  /* For storing in frame table (implemented as a hash table). */
  struct hash_elem hash_elem;

  /* List of frames for implementing LRU. */
  struct list_elem lru_list_elem;

  /* For recording which process currently owns the frame. */
  struct thread *owner_proc;

  /* For sharing - references a read only file */
  struct file *file;
  unsigned pages_shared;

  /* Records whether the current page in the frame is in use.
     Prevents it from being evicted inappropriately. */
  bool pinned;
};

/* Frame table (hash table implementation). */
struct hash frame_table;

/* List of frames (for LRU page replacement algorithm)*/
struct list frame_lru_list;

/* Initialises a new frame table. */
void frame_init (void);

/* Functions for allocating and freeing frames. */
pageptr_t frame_alloc (enum palloc_flags flags, pageptr_t user_page, struct file* file);
void frame_free (pageptr_t kernel_page);
struct thread *frame_get_owner_process (pageptr_t kernel_page);

/* Least Recently Used page eviction. */
void frame_lru_list_init (void);
void frame_lru_list_add (struct frame_table_entry *entry);
void frame_lru_list_remove (struct frame_table_entry *entry);
void frame_lru_list_update (void);
struct frame_table_entry *frame_lru_list_pop_min (void);

#endif
