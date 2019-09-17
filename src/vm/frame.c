#include <debug.h>
#include <stdio.h>
#include "frame.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

/* Functions for underlying hash table. */
static unsigned frame_table_hash_func (const struct hash_elem *element,
                                       void *aux);
static bool frame_table_less_func (const struct hash_elem *a,
                                   const struct hash_elem *b,
                                   void *aux UNUSED);

/* Frame eviction policy implementation. */
static void frame_evict (void);

/* Pin / unpin frames to prevent inappropriate eviction. */
static void frame_pin (pageptr_t kpage);
static void frame_unpin (pageptr_t kpage);

/* Initialize frame table. */
void frame_init (void)
{
  hash_init (&frame_table, frame_table_hash_func, frame_table_less_func, NULL);
  lock_init (&frame_table_lock);
  frame_lru_list_init ();
}

/* Hash function for frame table entries. */
static unsigned
frame_table_hash_func (const struct hash_elem *element, void *aux UNUSED)
{
  const struct frame_table_entry *entry = hash_entry (
      element, struct frame_table_entry, hash_elem);
  return hash_bytes (&entry->frame_addr, sizeof (entry->frame_addr));
}

/* Frame table entry comparison function. */
static bool
frame_table_less_func (const struct hash_elem *a,
                       const struct hash_elem *b,
                       void *aux UNUSED)
{
  const struct frame_table_entry *a_ = hash_entry (
      a, struct frame_table_entry, hash_elem);
  const struct frame_table_entry *b_ = hash_entry (
      b, struct frame_table_entry, hash_elem);
  return a_->frame_addr < b_->frame_addr;
}

/* Allocate a new page to be stored in a frame.
   Normally `flags` should be just PAL_USER, but may also want PAL_ZERO. */
pageptr_t
frame_alloc (enum palloc_flags flags, pageptr_t user_page, struct file *file)
{
  /* debug */
  ASSERT (flags & PAL_USER);
  ASSERT (user_page != NULL && is_user_vaddr (user_page));
  ASSERT (pg_ofs (user_page) == 0);

  lock_acquire (&frame_table_lock);

  /* Obtaining an unused frame (i.e. no entry in frame table) */
  pageptr_t frame = palloc_get_page (flags);
  if (frame == NULL)
    {
      /* No free memory: make a frame free by evicting some page. */
      frame_evict ();
      frame = palloc_get_page (flags);
      if (frame == NULL)
        {
          PANIC ("Couldn't get a frame even after evicting one.\n");
        }
    }
  else
    {
      struct frame_table_entry *frame_entry = malloc (
          sizeof (struct frame_table_entry));
      if (frame_entry == NULL)
        {
          PANIC ("Could allocate memory for frame table entry.\n");
        }
      frame_entry->page_addr = user_page;
      frame_entry->frame_addr = frame;
      frame_entry->owner_proc = thread_current ();
      frame_entry->pages_shared = 1;
      frame_entry->file = file;
      hash_insert (&frame_table, &frame_entry->hash_elem);
      frame_lru_list_add (frame_entry);
    }

  lock_release (&frame_table_lock);
  return frame;
}

/* Note: not thread-safe, call this inside a function with frame lock acquired.*/
static struct frame_table_entry *
find_entry_by_kernel_page (pageptr_t kernel_page)
{
  ASSERT (lock_held_by_current_thread (&frame_table_lock));
  ASSERT (pg_ofs (kernel_page) == 0);
  struct frame_table_entry tmp = {.frame_addr = kernel_page};
  struct hash_elem *elem = hash_find (&frame_table, &tmp.hash_elem);
  if (elem == NULL)
    {
      return NULL;
    }
  return hash_entry (elem, struct frame_table_entry, hash_elem);
}

/* Get pointer to process owning this frame. */
struct thread *
frame_get_owner_process (pageptr_t kernel_page)
{
  ASSERT (pg_ofs (kernel_page) == 0);
  lock_acquire (&frame_table_lock);
  struct thread *res = find_entry_by_kernel_page (kernel_page)->owner_proc;
  lock_release (&frame_table_lock);
  return res;
}

/* Unsynchronized version of frame_free(). */
static void
frame_free_nosync (pageptr_t kernel_page)
{
  ASSERT (lock_held_by_current_thread (&frame_table_lock));
  struct frame_table_entry *entry = find_entry_by_kernel_page (kernel_page);
  ASSERT (entry != NULL);
  palloc_free_page (entry->frame_addr);
  hash_delete (&frame_table, &entry->hash_elem);
  frame_lru_list_remove (entry);
  free (entry);
}

/* Free the memory of the given entry. */
void
frame_free (pageptr_t kernel_page)
{
  ASSERT (pg_ofs (kernel_page) == 0);
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *entry = find_entry_by_kernel_page (kernel_page);
  ASSERT (entry != NULL);
  entry->pages_shared--;
  if (entry->pages_shared >= 0)
    {
      palloc_free_page (entry->frame_addr);
      hash_delete (&frame_table, &entry->hash_elem);
      frame_lru_list_remove (entry);
      free (entry);
    }
  lock_release (&frame_table_lock);
}

/* Choose a frame to evict.
   Assumes the caller has acquired the global frame table lock. */
static void
frame_evict (void)
{
  ASSERT (lock_held_by_current_thread (&frame_table_lock));

  /* Choose LRU frame */
  struct frame_table_entry *target_entry = frame_lru_list_pop_min ();

  struct spt_entry *e = spt_retrieve (target_entry->page_addr);
  ASSERT (e != NULL && e->loaded);
  e->loaded = false;

  pagedir_clear_page (target_entry->owner_proc->pagedir, target_entry->page_addr);
  frame_free_nosync (target_entry->frame_addr);
}

/* Pin a page to its frame. */
static void
frame_pin (pageptr_t kpage)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *entry = find_entry_by_kernel_page (kpage);
  ASSERT (entry != NULL);
  ASSERT (entry->page_addr != NULL);
  entry->pinned = true;
  lock_release (&frame_table_lock);
}

/* Unpin a page from its frame. */
static void
frame_unpin (pageptr_t kpage)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *entry = find_entry_by_kernel_page (kpage);
  ASSERT (entry != NULL);
  ASSERT (entry->page_addr != NULL);
  entry->pinned = false;
  lock_release (&frame_table_lock);
}

/* Initialize LRU list for frame eviction. */
void
frame_lru_list_init (void)
{
  list_init (&frame_lru_list);
  lock_init (&frame_lru_list_lock);
}

/* Add frame entry to LRU list. */
void
frame_lru_list_add (struct frame_table_entry *entry)
{
  lock_acquire (&frame_lru_list_lock);
  list_push_back (&frame_lru_list, &entry->lru_list_elem);
  lock_release (&frame_lru_list_lock);
}

/* Remove frame entry from LRU list. */
void
frame_lru_list_remove (struct frame_table_entry *entry)
{
  lock_acquire (&frame_lru_list_lock);
  list_remove (&entry->lru_list_elem);
  lock_release (&frame_lru_list_lock);
}

/* Call this periodically to reset reference bits (i.e. accessed bits) to 0.
   NOTE: this does not use locks for synchronization because it is called in
   thread_tick() in thread.c with interrupts disabled. Using locks would cause
   kernel panics. */
void
frame_lru_list_update (void)
{
  struct frame_table_entry *entry = NULL;
  for (struct list_elem *e = list_begin (&frame_lru_list);
       e != list_end (&frame_lru_list);
       e = list_next (e))
    {
      entry = list_entry (e, struct frame_table_entry, lru_list_elem);
      /* set reference bits to zero */
      if (entry->page_addr != NULL && !entry->pinned)
        {
          pagedir_set_accessed (entry->owner_proc->pagedir, entry->page_addr, false);
        }
    }
}

/* Get the LRU frame entry and remove it from the LRU list. */
struct frame_table_entry *
frame_lru_list_pop_min (void)
{
  ASSERT (lock_held_by_current_thread (&frame_table_lock));
  ASSERT (!list_empty (&frame_lru_list));

  struct frame_table_entry *entry = NULL;
  for (struct list_elem *e = list_begin (&frame_lru_list);
       e != list_end (&frame_lru_list);
       e = list_next (e))
    {
      entry = list_entry (e, struct frame_table_entry, lru_list_elem);

      if (!pagedir_is_accessed (entry->owner_proc->pagedir, entry->page_addr))  // reference bit = 0
        {
          if (!entry->pinned)
            {
              list_remove (&entry->lru_list_elem);
              break;
            }
        }
    }
  return entry;
}
