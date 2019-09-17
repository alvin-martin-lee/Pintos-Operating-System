#include <string.h>
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>

static unsigned spt_hash_func (const struct hash_elem *elem, void *aux UNUSED);
static bool spt_less_func (const struct hash_elem *a_,
                           const struct hash_elem *b_,
                           void *aux UNUSED);
bool spt_file_load (struct spt_entry *entry);
bool spt_swap_load (struct spt_entry *entry);
void perform_munmap (struct mmap_mapping *mmap, struct thread *cur);

/* Hashes an entry using the addr element as the unique identifier */
static unsigned
spt_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct spt_entry *entry = hash_entry (elem, struct spt_entry, hash_elem);
  return hash_bytes (&entry->addr, sizeof (void *));
}

/* Used for ordering elements of the spt hash table */
static bool
spt_less_func (const struct hash_elem *a_,
               const struct hash_elem *b_,
               void *aux UNUSED)
{
  const struct spt_entry *a = hash_entry (a_, struct spt_entry, hash_elem);
  const struct spt_entry *b = hash_entry (b_, struct spt_entry, hash_elem);

  return a->addr < b->addr;
}

/* Free the resources held by the SPT entry and clear the page.*/
static void
spt_destroy_func (struct hash_elem *elem, void *aux UNUSED)
{
  struct spt_entry *entry = hash_entry (elem, struct spt_entry, hash_elem);
  ASSERT (entry != NULL);
  ASSERT (!(entry->type == ERROR));

  if (entry->loaded)
    {
      /* Destroy page contents if actually loaded */
      pageptr_t kernel_page = pagedir_get_page (
          thread_current ()->pagedir, entry->addr);
      frame_free (kernel_page);
      pagedir_clear_page (thread_current ()->pagedir, entry->addr);
    }
  free (entry);
}

/* Sets up the spt hash table */
bool
spt_init (struct hash *spt)
{
  return hash_init (spt, spt_hash_func, spt_less_func, NULL);
}

/* Calls spt_destroy_func for each element of the hash table */
void
spt_destroy (struct hash *spt)
{
  hash_destroy (spt, spt_destroy_func);
}

/* Finds the spt_entry corresponding to the given user_addr */
struct spt_entry *
spt_retrieve (const void *user_addr)
{
  lock_acquire (&thread_current ()->spt_lock);

  struct spt_entry entry;
  struct hash_elem *elem;

  entry.addr = pg_round_down (user_addr);
  struct hash *spt = &thread_current ()->spt;
  elem = hash_find (spt, &entry.hash_elem);

  /* Search the hash table for corresponding element */
  struct spt_entry *result = elem != NULL ?
                             hash_entry (elem, struct spt_entry, hash_elem)
                                          : NULL;

  lock_release (&thread_current ()->spt_lock);
  return result;
}

/* Checks if an spt_entry exists for a given user_addr */
bool
spt_exists (const void *user_addr)
{
  return spt_retrieve (user_addr) != NULL;
}

/* Loads a page of content for a given spt_entry */
bool
spt_page_load (struct spt_entry *entry)
{
  /* Do not attempt to load page is already loaded */
  if (entry->loaded)
    {
      return false;
    }

  /* Delegate to specific helper function depending on spt entry type */
  switch (entry->type)
    {
      case FILE:
        return spt_file_load (entry);

      case SWAP:
        return spt_swap_load (entry);

      case MMAP:
        return spt_file_load (entry);

      default:
        return false;
    }

  NOT_REACHED ();
}

/* Helper function to load file contents of an spt_entry */
bool
spt_file_load (struct spt_entry *entry)
{
  /* SHARING */
  struct hash_iterator iterator;
  bool found = false;

  hash_first (&iterator, &frame_table);
  while (hash_next (&iterator))
    {
      /* Get the frame_table_entry */
      struct frame_table_entry *frame_table_entry =
          hash_entry (hash_cur (&iterator), struct frame_table_entry, hash_elem);

      if (frame_table_entry->file == entry->file)
        {
          entry->physical_addr = frame_table_entry->frame_addr;
          frame_table_entry->pages_shared++;
        }
    }

  pageptr_t *frame;

  if (entry->file_bytes_read > 0)
    {
      frame = frame_alloc (PAL_USER, entry->addr, entry->file);
      if (frame == NULL)
        return false;

      lock_acquire (&filesys_lock);
      if (file_read_at (entry->file, frame, entry->file_bytes_read, entry->file_offset)
          != (int) entry->file_bytes_read)
        {
          frame_free (frame);
          return false;
        }
      memset (frame + entry->file_bytes_read, 0, entry->file_bytes_zero);
      lock_release (&filesys_lock);
    }
  else
    {
      frame = frame_alloc (PAL_USER | PAL_ZERO, entry->addr, entry->file);
      if (frame == NULL)
        return false;
    }

  /* Try and install the page, return an error if unsuccessful */
  if (!install_page (entry->addr, frame, !entry->read_only))
    {
      frame_free (frame);
      return false;
    }

  entry->loaded = true;
  return true;
}

/* Helper function to load swap contents of an spt_entry */
bool
spt_swap_load (struct spt_entry *entry)
{
  /* Get a page of memory. */
  pageptr_t *frame = frame_alloc (PAL_USER, entry, NULL);
  if (frame == NULL)
    return false;

  /* Add the page to the process's address space. */
  if (!install_page (entry->addr, frame, !entry->read_only))
    {
      frame_free (frame);
      return false;
    }

  /* Perform the actual swap load */
  swap_load (entry->swap_num, entry->addr);

  entry->loaded = true;
  return true;
}


/* Creates an spt_entry for a file and stores it in the spt hash table */
bool
spt_file_add (void *user_addr, bool read_only, struct file *file,
              off_t offset, off_t bytes_read, off_t bytes_zero)
{
  lock_acquire (&thread_current ()->spt_lock);
  struct hash *spt = &thread_current ()->spt;
  struct spt_entry *entry = malloc (sizeof (struct spt_entry));
  if (entry == NULL)
    {
      lock_release (&thread_current ()->spt_lock);
      return false;
    }

  /* Setup the spt_entry properties */
  entry->type = FILE;
  entry->addr = user_addr;
  entry->loaded = false;
  entry->read_only = read_only;
  entry->file = file;
  entry->file_offset = offset;
  entry->file_bytes_read = bytes_read;
  entry->file_bytes_zero = bytes_zero;

  /* Push the new spt_entry into the hash table */
  struct hash_elem *result = hash_insert (spt, &entry->hash_elem);
  lock_release (&thread_current ()->spt_lock);
  return result == NULL;
}

/* Creates an spt_entry for a memory mapping and stores it in the spt hash table */
mapid_t
spt_mmap_add (void *addr, struct file *file, int filesize)
{
  struct thread *cur = thread_current ();
  lock_acquire (&cur->spt_lock);
  struct hash *spt = &cur->spt;

  mapid_t mapid = cur->next_mmap_id;

  for (int offset = 0; filesize > 0;
       addr += PGSIZE, offset += PGSIZE, filesize -= PGSIZE)
    {
      struct spt_entry *entry = malloc (sizeof (struct spt_entry));
      if (entry == NULL)
        {
          lock_release (&thread_current ()->spt_lock);
          return ERROR_ID;
        }

      /* Setup the spt_entry properties */
      entry->type = MMAP;
      entry->addr = addr;
      entry->loaded = false;
      entry->read_only = false;
      entry->file = file_reopen (file);
      entry->file_offset = offset;

      int file_size_delta = PGSIZE - filesize;
      if (file_size_delta > 0)
        {
          entry->file_bytes_read = filesize;
          entry->file_bytes_zero = PGSIZE - filesize;
        }
      else
        {
          entry->file_bytes_read = PGSIZE;
          entry->file_bytes_zero = 0;
        }

      /* Push the new spt_entry into the hash table */
      struct hash_elem *result = hash_insert (spt, &entry->hash_elem);
      if (result != NULL)
        {
          spt_munmap (mapid);
          lock_release (&cur->spt_lock);
          return ERROR_ID;
        }

      /* Push the mapping into the thread mapping list */
      struct mmap_mapping *mmap_list_entry =
          malloc (sizeof (struct mmap_mapping));
      if (mmap_list_entry == NULL)
        {
          spt_munmap (mapid);
          lock_release (&cur->spt_lock);
          return ERROR_ID;
        }
      mmap_list_entry->mapid = mapid;
      mmap_list_entry->entry = entry;
      list_push_back (&cur->mmap_list, &mmap_list_entry->elem);
    }

  cur->next_mmap_id++;
  lock_release (&cur->spt_lock);
  return mapid;
}

/* Removes the given memory mapping */
void
spt_munmap (mapid_t target_mapid)
{
  struct thread *cur = thread_current ();
  lock_acquire (&cur->spt_lock);
  struct list *mmap_list = &cur->mmap_list;

  struct list_elem *elem, *next;

  /* Search for the mapping in the thread mapping list */
  for (elem = list_begin (mmap_list); elem != list_end (mmap_list);)
    {
      next = list_next (elem);
      struct mmap_mapping *mmap = list_entry (elem,
                                              struct mmap_mapping, elem);

      if (mmap->mapid == target_mapid)
        {
          /* Delegate unmapping to helper function */
          perform_munmap (mmap, cur);
        }

      elem = next;
    }

  lock_release (&cur->spt_lock);
}

/* Removes all memory mappings */
void
spt_munmap_all (void)
{
  struct thread *cur = thread_current ();
  lock_acquire (&cur->spt_lock);
  struct list *mmap_list = &cur->mmap_list;

  struct list_elem *elem, *next;

  /* Iterate through mapping list */
  for (elem = list_begin (mmap_list); elem != list_end (mmap_list);)
    {
      next = list_next (elem);
      struct mmap_mapping *mmap = list_entry (elem,
                                              struct mmap_mapping, elem);

      /* Call unmapping helper function for each element in list */
      perform_munmap (mmap, cur);

      elem = next;
    }

  lock_release (&cur->spt_lock);
}

/* Helper function to perform that actual unmapping and removal of the spt_entry */
void
perform_munmap (struct mmap_mapping *mmap, struct thread *cur)
{
  struct spt_entry *entry = mmap->entry;

  if (entry->loaded)
    {
      /* Only unload components if page was actually loaded */
      if (pagedir_is_dirty (cur->pagedir, entry->addr) && !entry->read_only)
        {
          lock_acquire (&filesys_lock);
          file_write_at (entry->file, entry->addr,
                         entry->file_bytes_read, entry->file_offset);
          lock_release (&filesys_lock);
        }

      frame_free (pagedir_get_page (cur->pagedir, entry->addr));
      pagedir_clear_page (cur->pagedir, entry->addr);
    }

  /* Delete the entry from the spt table */
  hash_delete (&cur->spt, &entry->hash_elem);

  if (entry->file != NULL)
    {
      /* Close the mapped file, if it exists */
      lock_acquire (&filesys_lock);
      file_close (entry->file);
      lock_release (&filesys_lock);
    }

  list_remove (&mmap->elem);

  free (mmap);
  free (entry);
}

/* If the provided user virtual address is a stack access, attempt to
   allocate extra memory for the stack.

   ESP is the current stack pointer. It is the esp member of struct intr_frame
   passed to syscall_handler() in a system call or to page_fault(). */
bool
spt_stack_grow (const void *user_addr)
{
  struct spt_entry *entry = malloc (sizeof (struct spt_entry));
  ASSERT (entry != NULL);

  /* Setup the spt_entry properties */
  entry->addr = pg_round_down (user_addr);
  entry->loaded = true;
  entry->read_only = false;
  entry->type = SWAP;
  entry->file = NULL;
  pageptr_t frame = frame_alloc (PAL_USER | PAL_ZERO, entry->addr, NULL);

  if (!frame)
    {
      free (entry);
      return false;
    }

  /* Try and install the page, return an error if unsuccessful */
  if (!install_page (entry->addr, frame, !entry->read_only))
    {
      frame_free (frame);
      free (entry);
      return false;
    }

  /* Push the new spt_entry into the spt hash table */
  struct hash_elem *result = hash_insert (&thread_current ()->spt, &entry->hash_elem);
  return result == NULL;
}

/* Checks if a user pointer refers to a valid stack access. */
bool
is_valid_stack_access (const void *user_addr, void *esp)
{
  return user_addr != NULL && is_user_vaddr (user_addr) && // in user space
         (user_addr >= esp // within stack area (allowing PUSHA / PUSH)
          || user_addr == esp - PUSH_PGFAULT_STK_OFFSET
          || user_addr == esp - PUSHA_PGFAULT_STK_OFFSET) &&
         (uintptr_t) user_addr >= USER_START && // before code segment
         PHYS_BASE - pg_round_down (user_addr)
         <= MAX_STACK_SIZE; // address not beyond max. stack size
}
