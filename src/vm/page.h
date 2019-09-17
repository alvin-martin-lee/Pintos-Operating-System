#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

#define PUSHA_PGFAULT_STK_OFFSET 32
#define PUSH_PGFAULT_STK_OFFSET 4
#define ERROR_ID -1;

/* 8 MB on GNU/Linux systems. */
#define MAX_STACK_SIZE 8388608

/* Enum of the different types of pages that can be added to SPT */
enum spt_entry_type {
  ERROR,
  FILE,
  MMAP,
  SWAP
};

/* SPT Entry that holds additional data about each page */
struct spt_entry {
    /* Hash elem for spt hash table */
    struct hash_elem hash_elem;

    /* Type of page */
    enum spt_entry_type type;

    /* Address of the page */
    void *addr;
    void *physical_addr;

    /* --- Page flags --- */

    /* If the current page is loaded in VM */
    bool loaded;     

    /* If the page is writable/read-only */
    bool read_only;  

    /* --- For use with type = FILE or MMAP --- */

    /* Pointer to file contained on the page */
    struct file *file;     

    /* Current file_offset */
    off_t file_offset;   

    /* Number of bytes read into the page */
    off_t file_bytes_read;

    /* Number of zero bytes on the page */
    off_t file_bytes_zero;

    /* --- For use with type = SWAP --- */

    /* Swap slot ID number */
    int swap_num;
};

/* Functions to create and work with spt entries */
bool spt_init (struct hash *spt);
void spt_destroy (struct hash *spt);
struct spt_entry* spt_retrieve (const void *user_addr);
bool spt_exists (const void *user_addr);
bool spt_page_load (struct spt_entry *entry);
bool spt_file_add (void *user_addr, bool read_only, struct file *file,
                   off_t offset, off_t bytes_read, off_t bytes_zero);
mapid_t spt_mmap_add (void *addr, struct file *file, int filesize);
void spt_munmap (mapid_t target_mapid);
void spt_munmap_all (void);
bool spt_stack_grow (const void *user_addr);
bool is_valid_stack_access (const void *user_addr, void *esp);

#endif
