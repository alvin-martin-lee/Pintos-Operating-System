#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <hash.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"

#define WRITE_FAILURE 0;

/* Lock for the file system */
struct lock filesys_lock;

/* Local helper functions */
static void get_args (uint32_t *syscall_args, void *esp);
static void syscall_handler (struct intr_frame *);
static int get_file_size (int fd);
static void validate_pointer (const void *addr, bool check_spt_exists);
static struct spt_entry *get_spt_at_addr (void *addr, void *esp);
static void *
get_buffer_at_addr (void *addr_start, size_t nbytes, void *esp, bool read_only);
static char *get_string_at_addr (void *addr_start);
static bool check_spt (const void *ptr, void *esp);
static void exit_error (void);

/* Implementation ofthe actual syscalls */
static void syscall_halt (struct syscall_details *sd);
static void syscall_exit (struct syscall_details *sd);
static void syscall_exec (struct syscall_details *sd);
static void syscall_wait (struct syscall_details *sd);
static void syscall_create (struct syscall_details *sd);
static void syscall_remove (struct syscall_details *sd);
static void syscall_open (struct syscall_details *sd);
static void syscall_filesize (struct syscall_details *sd);
static void syscall_read (struct syscall_details *sd);
static void syscall_write (struct syscall_details *sd);
static void syscall_seek (struct syscall_details *sd);
static void syscall_tell (struct syscall_details *sd);
static void syscall_close (struct syscall_details *sd);
static void syscall_mmap (struct syscall_details *sd);
static void syscall_munmap (struct syscall_details *sd);

/* Register the syscall_handler to trigger on interrupts */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init (&filesys_lock);
}

/* Check if a user-provided pointer has a corresponding entry in SPT. */
static bool
check_spt (const void *ptr, void *esp)
{
  struct spt_entry *entry = spt_retrieve (ptr);
  /* page could be in swap.*/
  if (entry != NULL)
    {
      if (!entry->loaded)
        {
          spt_page_load (entry);
        }
    }
  else if (is_valid_stack_access (ptr, esp) && ptr >= esp - USER_START)
    {
      spt_stack_grow (ptr);
      entry = spt_retrieve (ptr);
      ASSERT (entry != NULL); /* assume stack growth was successful */
    }
  else
    {
      return false;
    }
  return entry->loaded;
}

/* Retrieves the system arguements */
static void
get_args (uint32_t *syscall_args, void *esp)
{
  uint32_t *arg_ptr = esp;

  for (int i = 0; i < MAX_ARGS; i++)
    {
      arg_ptr++;

      /* Check if ptr is a valid pointer. */
      validate_pointer (arg_ptr, true);
      syscall_args[i] = *arg_ptr;
    }
}

/* Processes system calls */
static void
syscall_handler (struct intr_frame *f)
{
  void *esp = f->esp;

  validate_pointer (f->esp, true);

  uint32_t syscall_number = *(uint32_t *) esp;

  static void (*syscall_funcs[]) (struct syscall_details *sd) = {
      syscall_halt,
      syscall_exit,
      syscall_exec,
      syscall_wait,
      syscall_create,
      syscall_remove,
      syscall_open,
      syscall_filesize,
      syscall_read,
      syscall_write,
      syscall_seek,
      syscall_tell,
      syscall_close,
      syscall_mmap,
      syscall_munmap
  };

  /* Calls the appropriate functions to carry out the system call */
  if (syscall_number < sizeof (syscall_funcs) / sizeof (*syscall_funcs))
    {
      struct syscall_details *sd = &(struct syscall_details) {.f = f, .esp = f->esp};
      get_args (sd->args, sd->esp);
      syscall_funcs[syscall_number] (sd);
    }
  else
    {
      printf ("Invalid syscall number\n");
      exit_error ();
    }
}

/* Terminates Pintos */
static void
syscall_halt (struct syscall_details *sd UNUSED)
{
  shutdown_power_off ();
}

/* Terminates the current user program, sending its exit status to the kernel.
 * If the process's parent waits for it (see below), this is the status that
 * will be returned */
static void
syscall_exit (struct syscall_details *sd)
{
  int status = (int) sd->args[0];

  struct thread *cur = thread_current ();
  struct list *file_list = &cur->file_list;

  /* Frees all file mappings */
  while (!list_empty (file_list))
    {
      struct list_elem *e = list_pop_front (file_list);
      struct file_mapping *f_map = list_entry (e, struct file_mapping, elem);
      free (f_map);
    }

  process_set_exit_status (thread_current (), status);
  thread_exit ();
}

/* Runs the executable whose name is given in cmd line, passing any given
 * arguments, and returns the new process's program id (pid). */
static void
syscall_exec (struct syscall_details *sd)
{
  const char *cmd_line = get_string_at_addr ((void *) sd->args[0]);

  sd->f->eax = process_execute (cmd_line);
}

/* Waits for a child process pid and retrieves the child's exit status */
static void
syscall_wait (struct syscall_details *sd)
{
  pid_t pid = (pid_t) sd->args[0];

  sd->f->eax = process_wait (pid);
}

/* Creates a newly called initially initial size bytes in size */
static void
syscall_create (struct syscall_details *sd)
{
  const char *filename = get_string_at_addr ((void *) sd->args[0]);

  unsigned initial_size = (unsigned) sd->args[1];

  lock_acquire (&filesys_lock);
  bool did_create = filesys_create (filename, initial_size);
  lock_release (&filesys_lock);

  sd->f->eax = did_create;
}

/* Deletes the file called file.*/
static void
syscall_remove (struct syscall_details *sd)
{
  const char *filename = get_string_at_addr ((void *) sd->args[0]);

  lock_acquire (&filesys_lock);
  bool did_remove = filesys_remove (filename);
  lock_release (&filesys_lock);

  sd->f->eax = did_remove;
}

/* Opens the file called file */
static void
syscall_open (struct syscall_details *sd)
{
  const char *filename = get_string_at_addr ((void *) sd->args[0]);

  lock_acquire (&filesys_lock);
  struct file *file_ptr = filesys_open (filename);

  if (file_ptr)
    {
      /* Adds file to the file mapping system */
      struct thread *cur = thread_current ();
      struct file_mapping *f_map = malloc (sizeof (struct file_mapping));

      if (f_map)
        {
          /* Set f_mad id to next available, then increment next available */
          f_map->fd = cur->next_fd_id;
          cur->next_fd_id++;
          f_map->file = file_ptr;

          list_push_back (&cur->file_list, &f_map->elem);

          sd->f->eax = f_map->fd;
        }
      lock_release (&filesys_lock);
    }
  else
    {
      /* Could not open file from provided pointer */
      lock_release (&filesys_lock);
      sd->f->eax = PROCESS_EXIT_FAILURE;
    }
}

/* Returns the size, in bytes, of the file open as fd */
static void
syscall_filesize (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];

  sd->f->eax = get_file_size (fd);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 * of bytes actually read */
static void
syscall_read (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];
  unsigned size = (unsigned) sd->args[2];
  void *buffer = get_buffer_at_addr ((void *) sd->args[1], (size_t) size, sd->esp, false);

  /* Prevents writing to a read-only memory region. */
  struct spt_entry *entry = spt_retrieve ((void *) sd->args[1]);
  if (entry->type == FILE && entry->read_only)
    {
      exit_error ();
    }

  /* Checks if fd is STDIN_FILENO and hence keyboard input */
  if (fd == STDIN_FILENO)
    {
      for (unsigned i = 0; i < size; i++)
        {
          input_putc (input_getc ());
        }

      sd->f->eax = size;
    }
  else
    {

      /* Open a file from memory */
      lock_acquire (&filesys_lock);
      struct file *file_ptr = get_file (fd);

      if (file_ptr)
        {
          sd->f->eax = file_read (file_ptr, buffer, size);
        }
      else
        {
          sd->f->eax = PROCESS_EXIT_FAILURE;
        }

      lock_release (&filesys_lock);
    }
}

/* Writes size bytes from buffer to the open file fd
 * Returns the number of bytes actually written */
static void
syscall_write (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];
  unsigned size = (unsigned) sd->args[2];
  const void *buffer = get_buffer_at_addr ((void *) sd->args[1], (size_t) size, sd->esp, true);

  /* Writing to console */
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      sd->f->eax = size;
    }
  else
    {
      /* Write to a file */
      lock_acquire (&filesys_lock);
      struct file *file_ptr = get_file (fd);

      if (file_ptr)
        {
          sd->f->eax = file_write (file_ptr, buffer, size);
        }
      else
        {
          sd->f->eax = WRITE_FAILURE;
        }

      lock_release (&filesys_lock);
    }
}

/* Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file */
static void
syscall_seek (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];
  unsigned position = (unsigned) sd->args[1];

  lock_acquire (&filesys_lock);
  struct file *file_ptr = get_file (fd);
  file_seek (file_ptr, position);
  lock_release (&filesys_lock);
}

/* Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file. */
static void
syscall_tell (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];

  lock_acquire (&filesys_lock);
  struct file *file_ptr = get_file (fd);
  unsigned pos = file_tell (file_ptr);
  lock_release (&filesys_lock);

  sd->f->eax = pos;
}

/* Closes file descriptor fd */
static void
syscall_close (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];

  if (fd != STDOUT_FILENO && fd != STDIN_FILENO)
    {
      lock_acquire (&filesys_lock);
      struct file_mapping *f_map = get_file_mapping (fd);

      if (f_map)
        {
          file_close (f_map->file);
          list_remove (&f_map->elem);
          free (f_map);
        }

      lock_release (&filesys_lock);
    }
}

/* Maps file fd into address addr */
static void
syscall_mmap (struct syscall_details *sd)
{
  int fd = (int) sd->args[0];
  void *addr = (void *) sd->args[1];

  struct file *file = get_file (fd);
  int filesize = get_file_size (fd);

  if (file && fd != 0 && fd != 1 && filesize > 0 && addr != 0 &&
      is_user_vaddr (addr) && (int) addr % PGSIZE == 0)
    {
      /* Checks whether new mapping will overlap existing segments */
      int test_addr = (int) addr;
      for (int f_size = filesize; f_size >= 0;
           test_addr += PGSIZE, f_size -= PGSIZE)
        {
          if (check_spt ((void *) test_addr, sd->esp))
            {
              /* There is already an entry at test_addr */
              sd->f->eax = MAP_FAILED;
              return;
            }
        }

      /* MMAP CREATION AND HANDLING */
      sd->f->eax = spt_mmap_add (addr, file, filesize);
      return;
    }

  sd->f->eax = MAP_FAILED;
}

/* Unmaps the mapping given by mapping */
static void
syscall_munmap (struct syscall_details *sd)
{
  mapid_t mapping = (mapid_t) sd->args[0];

  if (mapping < 1)
    {
      /* Invalid mapping number */
      return;
    }

  spt_munmap (mapping);
}

/* Retrieves the file_mapping structure of a particular fd, NULL if not found */
struct file_mapping *
get_file_mapping (int fd)
{
  struct thread *cur = thread_current ();
  struct list *file_list = &cur->file_list;

  struct list_elem *e;

  /* Search for fd in current thread's file_list */
  for (e = list_begin (file_list); e != list_end (file_list);
       e = list_next (e))
    {
      struct file_mapping *f_map = list_entry (e, struct file_mapping, elem);

      if (f_map->fd == fd)
        {
          return f_map;
        }
    }

  return NULL;
}

/* Retrieves the file structure of a particular fd, NULL if not found */
struct file *
get_file (int fd)
{
  struct file_mapping *f_map = get_file_mapping (fd);

  if (f_map)
    {
      return f_map->file;
    }
  else
    {
      return NULL;
    }
}

/* Returns the size of the file given by fd */
int
get_file_size (int fd)
{
  int filesize = 0;

  lock_acquire (&filesys_lock);
  struct file *file_ptr = get_file (fd);
  if (file_ptr)
    {
      filesize = file_length (file_ptr);
    }
  lock_release (&filesys_lock);

  return filesize;
}

/* Checks that a pointer is valid and, optionally, that an spt entry at that
   address also exists */
static void
validate_pointer (const void *addr, bool check_spt_exists)
{
  if (!(addr >= (void *) USER_START && is_user_vaddr (addr)))
    {
      exit_error ();
    }

  if (check_spt_exists && !spt_exists (addr))
    {
      exit_error ();
    }
}

/* Returns a pointer to an spt entry with the virtual address addr */
static struct spt_entry *
get_spt_at_addr (void *addr, void *esp)
{
  validate_pointer (addr, false);

  if (!check_spt (addr, esp))
    {
      exit_error ();
    }

  /* entry is guaranteed to exist due to earlier calls */
  struct spt_entry *entry = spt_retrieve (addr);

  return entry;
}

/* Get a buffer of size `nbytes` starting and the given pointer, NULL otherwise.
 *
 * Steps are as follows:
 * - Check the starting address `addr_start`.
 * - If the data is within the same page then no further checks are needed.
 * - Otherwise, the data spans across multiple contiguous pages, each has
 * - to be checked. */
static void *
get_buffer_at_addr (void *addr_start, size_t nbytes, void *esp, bool read_only)
{
  size_t processed = 0;
  uint8_t *addr = (uint8_t *) addr_start;

  /* Validate each byte individually */
  while (processed < nbytes)
    {
      struct spt_entry *entry = get_spt_at_addr ((void *) addr, esp);

      if (!read_only && entry != NULL && entry->read_only)
        {
          exit_error ();
        }

      addr++;
      processed++;
    }

  /* Buffer all valid, so can return pointer to buffer */
  return addr_start;
}

/* Return a string starting at the given address, or exits as an error if
 * it is invalid.
 *
 * The size of the string need not be known. This function
 * scans until a null-terminator is reached. */
static char *
get_string_at_addr (void *addr_start)
{
  /* Perform an initial validation to allow deferencing during the for loop */
  validate_pointer (addr_start, true);

  /* Validate each byte until an error or null terminator */
  for (uint8_t *addr = addr_start; *addr != '\0'; addr++)
    {
      validate_pointer (addr, true);
    }

  /* String valid, so can return casted pointer to string */
  return (char *) addr_start;
}

/* Helper function to clean up and exit (e.g. in case of bad parameters) */
static void
exit_error (void)
{
  struct thread *cur = thread_current ();
  struct list *file_list = &cur->file_list;

  while (!list_empty (file_list))
    {
      struct list_elem *e = list_pop_front (file_list);
      struct file_mapping *f_map = list_entry (e, struct file_mapping, elem);
      free (f_map);
    }

  process_set_exit_status (thread_current (), PROCESS_EXIT_FAILURE);
  thread_exit ();
}
