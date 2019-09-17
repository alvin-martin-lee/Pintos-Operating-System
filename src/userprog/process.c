#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;

static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Test if the arguments will overflow the stack.
 *
 * args_size is the total number of bytes used by the argument strings.
 * argc is the number of arguments. Simulate pushing arguments to the stack. */
static bool
will_pushing_args_overflow_stack (size_t args_size, int argc)
{
  /* Space for pushing argument strings */
  size_t total_size = args_size;

  /* Account for word padding */
  total_size = ROUND_UP (total_size, WORD_SIZE);

  total_size += sizeof (char *) * (1 + argc); // null sentinel + args addresses
  total_size += sizeof (char **) + sizeof (int); // argv + argc
  total_size += sizeof (void (*) ()); // fake return address
  return total_size > ARGS_MAX_SIZE;
}

/* Get the argument size (total bytes of tokenized string arguments)
 * and the number of arguments. If the argument size exceeds the allowed size,
 * return -1.
 *
 * This function overwrites `command` because it uses `strtok_r()`. */
static int
get_argument_stats (char *command, size_t *args_size, int *arg_count)
{
  size_t argsz = 0;
  int argc = 0;
  char *save_ptr;
  for (char *token = strtok_r (command, " ", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      argsz += strlen (token) + 1;
      argc++;
      if (argsz > ARGS_MAX_SIZE)
        {
          return -1;
        }
    }
  *args_size = argsz;
  *arg_count = argc;
  return 0;
}

/* Save tokens from `command` into the given array `argv`.
 * Assumes the number of tokens is equal to the number of elements allowed
 * in argv.*/
static void
get_argument_tokens (char *command, char *argv[], int argc)
{
  int i = 0;
  char *save_ptr;
  for (char *token = strtok_r (command, " ", &save_ptr);
       token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      ASSERT (i < argc);
      argv[i++] = token;
    }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command)
{
  /* Get the argument size and count, then check that the
   * arguments won't overflow the stack. */
  const size_t command_size = strlen (command) + 1;
  char *command_copy = malloc (command_size); // m1
  if (command_copy == NULL)
    return TID_ERROR;
  strlcpy (command_copy, command, command_size);
  size_t args_size = 0;
  int argc = 0;
  int result = get_argument_stats (command_copy, &args_size, &argc);
  if (result == -1 || will_pushing_args_overflow_stack (args_size, argc))
    {
      free (command_copy); // m1
      return TID_ERROR;
    }

  /* Collect the actual tokens into an array argv. */
  strlcpy (command_copy, command, command_size);
  char **argv = malloc (sizeof (char *) * argc); // m2
  if (argv == NULL)
    {
      free (command_copy); // m1
      return TID_ERROR;
    }
  get_argument_tokens (command_copy, argv, argc);

  /* Pass argument info into start_process. */
  struct arguments *args = malloc (sizeof (struct arguments)); // m3
  if (args == NULL)
    {
      free (command_copy); // m1
      free (argv); // m2
      return TID_ERROR;
    }
  args->argv = argv;
  args->argc = argc;

  /* for establishing the child-parent relationship in start_thread() */
  args->parent_thread = thread_current ();

  /* Create a new thread to execute the command */
  tid_t tid = thread_create (command, PRI_DEFAULT, start_process, args);
  struct thread *cur = thread_current ();
  sema_down (&cur->exec_child_sema);
  if (!cur->exec_child_success || tid == TID_ERROR)
    {
      tid = TID_ERROR;
      free (command_copy); // m1
      free (argv); // m2
      // m3 in start process
    };
  return tid;
}

/* Push a string argument to the stack and update the stack pointer. */
static void
stack_push_arg_string (void **stack_ptr, char *arg)
{
  size_t arg_size = strlen (arg) + 1;
  *stack_ptr -= arg_size;
  memcpy (*stack_ptr, arg, arg_size);
}

/* Push an address (size of a word) to the stack and update the stack pointer. */
static void
stack_push_arg_word (void **stack_ptr, void *address)
{
  *stack_ptr -= sizeof (void *);
  *((uint32_t **) *stack_ptr) = address;
}

static void
stack_push_args (struct intr_frame *if_, int argc, char **argv)
{
  /* Push string arguments to the stack. */
  void *ptr = if_->esp;
  for (int i = argc - 1; i >= 0; i--)
    {
      stack_push_arg_string (&ptr, argv[i]);
    }

  /* Word-padding and null pointer sentinel */
  ptr = (void *) ROUND_DOWN ((uintptr_t) ptr, WORD_SIZE);
  stack_push_arg_word (&ptr, NULL);

  /* Push the address of each argument */
  void *str_addr = if_->esp;
  for (int i = argc - 1; i >= 0; i--)
    {
      str_addr -= strlen (argv[i]) + 1;
      stack_push_arg_word (&ptr, str_addr);
    }
  /* Push argv, argc and fake return address (esp will point to it) */
  stack_push_arg_word (&ptr, ptr);
  stack_push_arg_word (&ptr, (void *) argc);
  stack_push_arg_word (&ptr, NULL);
  if_->esp = ptr;
}

/* Inform parent and (IMPORTANT) up semaphore */
static void
inform_parent_and_exit (struct thread *parent)
{
  parent->exec_child_success = false;
  sema_up (&parent->exec_child_sema);
  thread_exit ();
}

/* Create process tracker and link child to parent.
 *
 * If this fails due to malloc() errors, it could inform the parent and exit.
 * */
static void
setup_thread_process_tracker (struct thread *cur, const char *file_name, struct thread *parent)
{
  struct process_tracker *tmp_track = malloc (sizeof (struct process_tracker)); // m4
  if (tmp_track == NULL)
    {
      inform_parent_and_exit (parent);
    }
  char *tmp_procname = malloc (strlen (file_name) + 1); // m5
  if (tmp_procname == NULL)
    {
      free (tmp_track);
      inform_parent_and_exit (parent);
    }
  cur->tracker = tmp_track; // m4
  cur->tracker->process_name = tmp_procname; // m5
  cur->tracker->pid = cur->tid;
  cur->tracker->exited = false;
  cur->tracker->parent_thread = parent;
  list_push_back (&parent->child_process_trackers, &cur->tracker->elem);
  sema_init (&cur->tracker->wait_sema, CHILD_SEMA_INIT_VALUE);

  strlcpy (cur->tracker->process_name, file_name, strlen (file_name) + 1);
}

/* A thread function that loads a user process and starts it
 * running.
 *
 * IMPORTANT: it is assumed that THE ARGUMENTS WILL NOT OVERFLOW THE STACK.
 * This should be checked in the argument-parsing code. */
static void
start_process (void *args)
{
  struct arguments *arguments = (struct arguments *) args; // m1
  char **argv = arguments->argv; // m2
  int argc = arguments->argc;

  struct thread *parent = arguments->parent_thread;
  char *file_name = argv[0]; // m3
  struct thread *cur = thread_current ();
  setup_thread_process_tracker (cur, file_name, parent);
  free (arguments);

  spt_init (&cur->spt);

  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (file_name, &if_.eip, &if_.esp);

  /* synchronization issue when waiting for load() */
  if (!success)
    {
      list_remove (&cur->tracker->elem);
      free (cur->tracker->process_name); // m5
      free (cur->tracker); // m4
      cur->tracker->parent_thread = NULL;
      cur->tracker = NULL;
    }
  parent->exec_child_success = success;
  sema_up (&parent->exec_child_sema);

  /* If load failed, quit. */
  if (!success)
    {
      thread_exit ();
    }

  /* Denies writes to the file containing the process' executable */
  struct file *exec = filesys_open (file_name);
  file_deny_write (exec);
  cur->tracker->exec_file = exec;

  /* argument-pushing step */
  stack_push_args (&if_, argc, argv);

  /* Cleanup */
  free (argv); // m2
  free (file_name); // m3

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (pid_t child_pid)
{
  /* Find the child process with the required tid (i.e. pid)*/
  struct process_tracker *child_proc = NULL;
  struct list *children = &thread_current ()->child_process_trackers;
  for (struct list_elem *e = list_begin (children);
       e != list_end (children);
       e = list_next (e))
    {
      child_proc = list_entry(e, struct process_tracker, elem);
      if (child_proc->pid == child_pid)
        break;
    }
  if (child_proc == NULL)
    {
      return PROCESS_EXIT_FAILURE;
    }
  if (!child_proc->exited)
    {
      sema_down (&child_proc->wait_sema);
    }
  ASSERT(child_proc->exited);
  int status = child_proc->exit_status;
  list_remove (&child_proc->elem);
  free (child_proc);
  return status;
}

/* Make the current thread stop tracking exited child processes.
   This is called when the current thread is exiting.

   Technically there shouldn't be any trackers of exited child processes,
   because the current thread (as the parent) should have called wait on
   each child, in which the tracker is freed. */
static void
stop_tracking_exited_children (struct list *children)
{
  if (list_empty (children))
    {
      return;
    }
  /* children that haven't exited may still need to access their tracker.
     e.g. for printing the exit status just before it leaves. */
  struct list_elem *e = list_begin (children);
  while (e != list_end (children))
    {
      struct process_tracker *child_track = list_entry(e, struct process_tracker, elem);
      if (child_track->exited)
        {
          e = list_remove (e);
          free (child_track);
        }
      else
        {
          child_track->parent_thread = NULL;
          e = list_next (e);
        }
    }
}

/* Sets the current thread's exit code and updates trackers.
 * Called before process_exit(). */
void
process_set_exit_status (struct thread *cur, int exit_status)
{
  cur->tracker->exit_status = exit_status;
}

/* Free the current process's resources, update trackers and unblock. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  if (cur->tracker != NULL)
    {
      /* Allows writes again to the process' executable file */
      struct file *exec_file = cur->tracker->exec_file;
      if (exec_file != NULL)
        {
          file_allow_write (exec_file);
        }

      spt_munmap_all ();

      cur->tracker->exited = true;
      stop_tracking_exited_children (&cur->child_process_trackers);
      printf ("%s: exit(%d)\n", cur->tracker->process_name, cur->tracker->exit_status);
      free (cur->tracker->process_name);

      if (cur->tracker->parent_thread == NULL)
        {
          free (cur->tracker);
        }
      else
        {
          sema_up (&cur->tracker->wait_sema);
        }
    }
  /* Clean up SPT. */
  spt_destroy (&cur->spt);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  uint32_t *pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);

static bool validate_segment (const struct Elf32_Phdr *, struct file *);

static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  /* Life is fine. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (!spt_file_add (upage, !writable, file, ofs, page_read_bytes, page_zero_bytes))
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  /* Create initial stack page. */
  bool success = spt_stack_grow (((uint8_t *) PHYS_BASE) - PGSIZE);
  if (success)
    {
      *esp = PHYS_BASE;
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
