#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <list.h>
#include <stdint.h>
#include "userprog/exception.h"
#include "threads/synch.h"

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* Max number of arguments in syscall */
#define MAX_ARGS 3

/* Lock for the file system */
struct lock filesys_lock;

/* Holds details of the system call */
struct syscall_details {
  /* Interrupt frame of the system call */
  struct intr_frame *f;

  /* Reference to stack pointer */
  void *esp;

  /* System arguments */
  uint32_t args[MAX_ARGS];
};

/* Wrapper for file handling in syscalls - Maps fds to files */
struct file_mapping {
  /* List elem for file_list */
  struct list_elem elem;

  /* Thread unique file descriptor number */
  int fd;

  /* Pointer to open file */
  struct file *file;
};

/* Wrapper for mapping spt_entrys to mapids */
struct mmap_mapping {
  /* List elem for mmap_list */
  struct list_elem elem;

  /* Thread unique mmap identifier */
  mapid_t mapid;

  /* Pointer to an spt_entry within the process/thread's spt */
  struct spt_entry *entry;
};

void syscall_init (void);

struct file_mapping *get_file_mapping (int fd);
struct file *get_file (int fd);

#endif /* userprog/syscall.h */
