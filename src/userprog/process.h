#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

#define ARGS_MAX_SIZE 8388608
#define WORD_SIZE 4

#define PROCESS_EXIT_SUCCESS 0
#define PROCESS_EXIT_FAILURE (-1)

/* For passing arguments in start_process() */
struct arguments {
    /* Array of argument strings */
    char **argv;

    /* Number of strings in argv. */
    int argc;

    /* Pointer to parent to set up trackers */
    struct thread *parent_thread;
};

/* Process representation of a thread.
 *
 * This struct contains extra information needed to implement process waiting.
 * This includes the ID of the process being tracked and exit information.
 *
 * When the actual process is destroyed, this struct still exists in memory.
 * The parent can check its exit status through here, then free() it when done. */
struct process_tracker {
    /* same as tid */
    pid_t pid;

    /* Check if the parent is still in memory. */
    struct thread *parent_thread;

    /* Right before the thread gets killed, save its exit data here. */
    bool exited;
    int exit_status;

    /* 0-semaphore for process_wait() */
    struct semaphore wait_sema;

    /* Lets a parent store a list to track child processes */
    struct list_elem elem;

    /* Name of process used for process termination messages. */
    char *process_name;

    /* Executable file. */
    struct file *exec_file;
};

tid_t process_execute (const char *command);
int process_wait (tid_t);
void process_set_exit_status (struct thread *cur, int exit_status);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
