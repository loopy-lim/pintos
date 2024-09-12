#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "userprog/file_descriptor.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "userprog/exception.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct semaphore global_file_sema;

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
  sema_init(&global_file_sema, 1);
}

bool check_kernel_pointer(void *ptr) {
  if (ptr == NULL || is_kernel_vaddr(ptr) ||
      pml4e_walk(thread_current()->pml4, ptr, false) == NULL) {
    thread_current()->exit_status = -1;
    return true;
  }
  return false;
}

bool syscall_write(struct intr_frame *f) {
  if (f->R.rdi == STDOUT_FILENO) {
    putbuf((char *)f->R.rsi, f->R.rdx);
    return true;
  }
  sema_down(&global_file_sema);
  fdid_t fdid_ = f->R.rdi;
  void *buffer = (void *)f->R.rsi;
  unsigned int buffer_size = f->R.rdx;

  struct thread *curr = thread_current();
  if (check_kernel_pointer(buffer)) {
    sema_up(&global_file_sema);
    return false;
  }

  int bytes_written = write_fd(fdid_, buffer, buffer_size, curr);

  f->R.rax = bytes_written;
  sema_up(&global_file_sema);
  return true;
}

bool syscall_fork(struct intr_frame *f) {
  char *name = (char *)f->R.rdi;
  tid_t child_tid = process_fork(name, f);

  f->R.rax = child_tid;
  return true;
}

bool syscall_wait(struct intr_frame *f) {
  tid_t child_tid = f->R.rdi;
  int exit_status = process_wait(child_tid);

  f->R.rax = exit_status;
  return true;
}

bool syscall_exec(struct intr_frame *f) {
  sema_down(&global_file_sema);

  void *f_name = (void *)f->R.rdi;
  if (check_kernel_pointer(f_name)) {
    sema_up(&global_file_sema);
    return false;
  }

  int f_name_len = strlen(f_name) + 1;
  if (f_name_len > PGSIZE) {
    f->R.rax = -1;
    sema_up(&global_file_sema);
    return true;
  }

  char *f_name_copy = palloc_get_page(0);
  if (f_name_copy == NULL) {
    f->R.rax = -1;
    sema_up(&global_file_sema);
    return true;
  }

  struct thread *t = thread_current();

  strlcpy(f_name_copy, (char *)f_name, PGSIZE);
  int status = process_exec(f_name_copy, &global_file_sema);

  if (status < 0) {
    sema_up(&global_file_sema);
    t->exit_status = -1;
    return false;
  }
}

bool syscall_exit(struct intr_frame *f) {
  struct thread *curr = thread_current();
  curr->exit_status = f->R.rdi;
  thread_exit();
  return true;
}

bool syscall_create(struct intr_frame *f) {
  sema_down(&global_file_sema);
  const char *name = (const char *)f->R.rdi;
  unsigned initial_size = f->R.rsi;
  struct thread *curr = thread_current();

  if (check_kernel_pointer(name)) {
    sema_up(&global_file_sema);
    return false;
  }

  f->R.rax = filesys_create(name, initial_size);
  sema_up(&global_file_sema);
  return true;
}

bool syscall_open(struct intr_frame *f) {
  sema_down(&global_file_sema);
  const char *file_name = (const char *)f->R.rdi;
  const struct thread *curr = thread_current();

  if (check_kernel_pointer(file_name)) {
    sema_up(&global_file_sema);
    return false;
  }

  fdid_t fdid_ = open_fd(file_name, curr);

  f->R.rax = fdid_;
  sema_up(&global_file_sema);
  return true;
}

bool syscall_close(struct intr_frame *f) {
  fdid_t fdid_ = f->R.rdi;
  struct thread *curr = thread_current();
  f->R.rax = delete_fd(fdid_, curr);
  return true;
}

bool syscall_read(struct intr_frame *f) {
  fdid_t fdid_ = f->R.rdi;
  void *buffer = (void *)f->R.rsi;

  if (check_kernel_pointer(buffer)) {
    sema_up(&global_file_sema);
    return false;
  }

  unsigned int buffer_size = f->R.rdx;
  if (fdid_ == STDIN_FILENO) {
    for (unsigned int i = 0; i < buffer_size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    f->R.rax = buffer_size;
    sema_up(&global_file_sema);
    return true;
  }

  if (fdid_ == STDOUT_FILENO) {
    f->R.rax = -1;
    sema_up(&global_file_sema);
    return true;
  }
  struct thread *curr = thread_current();
  int bytes_read = read_fd(fdid_, buffer, buffer_size, curr);

  f->R.rax = bytes_read;
  return true;
}

bool syscall_file_size(struct intr_frame *f) {
  sema_down(&global_file_sema);
  fdid_t *fdid_ = f->R.rdi;
  struct thread *curr = thread_current();
  f->R.rax = file_size_fd(fdid_, curr);
  sema_up(&global_file_sema);
  return true;
}

bool syscall_file_seek(struct intr_frame *f) {
  sema_down(&global_file_sema);
  fdid_t *fdid_ = f->R.rdi;
  unsigned position = f->R.rsi;
  struct thread *curr = thread_current();
  seek_fd(fdid_, position, curr);
  sema_up(&global_file_sema);
  return true;
}

bool syscall_remove(struct intr_frame *f) {
  sema_down(&global_file_sema);
  const char *file_name = (const char *)f->R.rdi;
  f->R.rax = filesys_remove(file_name);
  sema_up(&global_file_sema);
  return true;
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  int syscall_call_number = f->R.rax;
  bool is_success = false;

  switch (syscall_call_number) {
    case SYS_WRITE:
      is_success = syscall_write(f);
      break;
    case SYS_EXIT:
      is_success = syscall_exit(f);
      break;
    case SYS_CREATE:
      is_success = syscall_create(f);
      break;
    case SYS_OPEN:
      is_success = syscall_open(f);
      break;
    case SYS_CLOSE:
      is_success = syscall_close(f);
      break;
    case SYS_READ:
      is_success = syscall_read(f);
      break;
    case SYS_FILESIZE:
      is_success = syscall_file_size(f);
      break;
    case SYS_FORK:
      is_success = syscall_fork(f);
      break;
    case SYS_WAIT:
      is_success = syscall_wait(f);
      break;
    case SYS_EXEC:
      is_success = syscall_exec(f);
      break;
    case SYS_SEEK:
      is_success = syscall_file_seek(f);
      break;
    case SYS_REMOVE:
      is_success = syscall_remove(f);
      break;
    default:
      printf("%d\n", syscall_call_number);
      printf("system call!\n");
  }

  if (!is_success) {
    thread_exit();
  }
}
