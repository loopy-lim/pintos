#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/file_descriptor.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "userprog/file_descriptor.h"
#include "vm/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void exit_(int status);
void check_user_vaddr(const void *vaddr);
void syscall_write(struct intr_frame *f);
void syscall_exit(struct intr_frame *f);
void syscall_create(struct intr_frame *f);
void syscall_open(struct intr_frame *f);
void syscall_close(struct intr_frame *f);
void syscall_read(struct intr_frame *f);
void syscall_filesize(struct intr_frame *f);
void syscall_fork(struct intr_frame *f);
void syscall_exec(struct intr_frame *f);
void syscall_wait(struct intr_frame *f);
void syscall_seek(struct intr_frame *f);
void syscall_remove(struct intr_frame *f);
void syscall_mmap(struct intr_frame *f);
void syscall_munmap(struct intr_frame *f);

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

static struct semaphore syscall_file_sema;

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

  sema_init(&syscall_file_sema, 1);
}

void exit_(int status) {
  struct thread *t = thread_current();
  t->process.exit_status = status;
  thread_exit();
}

void check_user_vaddr(const void *vaddr) {
  if (vaddr == NULL || is_kernel_vaddr(vaddr)) {
    exit_(-1);
  }
}

void syscall_write(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  int fd = f->R.rdi;
  const void *buffer = (const void *)f->R.rsi;
  unsigned size = f->R.rdx;
  check_user_vaddr(buffer);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->R.rax = size;
    sema_up(&syscall_file_sema);
    return;
  }
  if (fd == STDIN_FILENO) {
    f->R.rax = -1;
    sema_up(&syscall_file_sema);
    return;
  }
  if (fd < 2 || fd > 127) {
    f->R.rax = -1;
    sema_up(&syscall_file_sema);
    return;
  }

  f->R.rax = fd_write(fd, buffer, size);
  sema_up(&syscall_file_sema);
}

void syscall_exit(struct intr_frame *f) {
  int exit_status = f->R.rdi;
  exit_(exit_status);
}

void syscall_create(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  const char *file = (const char *)f->R.rdi;
  const unsigned initial_size = f->R.rsi;
  check_user_vaddr(file);

  if (file == NULL && strlen(file) == 0) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  off_t off_ = fd_create(file, initial_size);
  f->R.rax = off_;
  sema_up(&syscall_file_sema);
}

void syscall_open(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  const char *file = (const char *)f->R.rdi;
  check_user_vaddr(file);

  if (file == NULL && strlen(file) == 0) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  fdid_t fd = fd_open(file);
  f->R.rax = fd;
  sema_up(&syscall_file_sema);
}

void syscall_close(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  const int fd = f->R.rdi;
  if (fd < 0 || fd > 127) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  bool success = fd_close(fd);
  f->R.rax = success;
  sema_up(&syscall_file_sema);
}

void syscall_read(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  int fd = f->R.rdi;
  void *buffer = (void *)f->R.rsi;
  unsigned size = f->R.rdx;

  check_user_vaddr(buffer);

  if (fd < 0 || fd > 127) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  if (fd == STDIN_FILENO) {
    for (unsigned i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    f->R.rax = size;
    sema_up(&syscall_file_sema);
    return;
  }
  if (fd == STDOUT_FILENO) {
    f->R.rax = -1;
    sema_up(&syscall_file_sema);
    return;
  }

  uint64_t *pte = pml4e_walk(thread_current()->pml4, (uint64_t)buffer, 0);
  if (pte && (*pte != NULL) && !(*pte & PTE_W)) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  f->R.rax = fd_read(fd, buffer, size);
  sema_up(&syscall_file_sema);
}

void syscall_filesize(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  int fd = f->R.rdi;

  if (fd < 0 || fd > 127) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  off_t file_size = fd_file_size(fd);
  f->R.rax = file_size;
  sema_up(&syscall_file_sema);
}

void syscall_fork(struct intr_frame *f) {
  const char *file_name = (const char *)f->R.rdi;
  f->R.rax = process_fork(file_name, f);
}

void syscall_exec(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  char *f_name = (char *)f->R.rdi;
  check_user_vaddr(f_name);

  int f_name_len = strlen(f_name) + 1;
  if (f_name_len > PGSIZE) {
    f->R.rax = -1;
    sema_up(&syscall_file_sema);
    return;
  }

  char *f_name_copy = palloc_get_page(0);
  if (f_name_copy == NULL) {
    f->R.rax = -1;
    sema_up(&syscall_file_sema);
    return;
  }

  strlcpy(f_name_copy, f_name, PGSIZE);
  int status = process_exec(f_name_copy, &syscall_file_sema);
  exit_(status);
}

void syscall_wait(struct intr_frame *f) {
  tid_t tid = f->R.rdi;
  f->R.rax = process_wait(tid);
}

void syscall_seek(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  int fd = f->R.rdi;
  unsigned position = f->R.rsi;

  if (fd < 0 || fd > 127) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  fd_seek(fd, position);
  sema_up(&syscall_file_sema);
}

void syscall_remove(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  const char *file_name = (const char *)f->R.rdi;
  check_user_vaddr(file_name);

  if (file_name == NULL && strlen(file_name) == 0) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  bool success = fd_remove(file_name);
  f->R.rax = success;
  sema_up(&syscall_file_sema);
}

void syscall_mmap(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  void *addr = (void *)f->R.rdi;
  size_t length = (size_t)f->R.rsi;
  int writable = (int)f->R.rdx;
  int fd = (int)f->R.r10;
  off_t offset = (off_t)f->R.r8;

  if (fd < 2 || fd > 127) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }
  struct file *file = thread_current()->process.files[fd];

  if (file == NULL) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  if (file_length(file) <= 0) {
    sema_up(&syscall_file_sema);
    exit_(-1);
  }

  addr = do_mmap(addr, length, writable, file, offset);
  f->R.rax = addr;
  sema_up(&syscall_file_sema);
}

void syscall_munmap(struct intr_frame *f) {
  sema_down(&syscall_file_sema);
  void *addr = (void *)f->R.rdi;
  do_munmap(addr);
  sema_up(&syscall_file_sema);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  thread_current()->stack_pointer = f->rsp;
  switch (f->R.rax) {
    case SYS_WRITE:
      syscall_write(f);
      break;
    case SYS_EXIT:
      syscall_exit(f);
      break;
    case SYS_CREATE:
      syscall_create(f);
      break;
    case SYS_OPEN:
      syscall_open(f);
      break;
    case SYS_CLOSE:
      syscall_close(f);
      break;
    case SYS_READ:
      syscall_read(f);
      break;
    case SYS_FILESIZE:
      syscall_filesize(f);
      break;
    case SYS_FORK:
      syscall_fork(f);
      break;
    case SYS_EXEC:
      syscall_exec(f);
      break;
    case SYS_WAIT:
      syscall_wait(f);
      break;
    case SYS_SEEK:
      syscall_seek(f);
      break;
    case SYS_REMOVE:
      syscall_remove(f);
      break;
    case SYS_MMAP:
      syscall_mmap(f);
      break;
    case SYS_MUNMAP:
      syscall_munmap(f);
      break;
    default:
      printf("%lld \n", f->R.rax);
      printf("system call!\n");
      thread_exit();
      break;
  }
}
