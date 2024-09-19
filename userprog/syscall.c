#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/file_descriptor.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/flags.h"
#include "intrinsic.h"

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

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void exit_(int status) {
  struct thread *t = thread_current();
  t->process.exit_status = status;
  thread_exit();
}

void check_user_vaddr(const void *vaddr) {
  if (vaddr == NULL || is_kernel_vaddr(vaddr) ||
      pml4e_walk(thread_current()->pml4, vaddr, false) == NULL) {
    exit_(-1);
  }
}

void syscall_write(struct intr_frame *f) {
  int fd = f->R.rdi;
  const void *buffer = (const void *)f->R.rsi;
  unsigned size = f->R.rdx;
  check_user_vaddr(buffer);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->R.rax = size;
    return;
  }
  if (fd == STDIN_FILENO) {
    f->R.rax = -1;
    return;
  }
  if (fd < 2 || fd > 127) {
    f->R.rax = -1;
    return;
  }

  f->R.rax = fd_write(fd, buffer, size);
}

void syscall_exit(struct intr_frame *f) {
  int exit_status = f->R.rdi;
  struct thread *t = thread_current();
  t->process.exit_status = exit_status;
  thread_exit();
}

void syscall_create(struct intr_frame *f) {
  const char *file = (const char *)f->R.rdi;
  const unsigned initial_size = f->R.rsi;
  check_user_vaddr(file);

  if (file == NULL && strlen(file) == 0) {
    exit_(-1);
  }

  off_t off_ = fd_create(file, initial_size);
  f->R.rax = off_;
}

void syscall_open(struct intr_frame *f) {
  const char *file = (const char *)f->R.rdi;
  check_user_vaddr(file);

  if (file == NULL && strlen(file) == 0) {
    exit_(-1);
  }

  fdid_t fd = fd_open(file);
  f->R.rax = fd;
}

void syscall_close(struct intr_frame *f) {
  const int fd = f->R.rdi;
  if (fd < 0 || fd > 127) {
    exit_(-1);
  }

  bool success = fd_close(fd);
  f->R.rax = success;
}

void syscall_read(struct intr_frame *f) {
  int fd = f->R.rdi;
  void *buffer = (void *)f->R.rsi;
  unsigned size = f->R.rdx;

  check_user_vaddr(buffer);

  if (fd < 0 || fd > 127) {
    exit_(-1);
  }

  if (fd == STDIN_FILENO) {
    for (unsigned i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    f->R.rax = size;
    return;
  }
  if (fd == STDOUT_FILENO) {
    f->R.rax = -1;
    return;
  }
  f->R.rax = fd_read(fd, buffer, size);
}

void syscall_filesize(struct intr_frame *f) {
  int fd = f->R.rdi;

  if (fd < 0 || fd > 127) {
    exit_(-1);
  }

  off_t file_size = fd_file_size(fd);
  f->R.rax = file_size;
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
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
    default:
      printf("%lld \n", f->R.rax);
      printf("system call!\n");
      thread_exit();
      break;
  }
}
