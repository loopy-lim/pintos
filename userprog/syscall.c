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
  if (!is_user_vaddr(vaddr)) {
    exit_(-1);
  }
}

void syscall_write(struct intr_frame *f) {
  int fd = f->R.rdi;
  const void *buffer = (const void *)f->R.rsi;
  unsigned size = f->R.rdx;

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->R.rax = size;
  } else {
    f->R.rax = -1;
  }
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

  if (file == NULL) {
    exit_(-1);
  }

  if (strlen(file) == 0) {
    exit_(-1);
  }

  off_t off_ = fd_create(file, initial_size);
  f->R.rax = off_;
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
    default:
      printf("%d \n", f->R.rax);
      printf("system call!\n");
      thread_exit();
      break;
  }
}
