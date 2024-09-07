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

void syscall_write(struct intr_frame *f) {
  int fd = f->R.rdi;
  void *buffer = (void *)f->R.rsi;
  unsigned int buffer_size = f->R.rdx;

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, buffer_size);
  }
}

void syscall_exit(struct intr_frame *f) {
  struct thread *curr = thread_current();
  curr->exit_status = f->R.rdi;
  thread_exit();
}

void syscall_create(struct intr_frame *f) {
  const char *file = (const char *)f->R.rdi;
  unsigned initial_size = f->R.rsi;
  struct thread *curr = thread_current();

  if (file == NULL || is_kernel_vaddr(file) ||
      pml4e_walk(curr->pml4, file, false) == NULL) {
    curr->exit_status = -1;
    thread_exit();
    return;
  }

  f->R.rax = filesys_create(file, initial_size);
}

void syscall_open(struct intr_frame *f) {
  const char *file_name = (const char *)f->R.rdi;
  struct thread *curr = thread_current();

  if (file_name == NULL || is_kernel_vaddr(file_name) ||
      pml4e_walk(curr->pml4, file_name, false) == NULL) {
    curr->exit_status = -1;
    thread_exit();
    return;
  }

  int file = filesys_open(file_name);
  if (file == NULL) {
    f->R.rax = -1;
    return;
  }

  int fd = create_fd(file, curr);

  f->R.rax = fd;
}

void syscall_close(struct intr_frame *f) {
  struct fdid *fdid_ = f->R.rdi;
  if (fdid_ == STDOUT_FILENO || fdid_ == STDIN_FILENO) return;
  struct thread *curr = thread_current();
  f->R.rax = delete_fd(fdid_, curr);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  int syscall_call_number = f->R.rax;
  switch (syscall_call_number) {
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
    default:
      printf("%d\n", syscall_call_number);
      printf("system call!\n");
      thread_exit();
  }
}
