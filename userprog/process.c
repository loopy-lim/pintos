#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/file_descriptor.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "../threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
struct process *get_child_process(tid_t tid);

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  char *save_ptr;
  file_name = strtok_r(file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
  if (tid == TID_ERROR) palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  process_init();

  if (process_exec(f_name, NULL) < 0) PANIC("Fail to launch initd\n");
  NOT_REACHED();
}

struct process_fork_args {
  struct intr_frame *if_;
  struct thread *parent;
  struct semaphore sema;
  int status;
};

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
  struct process_fork_args args;
  args.if_ = if_;
  args.parent = thread_current();
  sema_init(&args.sema, 0);
  tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, &args);

  sema_down(&args.sema);
  return args.status;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct thread *current = thread_current();
  struct thread *parent = (struct thread *)aux;
  void *parent_page;
  void *newpage;
  bool writable;

  if (is_kern_pte(pte)) return true;

  parent_page = pml4_get_page(parent->pml4, va);
  if (parent_page == NULL) return false;

  newpage = palloc_get_page(PAL_USER);
  if (newpage == NULL) return false;

  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);

  if (!pml4_set_page(current->pml4, va, newpage, writable)) {
    palloc_free_page(newpage);
    return false;
  }
  return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux) {
  struct intr_frame if_;
  struct process_fork_args *args = aux;
  struct thread *parent = args->parent;
  struct thread *current = thread_current();
  struct intr_frame *parent_if = args->if_;
  bool succ = true;

  /* 1. Read the cpu context to local stack. */
  memcpy(&if_, parent_if, sizeof(struct intr_frame));

  /* 2. Duplicate PT */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL) goto error;

  process_activate(current);
#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

  bool is_success_duplicate =
      fd_duplicates(&parent->process, &current->process);
  if (!is_success_duplicate) goto error;

  if_.R.rax = 0;

  current->process.parent = &parent->process;
  current->process.self_file = file_duplicate(parent->process.self_file);
  if (current->process.self_file == NULL) goto error;

  process_init();
  args->status = current->tid;
  sema_up(&args->sema);

  /* Finally, switch to the newly created process. */
  if (succ) do_iret(&if_);
error:
  args->status = -1;
  current->process.exit_status = -1;
  list_remove(&current->process.elem);
  sema_up(&args->sema);
  sema_up(&current->process.sema_exit);
  thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name, struct semaphore *sema) {
  char *file_name = f_name;
  bool success;

  /* We cannot use the intr_frame in the thread structure.
   * This is because when current thread rescheduled,
   * it stores the execution information to the member. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  /* We first kill the current context */
  process_cleanup();

  /* And then load the binary */
  success = load(file_name, &_if);

  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (sema != NULL) sema_up(sema);
  if (!success) return -1;

  /* Start switched process. */
  do_iret(&_if);
  NOT_REACHED();
}

struct process *get_child_process(tid_t tid) {
  struct process *current = &thread_current()->process;
  struct list_elem *e;

  for (e = list_begin(&current->children); e != list_end(&current->children);
       e = list_next(e)) {
    struct process *p = list_entry(e, struct process, elem);
    if (p->self->tid == tid) return p;
  }
  return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
  struct process *child = get_child_process(child_tid);
  struct thread *curr = thread_current();

  if (child == NULL) return -1;

  struct list_elem *e;
  for (e = list_begin(&child->sema_wait.waiters);
       e != list_end(&child->sema_wait.waiters); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, elem);
    if (t->tid == curr->tid) return -1;
  }

  sema_down(&child->sema_wait);
  int status = child->exit_status;
  printf("%s: exit(%d)\n", child->self->name, child->exit_status);
  list_remove(&child->elem);
  sema_up(&child->sema_exit);
  return status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  struct thread *curr = thread_current();

  sema_up(&curr->process.sema_wait);
  fd_clean_up_by(&curr->process);
  process_cleanup();
  sema_down(&curr->process.sema_exit);
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;

  if (curr->process.self_file != NULL) {
    file_close(curr->process.self_file);
    curr->process.self_file = NULL;
  }

  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();
  if (t->pml4 == NULL) goto done;
  process_activate(t);

  char *token, *save_ptr;
  token = strtok_r(file_name, " ", &save_ptr);

  /* Open executable file. */
  file = filesys_open(token);
  if (file == NULL) {
    printf("load: %s: open failed\n", token);
    goto done;
  }
  t->process.self_file = file;
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
      ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
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
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint64_t file_page = phdr.p_offset & ~PGMASK;
          uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint64_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             * Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes =
                (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             * Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                            zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_)) goto done;

  /* Start address. */
  if_->rip = ehdr.e_entry;

  void *stack_pointer = if_->rsp - 8;
  int char_size;
  int argc = 0;
  char **argv[64] = {
      NULL,
  };

  do {
    char_size = strlen(token) + 1;
    stack_pointer -= char_size;
    memcpy(stack_pointer, token, char_size);
    argv[argc++] = stack_pointer;
    token = strtok_r(NULL, " ", &save_ptr);
  } while (token != NULL);

  stack_pointer = ROUND_DOWN((unsigned long long)stack_pointer, 8);

  for (int i = argc; i >= 0; i--) {
    stack_pointer -= 8;
    memcpy(stack_pointer, &argv[i], 8);
  }

  if_->R.rdi = argc;
  if_->R.rsi = (int)stack_pointer;

  stack_pointer -= 8;
  *(int *)stack_pointer = 0;

  if_->rsp = stack_pointer;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL &&
          pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on
 * the upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
  /* TODO: Load the segment from the file */
  /* TODO: This called when the first page fault occurs on address VA. */
  /* TODO: VA is available when calling this function. */
  struct load_seg *seg = aux;
  struct file *file = seg->file;
  size_t page_read_byte = seg->page_read_bytes;
  size_t page_zero_byte = seg->page_zero_bytes;
  off_t offset = seg->offset;

  struct frame *frame = page->frame;

  file_seek(file, offset);
  if (file_read(file, frame->kva, page_read_byte) != (int)page_read_byte) {
    return false;
  }
  // file_read(file,frame->kva, page_read_byte);
  memset(frame->kva + page_read_byte, 0, page_zero_byte);

  free(aux);
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Set up aux to pass information to the lazy_load_segment. */
    // 세그먼트에 넣을 정보를 aux를 통해서 전달해라.
    struct load_seg *aux = malloc(sizeof(struct load_seg));
    aux->file = file;
    aux->offset = ofs;
    aux->page_read_bytes = page_read_bytes;
    aux->page_zero_bytes = page_zero_bytes;
    aux->type = VM_ANON;  // spt에 있어도 되려나??

    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                        lazy_load_segment, aux))
      return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    // ofs+=page_read_bytes-page_zero_bytes;
    ofs += page_read_bytes;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  bool success = false;
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* TODO: Map the stack on stack_bottom and claim the page immediately.
   * TODO: If success, set the rsp accordingly.
   * TODO: You should mark the page is stack. */
  /* TODO: Your code goes here */

  /* 처음에는 바로 스택을 할당해줘야한다.
   * palloc을 통해서 값을 설정해줘야한다.
   * 그리고 pml4로 매핑을 해줘야한다.
   * spt에 추가가 되어야한다. ->이건 함수안에 들어가 있을것이다.
   */

  /* 스택을 바로 할당해준다..-> 프레임을 얻고 그 프레임에 kva를 설정하고
   * 그프레임과 유저페이지를 매핑
   * 문제 : 이걸 해주는 함수들이 static이라 여기서 사용할 수 없음
   */

  /* vm_claim page를 활용한다.
   * 만약 spt_find_page에서 NULL 값이 나온다면
   * page를 만들어준다.
   * 여기서 페이지를 만들어줄때 셋팅해줄 값을 스택 초기값으로 만들어줘야한다.
   * aux값으로 설정할 구조체를 넘겨줘야할 것 같다.
   * 이전에 사용한 setup_stack을 확인해봤을때 페이지를 받고 rsp값만 가리키고
   * 끝났다.
   */
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct thread *t = thread_current();

  if (spt_find_page(spt, stack_bottom) == NULL) {
    //페이지를 초기화 해줘야하는데.. 지금은 어떠한 값으로도 초기화 되지 않은?
    //상태
    // 타입이 뭐이고, 어떤값을 읽어야하고,, 등등
    // 만든 페이지를 spt 테이블에 넣는다.
    vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true);
    // spt_insert_page(&t->spt, page);

    success = vm_claim_page(stack_bottom);
    if (success) if_->rsp = USER_STACK;
  }

  return success;
}


bool load_mmap(void *addr, size_t length, int writable, int fd, off_t offset){

}

#endif /* VM */
