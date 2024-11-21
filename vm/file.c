/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &file_ops;
  page->is_swapped = false;
  struct file_page *file_page = &page->file;
  off_t ofs = file_page->ofs;

  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page = &page->file;
  struct pml4 *pml4 = thread_current()->pml4;
  if (file_page->file == NULL) return false;
  if (page->frame == NULL) return false;
  if (page->is_swapped) return false;

  off_t ofs = file_page->ofs;
  file_seek(file_page->file, ofs);

  int read_bytes = file_read(file_page->file, kva, file_page->read_bytes);
  memset(kva + read_bytes, 0, file_page->zero_bytes);
  page->frame->kva = kva;
  page->is_swapped = true;

  pml4_set_page(pml4, page->va, kva, page->writable);

  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct file_page *file_page = &page->file;
  struct pml4 *pml4 = thread_current()->pml4;
  if (file_page->file == NULL) return true;
  if (!page->is_swapped) return true;

  bool is_dirty = pml4_is_dirty(thread_current()->pml4, page->va);
  if (is_dirty) {
    off_t ofs = file_page->ofs;
    file_seek(file_page->file, ofs);
    file_write(file_page->file, page->frame->kva, file_page->read_bytes);
    pml4_set_dirty(pml4, page->va, false);
    pml4_set_accessed(pml4, page->va, false);
  }

  pml4_clear_page(pml4, page->va);

  page->frame->page = NULL;
  page->is_swapped = false;
  page->frame = NULL;

  return true;
}

static void file_backed_destroy(struct page *page) {
  struct file_page *file_page = &page->file;
  if (file_page->file == NULL) return;
  if (page->writable == 0) return;

  if (pml4_is_dirty(thread_current()->pml4, page->va)) {
    off_t ofs = file_page->ofs;
    file_seek(file_page->file, ofs);
    file_write(file_page->file, page->frame->kva, file_page->read_bytes);
  }

  return;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  if (file == NULL) return NULL;
  if (file_length(file) <= 0) return NULL;
  if (addr == NULL || pg_ofs(addr) != 0) return NULL;
  if (is_kernel_vaddr(addr)) return NULL;
  if (length <= 0 || length > MAX_STACK_SIZE) return NULL;
  if (offset % PGSIZE != 0) return NULL;

  file = file_reopen(file);
  if (file == NULL) {
    return NULL;
  }

  size_t page_cnt = (length + PGSIZE - 1) / PGSIZE;

  void *page_addr = addr;
  off_t ofs = offset;

  for (size_t i = 0; i < page_cnt; i++) {
    if (!vm_alloc_page(VM_FILE | VM_MARKER_1, page_addr, writable)) goto error;
    struct page *page = spt_find_page(&thread_current()->spt, page_addr);
    if (page == NULL) goto error;

    struct file_page *file_page = &page->file;
    file_page->file = file;
    file_page->ofs = ofs;
    file_page->read_bytes = length < PGSIZE ? length : PGSIZE;
    file_page->zero_bytes = PGSIZE - file_page->read_bytes;

    page_addr += PGSIZE;
    ofs += PGSIZE;
    length -= PGSIZE;
  }

  return addr;

error:
  file_close(file);
  return NULL;
}

/* Do the munmap */
void do_munmap(void *addr) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  void *upage = addr;

  while (true) {
    struct page *page = spt_find_page(spt, upage);
    if (page == NULL) {
      page = spt_find_page(spt, addr);
      if (page == NULL) {
        return;
      }
      return;
    }

    spt_remove_page(spt, page);
    upage += PGSIZE;
  }
}
