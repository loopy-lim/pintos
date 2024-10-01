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

static bool file_lazy_load(struct page *page, void *aux) {
  struct lazy_info *file_info = aux;
  struct file *file = file_info->file;
  size_t page_read_bytes = file_info->page_read_bytes;
  size_t page_zero_bytes = file_info->page_zero_bytes;
  off_t offset = file_info->offset;

  struct frame *frame = page->frame;

  file_seek(file, offset);
  size_t read_size = file_read(file, frame->kva, page_read_bytes);
  memset(frame->kva + read_size, 0, PGSIZE - read_size);

  free(aux);
  return true;
}

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &file_ops;

  struct file_page *file_page = &page->file;
  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page UNUSED = &page->file;
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  struct file_page *file_page = &page->file;
  struct thread * t = thread_current();
  // 여기서 더티 여부 확인하고 더티일 시 파일을 저장하고 끝내게 만들어야한다.
  // pml4_is_dirty(t->pml4, )
  // palloc_free_page(page); 

}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  while (length > 0) {
    size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    struct lazy_info *aux = malloc(sizeof(struct lazy_info));
    aux->file = file;
    aux->offset = offset;
    aux->page_read_bytes = page_read_bytes;
    aux->page_zero_bytes = page_zero_bytes;
    vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_lazy_load,
                                   aux);
    length -= PGSIZE;
    offset += PGSIZE;
  }
}

/* Do the munmap */
void do_munmap(void *addr) {
  struct thread *t = thread_current();
  struct page *page = spt_find_page(&t->spt, addr);
  destroy(page);
}
