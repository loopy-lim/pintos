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
  struct file_load_info *file_info = aux;
  struct file *file = file_info->file;
  size_t file_length  = file_info->length;
  // size_t page_zero_bytes  = file_info->page_zero_bytes;
  off_t offset            = file_info->offset;
  bool cont_page          = file_info->cont_page;

  struct frame *frame = page->frame;

  file_seek(file, offset);
  size_t read_size = file_read(file, frame->kva, PGSIZE);
  // if(pml4_is_dirty(thread_current()->pml4,page->va))
  memset(frame->kva + read_size, 0, PGSIZE - read_size);
  page->file.file = file;
  page->file.offset = offset;
  page->file.file_size = file_length;
  page->file.page_read_bytes = read_size;
  page->file.page_zero_bytes = PGSIZE - read_size;
  // page->file.file_size = page_read_bytes;
  page->file.cont_page = cont_page;

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
  // 여기서 더티 여부 확인하고 더티일 시 파일을 저장하고 끝내게 만들어야한다.
  // pml4_is_dirty(t->pml4, )
  // palloc_free_page(page);
  // 파일을 reopen을 통해서 독립적으로 파일을 수정할 수 있도록 해야한다.
  struct file *file = file_page->file;
  size_t page_read_bytes = file_page->page_read_bytes;
  size_t page_zero_bytes = file_page->page_zero_bytes;
  off_t offset = file_page->offset;
  // struct file *file = file_reopen(old_file);
  if (pml4_is_dirty(thread_current()->pml4, page->va)) {
    file_write_at(file, page->frame->kva, page_read_bytes, offset);
  }

  file_close(file);
}
 
/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  struct file *re_file = file_reopen(file);
  bool pg_off = false;
  while (length > 0) {
    struct file_load_info *aux = malloc(sizeof(struct file_load_info));
    aux->file = re_file;
    aux->offset = offset;
    aux->length = length;
    // aux->page_zero_bytes = page_zero_bytes;
    aux->cont_page = pg_off;
    vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_lazy_load,
                                   aux);
    length = length>PGSIZE ? length-PGSIZE : 0;
    offset += PGSIZE;
    pg_off = true;
    addr   += PGSIZE;
  }
  
}

/* Do the munmap */
/* 
  파일의 크기만큼 페이지를 free해주고 
 */
void do_munmap(void *addr) {
  struct thread *t = thread_current();
  struct page *page = spt_find_page(&t->spt, addr);
  int size = PGSIZE;
  page->file.cont_page==true;
  int length = page->file.file_size;
  int refeat = length/PGSIZE;

  for(int i=0; i<refeat; i++){
    spt_remove_page(&t->spt, page);
    addr+=PGSIZE;
    page = spt_find_page(&t->spt, addr);    
  }
}
