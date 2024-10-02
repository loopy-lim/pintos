/* file.c: Implementation of memory backed file object (mmaped object). */
#include "userprog/file_descriptor.h"
#include "vm/vm.h"
#include "stdio.h"
#include "threads/vaddr.h"

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

  struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page UNUSED = &page->file;
  /* 파일에서 콘텐츠를 읽어서 kva에 swap_in 한다. */
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct file_page *file_page UNUSED = &page->file;
  /*먼저 페이지가 dirty 인지 확인한다. 
  페이지 교체를 한 후에는 페이지의 더티 비트를 끈다. 
  
  내용을 다시 파일에 기록하여 swap_out한다 */
  return true;
}
/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  struct file_page *file_page UNUSED = &page->file;
}

static bool lazy_file_load_segment(struct page *page, struct segment_aux *aux) {
  /* TODO: Load the segment from the file */
  /* TODO: This called when the first page fault occurs on address VA. */
  /* TODO: VA is available when calling this function. */
  /* 파일에서부터 segment를 로드해온다.
  이 함수는 가상 주소에서 처음 페이지 폴트가 발생했을 때 호출된다. 
  가상 주소는 이 함수를 호출했을 때 사용가능하다*/
  /* "여기서 페이지는 실행파일이야 그리고 그 페이지에 대한 데이터를 집어넣어줘야된다고 !"*/
    // struct segment_aux *aux; 
    /* Load this page. */
    file_seek(aux->file,aux->ofs);
    if (file_read(aux->file, page->frame->kva, aux->read_bytes) != (int)aux->read_bytes) {

      return false;
    }
    memset(page->frame->kva + aux->read_bytes, 0, aux->zero_bytes);
    free(aux);
  return true;
}


void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  // length는 read _bytes; 
  file = file_reopen(file);
  while (length > 0) {
      /* Do calculate how to fill this page.
      * We will read PAGE_READ_BYTES bytes from FILE
      * and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* TODO: Set up aux to pass information to the lazy_load_segment. */
      struct segment_aux *file_aux = malloc(sizeof(struct segment_aux));
      file_aux->file = file;
      file_aux->ofs = offset; // 현재 페이지의 파일 오프셋
      file_aux->read_bytes = page_read_bytes;
      file_aux->zero_bytes = page_zero_bytes;

      if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable,
                                          lazy_file_load_segment, file_aux))
        return false;

      /* Advance. */
      length -= page_read_bytes;
      // zero_bytes -= page_zero_bytes;
      addr += PGSIZE;
      offset += page_read_bytes;
    }
  }

/* Do the munmap */
void do_munmap(void *addr) {}
