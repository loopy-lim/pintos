/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
  /* TODO: Set up the swap_disk. */
  swap_disk = NULL;
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;

  struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  struct anon_page *anon_page = &page->anon;
  /* 1. 스왑 디스크 데이터 내용을 읽어서 anony page를 swap_in한다. 
  2. 스왑 아웃될 때 페이지 구조체는 스왑 디스크에 저장되어있어야함
  3. 스왑 테이블을 업데이트  */
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  /*1. 스왑 테이블을 사용하여 디스크에서 사용가능한 스왑 슬롯을 찾는다
  2. 데이터 페이지를 슬롯에 복사
  3. 데이터의 위치는 페이지 구조체에 저장되어야함
  디스크에 사용가능한 슬롯이 더이상 없으면 커널 패닉이 발생하낟*/
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  // if(anon_page != NULL){
  //   palloc_free_page(anon_page);
  // }
  return;
}
