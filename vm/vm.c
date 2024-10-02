/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include <string.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. 
 * 페이지의 타입을 가져온다. 이 함수는 페이지를 초기화 한 이후에 페이지의 타입을 알고 싶다면 유용하다 . 
 * 이 함수는 현재 충분히 구현되어있다. */
enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
    case VM_UNINIT:
      return VM_TYPE(page->uninit.type);
    default:
      return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. 
 * 이니셜라이저와 함께 대기 중인 페이지 객체를 생성합니다. 
 * 페이지를 직접 생성하지 말고, 이 함수 또는 `vm_alloc_page`를 통해 생성하십시오.
 * */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;
  upage = pg_round_down(upage);
  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. 
      * 페이지를 생성하고, initializer가 vm type 에 따라 초기화 함수를 가져와야한다. 
      * 그리고 uninit_new 함수를 호출하여 uninit 페이지 구조체를 생성한다. 
      * 너는 unint_new 함수를 호출 한 뒤에 field를 수정해야 한다 */
    /* TODO: Insert the page into the spt. 페이지를 spt에 삽입하시오. */
 
    struct page *page = (struct page *)malloc(sizeof(struct page)); //짱그니가 malloc으로 바꾸랬씀 완.
    switch (VM_TYPE(type)) {
      case VM_ANON:
        uninit_new(page, page->va, init, type, aux, anon_initializer);
        break;
      case VM_FILE:
        uninit_new(page, page->va, init, type, aux, file_backed_initializer);
        break;
    }

    page->va = pg_round_down(upage);
    page->writable = writable;

    if (!spt_insert_page(spt, page)) return false; 

    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt,
                           void *va) {
  // 주어진 supplemental page table에서로부터 va와 대응되는 페이지 구조체를 찾아서 반환
  struct page p;
  struct hash_elem *e;
  
  p.va = pg_round_down(va);
  e = hash_find (&spt->hash_table, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
                     struct page *page) {
  int succ = false;
  /* TODO: Fill this function. */  
  
  if (hash_insert(&spt->hash_table, &page->hash_elem) == NULL) {
    succ = true;
  }  
  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. 
evicted 될 프레임을 가져온다. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.
 페이지 하나를 evict 하고 연관된 frame 을 리턴한다. 
 실패시 NULL 을 반환한다. */
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */

  return NULL;
} 

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.
 * 
 * palloc()과 프레임을 가져옵니다. 사용할 수 있는 페이지가 없으면,
 * 페이지를 강제퇴출(evict)하고 그 페이지를 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀이 가득 차면
 * 이 함수는 메모리 공간을 확보하기 위해 프레임을 강제퇴출시킵니다.
 */
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  /* TODO: Fill this function. */

  // 메모리 풀에서 새로운 물리메모리 페이지를 가져온다 
  void *kpage = palloc_get_page(PAL_USER);
  // 유저 메모리 풀에서 페이지를 성공적으로 가져오면, 
  // 프레임을 할당하고 프레임 구조체의 멤버를 초기화한 후 해당 프레임을 반환한다. 
  if ( kpage == NULL ) {
    PANIC("todo");
    return;
  };
  frame = malloc(sizeof(struct frame));
  frame -> kva = kpage;
  frame -> page = NULL;
  // 이 함수를 구현한 후에는 모든 유저 공간 페이지들을 이 함수를 통해 할당해주어야한다. 
  // 페이지 할당이 실패했을 때는 PANIC("todo")으로 해당 케이스들을 표시해두어야한다.

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  addr = pg_round_down(addr);
  while (!spt_find_page(spt, addr))
  {
    if (!vm_alloc_page(VM_ANON, addr, true)) return false;
    addr += PGSIZE;
  }  
}
/* 하나 이상의 annonymous 페이지를 할당하여 스택 크기를 늘린다. 
addr은 faulted 주소에서 유효한 주소가 된다. 
페이지를 할당할 떄는 주소를 PGSIZE 기준으로 내림하기*/


/* Handle the fault on write_protected page 
쓰기 보호된 페이지에 대한 폴트를 다룬다.*/
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
                         bool user, bool write,
                         bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  /* page fault가 스택을 증가시켜야 하는 경우에 해당하는 지 스택 증가를 확인한다. 
  page fault 예외로 스택 증가를 확인한 후에는 vm_stack_growth 를 호출하여 스택을 증가시켜야 한다. */
  
  page = spt_find_page(spt,addr);

  if (user && is_kernel_vaddr(addr))
  {
    return false;
  }
  if(page == NULL){
    if(f->rsp - 8 <= addr && addr <= USER_STACK){
      vm_stack_growth(addr);
      return true;
    }
    return false;
  }
  if (page != NULL && !page -> writable && write)
  {
    return false;
  }
  return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va) {
  struct page *page = NULL;
  /* TODO: Fill this function */
  page = spt_find_page(&thread_current()->spt, va);
  if (page == NULL) return false;
	// 인자로 주어진 va에 페이지를 할당하고
	// 해당 페이지에 프레임을 할당한다
	// 해당 페이지를 인자로 갖는 vm_do_claim_page 함수를 호출 
  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. 
페이지를 메모리에 할당하고, MMU 를 설정한다. */
static bool vm_do_claim_page(struct page *page) {
	struct frame *frame = vm_get_frame();
  
	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* 인자로 주어진 Page 에 물리 메모리 프레임을 할당한다. vm_get_frame()으로 가져온 프레임 하나 있음
	그 이후 MMU 를 셋팅한다.*/
  if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, true))
    return false;
	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
/* 1.src 에서 dst 로 spt를 복제한다 
2. 이 경우는 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용된다. 
3. 각 page을 반복하고 dst에 spt에 있는 항목의 복사본을 만든다.
4. uninit page 를 할당하고 claim 하면 된다. */
// 그리고 page type 에 따라 달라지는 데 1. uninit type 일 떄면 그대로 spt를 복사해주면 될 것
// 2 . annoymous type 일 떄는 새로운 frame 을 할당해주고 그에 따른 깊은 복사를 해주어야한다. 
  struct hash_iterator i;

  hash_first(&i, &src->hash_table);
  while (hash_next(&i))
  {
    const struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);
    if(parent_page == NULL) return false;

    struct page *child_page = NULL;
    struct segment_aux *aux_ = NULL; 
    enum vm_type src_type;
    src_type = parent_page -> operations -> type;
    
    if(src_type == VM_UNINIT){
      aux_ = (struct segment_aux *)malloc(sizeof(struct segment_aux));
      memcpy(aux_, parent_page->uninit.aux, sizeof(struct segment_aux));
      if(!vm_alloc_page_with_initializer(page_get_type(parent_page), parent_page->va, parent_page->writable, parent_page->uninit.init, aux_)) return false;
    }
    else{
      if(!vm_alloc_page(page_get_type(parent_page), parent_page->va, parent_page->writable)) return false;
      if(!vm_claim_page(parent_page->va)) return false;
      child_page = spt_find_page(dst, parent_page->va); 
      if (child_page->frame == NULL || parent_page->frame == NULL) return false; // frame NULL 확인
      memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
    }
  } 
  return true;
}

/* Free the resource hold by the supplemental page table */
/* spt 에 의해 유지되던 모든 자원들을 free 한다*/
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. 
   스레드가 보유한 모든 보조 페이지 테이블을 삭제하고, 수정된 모든 내용을 저장소에 기록한다.*/
  
  /* 페이지 테이블에 있는 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야 한다. 
*/
  hash_clear(&spt->hash_table, NULL); //NULL로 하지 말고 함수를 만들기 (짱근 왈.)
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}