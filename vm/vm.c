/* vm.c: Generic interface for virtual memory objects. */
#include <string.h>
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h" /* va를 4kb단위로 정렬하기 위한 include */
#include "kernel/hash.h"
#include "vm/uninit.h"

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
 * This function is fully implemented now. */
/* 페이지의 타입을 결정하는 역할. 여기서 switch문을 사용해서 타입을 결정한다.
 * 여기에는 VM_UNINIT 타입만 분류가 되어있는데 모든 타입을 여기서 분류를
 * 해야한다. 왜?
 */

enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
    case VM_UNINIT:
      return VM_TYPE(page->uninit.type);
    default:  // default를 예외로 넣을까? 아니면 그냥 타입으로 처리할까?
      return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);
bool is_vm_addr(void *addr);
/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `3`. */
/* 새로운 페이지를 할당하고 초기화한다. */
/*
주어진 타입으로 초기화되지 않은 페이지를 생성해라.
초기화되지 않은 페이지의 swap_in 핸들러는 해당 타입에 따라 페이지를 자동으로
초기화하고, 주어진 AUX로 INIT를 호출한다. 페이지 구조체를 얻은 후에는, 이
페이지를 프로세스의 보조 페이지 테이블에 삽입해라. vm.h에 정의된 VM_TYPE
매크로를 사용하면 편리할 수 있다.

페이지 폴트 핸들러는 호출 체인을 따라가다가 결국 swap_in을 호출할 때
uninit_intialize 에 도달한다. Pintos는 이에 대한 완전한 구현을 제공한다. 하지만
우리의 설계에 따라 uninit_intialize 를 수정해야 할 수도 있다.
 */

bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;

  /* 현재 페이지의 spt를 가지고 와서 지금 할당하려는 페이지가 spt에 있는지
   * 확인한다. 없다면 새페이지를 할당하고 spt를 업데이트 해야한다.
   */

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */

    /* TODO: Insert the page into the spt. */
    /* uninit 타입의 페이지를 만들어야 한다. 하지만 이 페이지는
       페이지 폴트가 발생했을때 할당할 type을 알아야한다.
       뭔가 에러가 발생하면 goto err로 처리!
     */

    struct page *page = malloc(sizeof(struct page));
    switch (type) {
      case VM_ANON:
        uninit_new(page, upage, init, type, aux, anon_initializer);
        break;
      case VM_FILE:
        uninit_new(page, upage, init, type, aux, file_backed_initializer);
        break;
      case VM_ANON | VM_MARKER_0:
        uninit_new(page, upage, init, type, aux, stack_initializer);
        break;
    }
    page->va = pg_round_down(upage);
    page->writable = writable;

    /* spt에 방금 생성한 page를 넣는다. */
    if (!spt_insert_page(spt, page)) goto err;
    return true;
  }
err:
  return false;
}
/* vm_alloc_page_with_initializer에서 호출하는 spt에서 페이지가 있는지 찾는 함수
 */
/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
  struct page *page = NULL;
  /* TODO: Fill this function. */
  /* va값을 비트 마스킹 해서 4kb 크기로 정렬을 시킨다. */
  /* 정렬 후 해당 주소를 가진 hash_elem을 찾는다.*/
  /* 만약 있다면 해당 페이지 주소를 없다면 NULl을 */
  /* 실제로 있는 값을 찾는것으로 malloc을 할 필요가 없음! */
  va = pg_round_down(va);  // va값 정렬

  page = page_lookup(va);

  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  int succ = false;
  /* TODO: Fill this function. */
  /* spt에 page를 삽입을 해야한다. 어떤 자료구조를 사용할지 생각 할 필요 있음.
   */
  if (hash_insert(&spt->page_table, &page->page_elem) == NULL) succ = true;
  return succ;
}
/* spt에서 페이지 제거 */
void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  hash_delete(&spt->page_table, &page->page_elem);
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. */
/* 제거될 페이지를 victim이라고 부른다. 프레임이 가득 찼을때 제거할 페이지를
 * 선택하는건가? */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */
  // 어떤 프레임을 선택할지 선택 알고리즘을 골라야한다.
  return victim;
}

//프레임에서 페이지를 제거하는 함수
/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */
  //여기에는 제거할 페이지를 스왑 아웃할 수 있게 해야한다.
  return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
// 새로운 프레임(물리주소)를 할당받는다.
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  /* TODO: Fill this function. */
  // 줄 프레임이 없다면 evict프레임을 스왑아웃 해야함
  void *kpage = palloc_get_page(PAL_USER);
  /* frame을 새로 만들어야 한다. */
  frame = malloc(sizeof(struct frame));
  if (frame == NULL) return NULL;

  frame->kva = kpage;
  frame->page = NULL;

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *va) {
  struct thread *t = thread_current();
  // while 문으로 va값을 round_up을 통해서 4kb 크기로 올린다.
  while (spt_find_page(&t->spt, va) == NULL) {
    if (va >= USER_STACK) return;
    va = pg_round_down(va);
    vm_alloc_page(VM_ANON | VM_MARKER_0, va, true);
    va = va + PGSIZE;
  }
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */
  // page fault 시 호출하는 함수이다.
  // 폴트난 페이지는 spt를 이용해서 확인할 수 있다.

  /* 페이지 폴트가 발생 했는지 안했는제 여기서 확인을 해주어야 한다.
   * 만약 페이지 폴트가 발생한다면 여기서 해당 페이지에 claim을 해줘야 하고
   * 페이지 폴트가 발생하지 않는다면 그 페이지 그대로 념겨주면 된다.
   * 페이지가 frame에 할당되어 있는지 아닌지부터 확인해야한다.
   */
  //  if(!(addr>0x400000 && addr<USER_STACK))
  //   return false;

  // if(addr = thread_current)
  void *t_rsp = user ? f->rsp : thread_current()->t_rsp;
  void *thread_resp = thread_current()->t_rsp;
  void *check = addr + 8;

  if (t_rsp == check) {
    vm_stack_growth(addr);
  }
  page = spt_find_page(spt, addr);
  if (page == NULL) return false;
  // if(page->writable==false)
  //   if(write)
  //     return false;
  if (!vm_do_claim_page(page)) return false;
  return true;
}
/* //유효한 주소인지 알려주는 함수
bool is_vm_addr(void *addr){
  if(addr>0x400000 || addr<USER_STACK)
    return false;
  return true;
} */

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
  // claim 페이지를 여기서 선별을 하는 듯 하다. 그리고 그 페이지를 claim 할 수
  // 있게 do_claim_page로 넘긴다.
  page = spt_find_page(&thread_current()->spt, va);
  if (page == NULL) return false;
  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();
  struct thread *curr = thread_current();
  bool writable = page->writable;

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */
  pml4_set_page(curr->pml4, page->va, frame->kva, writable);
  if (!swap_in(page, frame->kva)) return false;
  return true;
}

/* Initialize new supplemental page table */
// 서플리먼트 페이지의 초기 설정을 여기서
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
  /* vm을 여기서 크기에 맞게 쪼개줘야한다. */
  hash_init(&spt->page_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
// fork 시 페이지테이블을 복사해줘야한다.
/*
src에서 dst로 보조 페이지 테이블을 복사한다.
이는 자식 프로세스가 부모의 실행 컨텍스트를 상속해야 할 때 사용된다.
(예 fork ) srt의 보조 페이지 테이블에 있는 각 페이지를 순회 하면서
dst의 보조 페이지 테이블에 정확한 복사본을 만든다.
초기화되지 않은 페이지를 할당 하고 즉시 이를 요청해야한다. */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
  // src hash 테이블의 값을 하나 하나씩 순회한다.
  // src hash 테이블의 hash_elem을 가지고 claim한다.
  bool succ = false;  // 추후 사용 예정
  struct hash_iterator inter;
  struct hash_elem *e = NULL;
  // memcpy(dst,src,sizeof(struct supplemental_page_table));
  hash_first(&inter, src);
  struct lazy_info *aux = NULL;
  while (hash_next(&inter)) {
    // 부모의 spt의 페이지를 순차적으로 읽어옴
    struct page *child_page = NULL;
    struct page *p_page = hash_entry(hash_cur(&inter), struct page, page_elem);

    enum vm_type type = p_page->operations->type;
    switch (type) {
      case VM_UNINIT:
        aux = malloc(sizeof(struct lazy_info));
        memcpy(aux, p_page->uninit.aux, sizeof(struct lazy_info));
        vm_alloc_page_with_initializer(p_page->uninit.type, p_page->va, true,
                                       p_page->uninit.init, aux);
        break;
      case VM_ANON:
        // 익명 페이지 처리
        vm_alloc_page(type, p_page->va, true);
        child_page = spt_find_page(&thread_current()->spt, p_page->va);
        if (!vm_do_claim_page(child_page)) return false;
        memcpy(child_page->frame->kva, p_page->frame->kva, PGSIZE);
        break;
      case VM_ANON | VM_MARKER_0:
        // 스택 처리
        vm_alloc_page(type, p_page->va, true);
        child_page = spt_find_page(&thread_current()->spt, p_page->va);
        if (!vm_do_claim_page(child_page)) return false;
        memcpy(child_page->frame->kva, p_page->frame->kva, PGSIZE);
        break;
      case VM_FILE:
        // 파일 매핑 페이지 처리
        vm_alloc_page(type, p_page->va, true);
        child_page = spt_find_page(&thread_current()->spt, p_page->va);
        vm_claim_page(p_page->va);
        memcpy(child_page->frame->kva, p_page->frame->kva, PGSIZE);
        break;
      default:
        return false;
    }
  }

  return true;
}

/* void supplemental_page_table_elem_kill(struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, page struct, page_elem);
  vm_dealloc_page(page);
}
 */
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  struct hash_iterator inter;
  struct page *page = NULL;
  if (hash_empty(spt)) return;
  hash_first(&inter, spt);

/*   while (hash_next(&inter)) {
    // 부모의 spt의 페이지를 순차적으로 읽어옴
    page = hash_entry(hash_cur(&inter), struct page, page_elem);
    spt_remove_page(spt, page);
    // vm_dealloc_page(page);
    // destroy(page);
  } */
 hash_clear(&spt->page_table,NULL);


  // hash_clear(spt, supplemental_page_table_elem_kill); 채승코드
}

static unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry(p_, struct page, page_elem);
  return hash_bytes(&p->va, sizeof p->va);
}

/* virtual address를 기준으로 hash 테이블에 넣기 위한 비교함수 */
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
                      void *aux UNUSED) {
  const struct page *a = hash_entry(a_, struct page, page_elem);
  const struct page *b = hash_entry(b_, struct page, page_elem);

  return a->va < b->va;
}

/* Returns the page containing the given virtual address, or a null pointer if
 * no such page exists. */
static struct page *page_lookup(const void *va) {
  struct page p;
  struct hash_elem *e;
  struct hash *page_table = &thread_current()->spt.page_table;

  p.va = va;
  e = hash_find(page_table, &p.page_elem);
  return e != NULL ? hash_entry(e, struct page, page_elem) : NULL;
}