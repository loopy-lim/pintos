/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "bitmap.h"
#include "list.h"

static struct list frame_table;
struct lock frame_lock;

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
  list_init(&frame_table);
  lock_init(&frame_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
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
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) != NULL) return false;

  /* TODO: Create the page, fetch the initialier according to the VM type,
   * TODO: and then create "uninit" page struct by calling uninit_new. You
   * TODO: should modify the field after calling the uninit_new. */
  struct page *page = malloc(sizeof(struct page));
  if (page == NULL) return false;

  switch (VM_TYPE(type)) {
    case VM_ANON:
      uninit_new(page, upage, init, type, aux, anon_initializer);
      break;
    case VM_FILE:
      uninit_new(page, upage, init, type, aux, file_backed_initializer);
      break;
    default:
      NOT_REACHED();
  }

  page->va = pg_round_down(upage);
  page->writable = writable;

  /* TODO: Insert the page into the spt. */
  return spt_insert_page(spt, page);
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
  struct page p;
  struct hash_elem *e;

  p.va = pg_round_down(va);
  e = hash_find(&spt->pages, &p.elem);
  return e != NULL ? hash_entry(e, struct page, elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  return hash_insert(&spt->pages, &page->elem) == NULL;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  if (page->frame != NULL) {
    list_remove(&page->frame->elem);
  }
  hash_delete(&spt->pages, &page->elem);
  vm_dealloc_page(page);
  return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  /* TODO: The policy for eviction is up to you. */
  struct frame *victim = NULL;
  struct pml4 *pml4 = thread_current()->pml4;

  lock_acquire(&frame_lock);
  struct list_elem *e = list_begin(&frame_table);
  while (e != list_end(&frame_table)) {
    struct frame *frame = list_entry(e, struct frame, elem);
    if (pml4_is_accessed(pml4, frame->page->va)) {
      pml4_set_accessed(pml4, frame->page->va, false);
      e = list_next(e);
      if (e == list_end(&frame_table)) e = list_begin(&frame_table);
      continue;
    } else {
      victim = frame;
      list_remove(&frame->elem);
      lock_release(&frame_lock);
      return victim;
    }
  }

  lock_release(&frame_lock);
  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  /* TODO: swap out the victim and return the evicted frame. */
  struct frame *victim = vm_get_victim();
  if (victim == NULL) return NULL;

  if (victim->page == NULL) return NULL;
  if (!swap_out(victim->page)) return NULL;
  if (victim->page != NULL) return NULL;

  lock_acquire(&frame_lock);
  list_push_back(&frame_table, &victim->elem);
  lock_release(&frame_lock);

  return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
  struct frame *frame = malloc(sizeof(struct frame));
  if (frame == NULL) {
    return vm_evict_frame();
  }
  frame->page = NULL;
  frame->kva = palloc_get_page(PAL_USER);

  if (frame->kva == NULL) {
    free(frame);
    return vm_evict_frame();
  }

  lock_acquire(&frame_lock);
  list_push_back(&frame_table, &frame->elem);
  lock_release(&frame_lock);

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr) {
  addr = pg_round_down(addr);
  vm_alloc_page(VM_ANON | VM_MARKER_0, addr, 1);
}
/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

bool can_stack_growth(void *addr, void *rsp) {
  return addr <= USER_STACK && rsp >= USER_STACK - MAX_STACK_SIZE &&
         addr >= rsp;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  void *rsp = !user ? thread_current()->stack_pointer : f->rsp;
  struct page *page = spt_find_page(spt, addr);
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */

  if (user && !is_user_vaddr(addr)) goto error;
  if (page == NULL) {
    if (can_stack_growth(addr, rsp - 8)) {
      if (pml4_get_page(thread_current()->pml4, addr) != NULL) goto error;
      vm_stack_growth(addr);
      return true;
    }
    goto error;
  }
  if (write && !page->writable) goto error;
  if (page->frame == NULL) return vm_do_claim_page(page);
  if (not_present) return swap_in(page, page->frame->kva);

  return false;

error:
  if (user) {
    return false;
  }
  thread_exit();
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va) {
  struct supplemental_page_table *spt = &thread_current()->spt;

  struct page *page = spt_find_page(spt, va);
  if (page == NULL) return false;

  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */
  if (!is_user_vaddr(page->va)) return false;
  if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva,
                     page->writable))
    return false;
  if (!swap_in(page, frame->kva)) return false;

  return true;
}

static uint64_t page_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  return hash_bytes(&page->va, sizeof(page->va));
}

static bool page_less(const struct hash_elem *a, const struct hash_elem *b,
                      void *aux UNUSED) {
  struct page *page_a = hash_entry(a, struct page, elem);
  struct page *page_b = hash_entry(b, struct page, elem);
  return page_a->va < page_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
  struct hash *pages = &src->pages;
  struct hash_iterator i;
  hash_first(&i, pages);

  while (hash_next(&i)) {
    struct page *parent_page = hash_entry(hash_cur(&i), struct page, elem);
    enum vm_type type = page_get_type(parent_page);
    void *upage = parent_page->va;
    bool writable = parent_page->writable;

    if (parent_page->uninit.type & VM_MARKER_0) {
      if (!vm_alloc_page(VM_ANON | VM_MARKER_0, upage, true)) return false;
      struct page *child_page = spt_find_page(dst, upage);
      if (!vm_claim_page(upage)) return false;
    } else if (parent_page->operations->type == VM_UNINIT) {
      vm_initializer *init = parent_page->uninit.init;
      void *aux = parent_page->uninit.aux;
      struct lazy_load_segment_aux *lazy_aux =
          malloc(sizeof(struct lazy_load_segment_aux));
      if (lazy_aux == NULL) return false;
      memcpy(lazy_aux, aux, sizeof(struct lazy_load_segment_aux));

      if (!vm_alloc_page_with_initializer(type, upage, writable, init,
                                          lazy_aux))
        return false;
    } else if (parent_page->operations->type == VM_ANON) {
      if (!vm_alloc_page(type, upage, writable)) return false;
      if (!vm_claim_page(upage)) return false;
    }

    if (parent_page->operations->type == VM_ANON) {
      struct page *child_page = spt_find_page(dst, upage);
      memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
    }
  }

  return true;
}

void spt_clear(struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  if (page->frame != NULL) {
    // palloc_free_page(page->frame->kva);
    list_remove(&page->frame->elem);
    // free(page->frame);
  }
  vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread andd
   * TODO: writeback all the modified contents to the storage. */
  struct hash *pages = &spt->pages;
  if (hash_empty(pages)) return false;
  hash_clear(pages, spt_clear);
  return true;
}
