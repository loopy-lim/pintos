/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "bitmap.h"
#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <string.h>
#include "threads/mmu.h"

#define SECTORS_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *swap_table;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

struct lock swap_lock;
struct lock frame_lock;

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
  swap_disk = disk_get(1, 1);
  if (swap_disk == NULL) PANIC("Fail to get swap disk");
  swap_table = bitmap_create(disk_size(swap_disk));
  lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;

  struct anon_page *anon_page = &page->anon;
  page->is_swapped = false;

  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  struct anon_page *anon_page = &page->anon;
  struct pml4 *pml4 = thread_current()->pml4;
  lock_acquire(&frame_lock);
  disk_sector_t swap_slot = page->swap_slot;
  lock_release(&frame_lock);

  for (int i = 0; i < SECTORS_PER_PAGE; i++) {
    disk_read(swap_disk, swap_slot + i, kva + i * DISK_SECTOR_SIZE);
  }

  lock_acquire(&swap_lock);
  bitmap_set_multiple(swap_table, swap_slot, SECTORS_PER_PAGE, false);
  lock_release(&swap_lock);

  pml4_set_page(pml4, page->va, kva, page->writable);
  page->frame->kva = kva;

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  struct pml4 *pml4 = thread_current()->pml4;
  lock_acquire(&frame_lock);
  if (page->frame == NULL) return false;
  void *kva = page->frame->kva;
  void *va = page->va;
  lock_release(&frame_lock);

  lock_acquire(&swap_lock);
  disk_sector_t swap_slot =
      bitmap_scan_and_flip(swap_table, 0, SECTORS_PER_PAGE, false);
  lock_release(&swap_lock);

  if (swap_slot == BITMAP_ERROR) return false;
  for (int i = 0; i < SECTORS_PER_PAGE; i++) {
    disk_write(swap_disk, swap_slot + i, kva + i * DISK_SECTOR_SIZE);
  }

  pml4_clear_page(pml4, va);

  page->swap_slot = swap_slot;
  page->frame->page = NULL;
  page->frame = NULL;

  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  if (page->is_swapped) {
    lock_acquire(&swap_lock);
    bitmap_set_multiple(swap_table, page->swap_slot, SECTORS_PER_PAGE, false);
    lock_release(&swap_lock);
  }
}
