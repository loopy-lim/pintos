#include "userprog/file_descriptor.h"
#include "threads/synch.h"

static struct lock fdid_lock;
static fdid_t allocate_fdid(void);

void fd_init() { lock_init(&fdid_lock); }

fdid_t open_fd(struct file* file, struct thread* t) {
  struct fd* new_fd = (struct fd*)malloc(sizeof(struct fd));
  new_fd->file = file;
  new_fd->fd = allocate_fdid();
  list_push_back(&t->file_descriptor_table, &new_fd->elem);
  return new_fd->fd;
}

struct fd* get_file_by_fd(fdid_t fdid, struct thread* t) {
  struct list_elem* e;
  struct list* l = &t->file_descriptor_table;
  for (e = list_begin(l); e != list_end(l); e = list_next(e)) {
    struct fd* cur_fd = list_entry(e, struct fd, elem);
    if (cur_fd->fd == fdid) return cur_fd;
  }

  return NULL;
}

int delete_fd(fdid_t fdid, struct thread* t) {
  struct fd* cur_fd = get_file_by_fd(fdid, t);
  if (cur_fd == NULL) return -1;
  file_deny_write(cur_fd->file);
  file_close(cur_fd->file);
  list_remove(&cur_fd->elem);
  free(cur_fd);
  return 0;
}

off_t read_fd(fdid_t fdid, void* buffer, unsigned size, struct thread* t) {
  struct fd* cur_fd = get_file_by_fd(fdid, t);
  if (cur_fd == NULL) return -1;
  return file_read(cur_fd->file, buffer, size);
}

off_t file_size_fd(fdid_t fdid, struct thread* t) {
  struct fd* cur_fd = get_file_by_fd(fdid, t);
  if (cur_fd == NULL) return -1;
  return file_length(cur_fd->file);
}

off_t write_fd(fdid_t fdid, const void* buffer, unsigned size,
               struct thread* t) {
  struct fd* cur_fd = get_file_by_fd(fdid, t);
  if (cur_fd == NULL) return -1;
  return file_write(cur_fd->file, buffer, size);
}

void seek_fd(fdid_t fdid, unsigned position, struct thread* t) {
  struct fd* cur_fd = get_file_by_fd(fdid, t);
  if (cur_fd == NULL) return;
  file_seek(cur_fd->file, position);
}

static fdid_t allocate_fdid(void) {
  static fdid_t next_fdid = 2;
  fdid_t fdid;

  lock_acquire(&fdid_lock);
  fdid = next_fdid++;
  lock_release(&fdid_lock);

  return fdid;
}
