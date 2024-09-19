#include "userprog/file_descriptor.h"
#include "threads/thread.h"

fdid_t get_first_fd(struct process *proc) {
  fdid_t fd = 2;
  while (proc->files[fd] != NULL) {
    if (fd == 127) return -1;
    fd++;
  }
  return fd;
}

bool fd_create(const char *file_name, const off_t initial_size) {
  bool is_create = filesys_create(file_name, initial_size);
  return is_create;
}

fdid_t fd_open(const char *file_name) {
  struct file *file = filesys_open(file_name);
  if (file == NULL) return -1;

  struct process *proc = &thread_current()->process;
  fdid_t fd = get_first_fd(proc);
  if (fd == -1) {
    file_close(file);
    return -1;
  }

  proc->files[fd] = file;
  return fd;
}