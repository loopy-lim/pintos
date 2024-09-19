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
