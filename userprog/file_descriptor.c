#include "userprog/file_descriptor.h"
#include "threads/thread.h"

fdid_t get_first_fd(struct process *proc);

fdid_t get_first_fd(struct process *proc) {
  fdid_t fd = 2;
  while (proc->files[fd] != NULL) {
    if (fd == 127) return 0;
    fd++;
  }
  return fd;
}

bool fd_create(const char *file_name, const off_t initial_size) {
  bool is_create = filesys_create(file_name, initial_size);
  return is_create;
}

void fd_seek(fdid_t fd, unsigned position) {
  struct process *proc = &thread_current()->process;
  if (proc->files[fd] == NULL) return;

  file_seek(proc->files[fd], position);
}

bool fd_remove(const char *file_name) {
  bool is_remove = filesys_remove(file_name);
  return is_remove;
}

fdid_t fd_open(const char *file_name) {
  struct file *file = filesys_open(file_name);
  if (file == NULL) return -1;

  struct process *proc = &thread_current()->process;
  fdid_t fd = get_first_fd(proc);
  if (fd == 0) {
    file_close(file);
    return -1;
  }

  proc->files[fd] = file;
  return fd;
}

bool fd_close(fdid_t fd) {
  struct process *proc = &thread_current()->process;
  if (proc->files[fd] == NULL) return false;

  file_close(proc->files[fd]);
  proc->files[fd] = NULL;
  return true;
}

off_t fd_read(fdid_t fd, void *buffer, unsigned size) {
  struct process *proc = &thread_current()->process;
  if (proc->files[fd] == NULL) return false;

  unsigned read_bytes = file_read(proc->files[fd], buffer, size);
  return read_bytes;
}

off_t fd_file_size(fdid_t fd) {
  struct process *proc = &thread_current()->process;
  if (proc->files[fd] == NULL) return -1;

  off_t file_size = file_length(proc->files[fd]);
  return file_size;
}

off_t fd_write(fdid_t fd, const void *buffer, unsigned size) {
  struct process *proc = &thread_current()->process;
  if (proc->files[fd] == NULL) return -1;

  unsigned write_bytes = file_write(proc->files[fd], buffer, size);
  return write_bytes;
}

bool fd_duplicates(struct process *parent, struct process *child) {
  for (int i = 0; i < 128; i++) {
    if (parent->files[i] != NULL) {
      child->files[i] = file_duplicate(parent->files[i]);
      if (child->files[i] == NULL) {
        return false;
      }
    }
  }
  return true;
}

void fd_clean_up_by(struct process *proc) {
  for (int i = 2; i < 128; i++) {
    if (proc->files[i] != NULL) {
      file_close(proc->files[i]);
      proc->files[i] = NULL;
    }
  }
}
