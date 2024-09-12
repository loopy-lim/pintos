#include "userprog/file_descriptor.h"
#include "threads/synch.h"
#include "threads/synch.h"
#include <stdio.h>
#include "filesys/filesys.h"

bool duplicate_threads_fd(struct thread* parent, struct thread* child) {
  for (int i = 2; i < 128; i++) {
    if (parent->file_descriptor_table[i] == NULL) break;
    struct file* parent_file = parent->file_descriptor_table[i];
    if (parent_file == STDIN_FILENO || parent_file == STDOUT_FILENO) {
      child->file_descriptor_table[i] = parent_file;
      continue;
    }
    child->file_descriptor_table[i] = file_duplicate(parent_file);
    if (child->file_descriptor_table[i] == NULL) {
      return false;
    }
  }
  return true;
}

void remove_all_fd(struct thread* t) {
  for (int i = 2; i < 128; i++) {
    if (t->file_descriptor_table[i] == NULL) return;
    delete_fd(i, t);
  }
}

fdid_t open_fd(char* file_name, struct thread* t) {
  struct file* file = filesys_open(file_name);
  if (file == NULL) {
    return -1;
  }
  for (int i = 2; i < 128; i++) {
    if (t->file_descriptor_table[i] == NULL) {
      t->file_descriptor_table[i] = file;
      return i;
    }
  }
  file_close(file);
  return -1;
}

int delete_fd(fdid_t fdid, struct thread* t) {
  if (fdid == NULL || fdid == STDIN_FILENO || fdid == STDOUT_FILENO ||
      fdid >= 128 || t->file_descriptor_table[fdid] == NULL) {
    return -1;
  }
  file_close(t->file_descriptor_table[fdid]);
  t->file_descriptor_table[fdid] = NULL;
  return 0;
}

off_t read_fd(fdid_t fdid, void* buffer, unsigned size, struct thread* t) {
  if (fdid == NULL || fdid >= 128 || fdid == STDOUT_FILENO || fdid < 0 ||
      t->file_descriptor_table[fdid] == NULL) {
    return -1;
  }

  if (fdid == STDIN_FILENO) {
    unsigned int i;
    for (i = 0; i < size; i++) {
      ((char*)buffer)[i] = input_getc();
    }
    return i;
  }
  off_t bytes_read = file_read(t->file_descriptor_table[fdid], buffer, size);
  return bytes_read;
}

off_t file_size_fd(fdid_t fdid, struct thread* t) {
  if (fdid == NULL || fdid == STDIN_FILENO || fdid == STDOUT_FILENO ||
      fdid < 0 || fdid >= 128 || t->file_descriptor_table[fdid] == NULL) {
    return -1;
  }
  off_t size = file_length(t->file_descriptor_table[fdid]);
  return size;
}

off_t write_fd(fdid_t fdid, const void* buffer, unsigned size,
               struct thread* t) {
  if (fdid == NULL || fdid == STDIN_FILENO || fdid >= 128 || fdid < 0 ||
      t->file_descriptor_table[fdid] == NULL) {
    return -1;
  }

  if (fdid == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }
  off_t bytes_written =
      file_write(t->file_descriptor_table[fdid], buffer, size);
  return bytes_written;
}

void seek_fd(fdid_t fdid, unsigned position, struct thread* t) {
  if (fdid == NULL || fdid == STDIN_FILENO || fdid == STDOUT_FILENO ||
      fdid < 0 || fdid >= 128 || t->file_descriptor_table[fdid] == NULL) {
    return;
  }
  file_seek(t->file_descriptor_table[fdid], position);
}