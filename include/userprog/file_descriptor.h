#include <list.h>
#include "threads/thread.h"
#include "filesys/file.h"

typedef int fdid_t;

struct fd {
  struct file* file;
  fdid_t fd;
  struct list_elem elem;
};

fdid_t open_fd(char* file_name, struct thread* t);
int delete_fd(fdid_t fdid, struct thread* t);
off_t read_fd(fdid_t fdid, void* buffer, unsigned size, struct thread* t);
off_t file_size_fd(fdid_t fdid, struct thread* t);
off_t write_fd(fdid_t fdid, const void* buffer, unsigned size,
               struct thread* t);
void seek_fd(fdid_t fdid, unsigned position, struct thread* t);
bool duplicate_threads_fd(struct thread* parent, struct thread* child);