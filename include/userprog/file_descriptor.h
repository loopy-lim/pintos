#include <list.h>
#include "threads/thread.h"
#include "filesys/file.h"

typedef int fdid_t;

struct fd {
  struct file* file;
  fdid_t fd;
  struct list_elem elem;
};

fdid_t create_fd(struct file* file, struct thread* t);
int delete_fd(fdid_t fdid, struct thread* t);
struct fd* get_file_by_fd(fdid_t fdid, struct thread* t);