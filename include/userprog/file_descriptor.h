#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/thread.h"

typedef unsigned int fdid_t;

bool fd_create(const char *file_name, const off_t initial_size);
fdid_t fd_open(const char *file_name);
off_t fd_read(fdid_t fd, void *buffer, unsigned size);
off_t fd_file_size(fdid_t fd);
bool fd_close(fdid_t fd);
off_t fd_write(fdid_t fd, const void *buffer, unsigned size);
bool fd_duplicates(struct process *parent, struct process *child);
void fd_seek(fdid_t fd, unsigned position);
bool fd_remove(const char *file_name);
void fd_clean_up_by(struct process *proc);
