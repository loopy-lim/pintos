#include "filesys/filesys.h"
#include "filesys/file.h"

typedef unsigned int fdid_t;

bool fd_create(const char *file_name, const off_t initial_size);
fdid_t fd_open(const char *file_name);
off_t fd_read(fdid_t fd, void *buffer, unsigned size);
off_t fd_file_size(fdid_t fd);