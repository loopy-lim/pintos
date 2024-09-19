#include "filesys/filesys.h"
#include "filesys/file.h"

typedef unsigned int fdid_t;

bool fd_create(const char *file_name, const off_t initial_size);