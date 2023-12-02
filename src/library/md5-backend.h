#include <uthash.h>

#include "fapolicyd-backend.h"

struct _hash_record {
  const char *key;
  UT_hash_handle hh;
};

static const int kMaxKeyLength = 4096;
static const int kMd5HexSize = 32;

int add_file_to_backend_by_md5(const char *path,
							const char *expected_md5,
							struct _hash_record **hashtable,
							trust_src_t trust_src,
							backend backend);
