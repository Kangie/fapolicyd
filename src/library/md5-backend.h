#include <uthash.h>

#include "fapolicyd-backend.h"

struct _hash_record {
  const char *key;
  UT_hash_handle hh;
};

static const int kMaxKeyLength = 4096;
static const int kMd5HexSize = 32;

int add_file_to_backend(const char *path,
						struct _hash_record **hashtable,
						const char *expected_md5,
						trust_src_t *trust_src,
						backend backend);
