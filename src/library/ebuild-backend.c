#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uthash.h>

#include "conf.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "message.h"

static const char kEbuildBackend[] = "ebuilddb";
static const int kMaxKeyLength = 4096;
static const int kMd5HexSize = 32;

static int ebuild_init_backend(void);
static int ebuild_load_list(const conf_t *);
static int ebuild_destroy_backend(void);

backend ebuild_backend = {
    kEbuildBackend,
    ebuild_init_backend,
    ebuild_load_list,
    ebuild_destroy_backend,
    /* list initialization */
    {0, 0, NULL},
};

typedef struct contents {
  char *md5;
  char *path;
} ebuildfiles;

struct epkg {
  char *name;
  char *version;
  char *category;
  char *slot;
  char *repo;
  ebuildfiles *content;
};

/*
 * Take a given portage category/package-version{-rev} string, and pointers to category, package and version variables
 * and split the string using the same rules as portage
 * 1. split category at the last '/' character
 *
 */
void split_portage_cpv(char *catpkgver, char **pkgcat, char **pkgname, char **pkgver){
  char *cat, *pkg, *ver;
  char *saveptr;

  cat = strtok_r(catpkgver, "/", &saveptr);
  // grab portage logic for pvr splitting and stick it here
}

/*
 * Given a path to a file with an expected MD5 digest, add
 * the file to the trust database if it matches.
 *
 * Dpkg does not provide sha256 sums or file sizes to verify against.
 * The only source for verification is MD5. The logic implemented is:
 * 1) Calculate the MD5 sum and compare to the dpkg database. If it does
 *    not match, abort.
 * 2) Calculate the SHA256 and file size on the local files.
 * 3) Add to database.
 *
 * Security considerations:
 * An attacker would need to craft a file with a MD5 hash collision.
 * While MD5 is considered broken, this is still some effort.
 * This function would compute a sha256 and file size on the attackers
 * crafted file so they do not secure this backend.
 */
static int add_file_to_backend(const char *path,
                               struct _hash_record **hashtable,
                               const char *expected_md5)
{
  struct stat path_stat;
  // Open the file and check the md5 hash first.
  int fd = open(path, O_RDONLY|O_NOFOLLOW);
  if (fd < 0) {
    if (errno != ELOOP) // Don't report symlinks as a warning
      msg(LOG_WARNING, "Could not open %si, %s", path, strerror(errno));
    return 1;
  }

  if (fstat(fd, &path_stat)) {
    close(fd);
    msg(LOG_WARNING, "fstat file %s failed %s", path, strerror(errno));
    return 1;
  }

  // If its not a regular file, skip.
  if (!S_ISREG(path_stat.st_mode)) {
    close(fd);
    msg(LOG_DEBUG, "Not regular file %s", path);
    return 1;
  }

  size_t file_size = lseek(fd, 0, SEEK_END);
  if (file_size == (size_t)-1) {
    close(fd);
    msg(LOG_ERR, "Error seeking the end");
    return 1;
  }
  lseek(fd, 0, SEEK_SET);
  char *md5_digest = get_hash_from_fd2(fd, file_size, 0);
  if (md5_digest == NULL) {
    close(fd);
    msg(LOG_ERR, "MD5 digest returned NULL");
    return 1;
  }

  if (strcmp(md5_digest, expected_md5) != 0) {
    msg(LOG_WARNING, "Skipping %s as hash mismatched. Should be %s, got %s",
        path, expected_md5, md5_digest);
    close(fd);
    free(md5_digest);
    return 1;
  }
  free(md5_digest);

  // It's OK so create a sha256 of the file
  char *sha_digest = get_hash_from_fd2(fd, file_size, 1);
  close(fd);

  if (sha_digest == NULL) {
    msg(LOG_ERR, "Sha digest returned NULL");
    return 1;
  }

  char *data;
  if (asprintf(&data, DATA_FORMAT, SRC_EBUILD, file_size, sha_digest) == -1) {
    data = NULL;
  }
  free(sha_digest);

  if (data) {
    // Getting rid of the duplicates.
    struct _hash_record *rcd = NULL;
    char key[kMaxKeyLength];
    snprintf(key, kMaxKeyLength - 1, "%s %s", path, data);

    HASH_FIND_STR(*hashtable, key, rcd);

    if (!rcd) {
      rcd = (struct _hash_record *)malloc(sizeof(struct _hash_record));
      rcd->key = strdup(key);
      HASH_ADD_KEYPTR(hh, *hashtable, rcd->key, strlen(rcd->key), rcd);
      list_append(&ebuild_backend.list, strdup(path), data);
    } else {
      free((void *)data);
    }
    return 0;
  }
  return 1;
}

/*
 * Portage stores data about installed packages in the VDB (/var/db/pkg/).
 * We care about /var/db/pkg/category/package-version/CONTENTS
 * which lists files and directories that are installed as part of a package 'merge'
 * operation. All files are prefixed with 'obj' and are in the format:
 * obj /path/to/file $(md5sum /path/to/file) $(date -r /path/to/file "+%s")
 * e.g.
 * obj /usr/bin/clamscan 3ade185bd024e29880e959e6ad187515 1693552964
 */

static int ebuild_load_list(const conf_t *conf) {

  DIR *vdbdir;
  struct dirent *dp;

  if (vdbdir = opendir("/var/db/pkg") == NULL) {
    msg(LOG_ERR, "Could not open /var/db/pkg");
    return 1;
  }

  struct epkg *pkgs = NULL;
  int i = 0;

  /*
   * recurse through category/package-version/ dirs,
   * process CONTENTS (files, md5s), repository, SLOT,
   * store in epkg array
  */
  while ((dp = readdir(vdbdir)) != NULL) {

    if (dp->d_type == DT_DIR && strcmp(dp->d_name, ".") != 0 &&
        strcmp(dp->d_name, "..") != 0) {

      char *catdir;
      if (asprintf(&catdir, "/var/db/pkg/%s", dp->d_name) == -1) {
        catdir = NULL;
      }

      if (catdir) {
        DIR *cat;
        struct dirent *catdp;
        if (cat = opendir(catdir) == NULL) {
          msg(LOG_ERR, "Could not open %s", catdir);
          free(catdir);
          continue;
        }

        while ((catdp = readdir(cat)) != NULL) {

          if (catdp->d_type == DT_DIR && strcmp(catdp->d_name, ".") != 0 &&
              strcmp(catdp->d_name, "..") != 0) {
            char *pkgverdir;

            if (asprintf(&pkgverdir, "%s/%s", catdir, catdp->d_name) == -1) {
              pkgverdir = NULL;
            }

            if (pkgverdir) {
              DIR *pkgver;
              struct dirent *pkgverdp;

              if (pkgver = opendir(pkgverdir) == NULL) {
                msg(LOG_ERR, "Could not open %s", pkgverdir);
                free(pkgverdir);
                continue;
              }

              while ((pkgverdp = readdir(pkgver)) != NULL) {

                char *pkgcat, *pkgname, *pkgrepo, *pkgslot, *pkgver;
                ebuildfiles* pkgcontents = NULL;
                int j = 0;

                // SLOT
                if (pkgverdp->d_type == DT_REG &&
                    strcmp(pkgverdp->d_name, "SLOT") == 0) {
                  char *slot;
                  if (asprintf(&slot, "%s/%s", pkgverdir,
                               pkgverdp->d_name) == -1) {
                    slot = NULL;
                  }
                  if (slot) {
                    FILE *fp;
                    char *line = NULL;
                    size_t len = 0;
                    ssize_t read;
                    if (fp = fopen(slot, "r") == NULL) {
                      msg(LOG_ERR, "Could not open %s", slot);
                      free(slot);
                      continue;
                    }
                    // SLOT will only ever contain a single line
                    if ((read = getline(&line, &len, fp)) != -1) {
                      pkgslot = strdup(line);
                    }
                    free(line);
                    free(slot);
                  }
                }

                // repository
                if (pkgverdp->d_type == DT_REG &&
                    strcmp(pkgverdp->d_name, "repository") == 0) {
                  char *repo;
                  if (asprintf(&repo, "%s/%s", pkgverdir,
                               pkgverdp->d_name) == -1) {
                    repo = NULL;
                  }
                  if (repo) {
                    FILE *fp;
                    char *line = NULL;
                    size_t len = 0;
                    ssize_t read;
                    if (fp = fopen(repo, "r") == NULL) {
                      msg(LOG_ERR, "Could not open %s", repo);
                      free(repo);
                      continue;
                    }
                    // repository will only ever contain a single line
                    if ((read = getline(&line, &len, fp)) != -1) {
                      pkgrepo = strdup(line);
                    }
                      free(line);
                      free(repo);
                  }
                }
                //contents
                if (pkgverdp->d_type == DT_REG &&
                    strcmp(pkgverdp->d_name, "CONTENTS") == 0) {
                  char *contents;
                  if (asprintf(&contents, "%s/%s", pkgverdir,
                               pkgverdp->d_name) == -1) {
                    contents = NULL;
                  }
                  if (contents) {
                    FILE *fp;
                    char *line = NULL;
                    size_t len = 0;
                    ssize_t read;
                    if (fp = fopen(contents, "r") == NULL) {
                      msg(LOG_ERR, "Could not open %s", contents);
                      free(contents);
                      continue;
                    }

                    while ((read = getline(&line, &len, fp)) != -1) {
                      char *token;
                      char *saveptr;

                      token = strtok_r(line, " ", &saveptr); // obj/dir, /path/to/file, md5, datestamp

                      if (token) {
                        // we only care about files
                        if (token == "dir") {
                          continue;
                        }

                        ebuildfiles *file = malloc(sizeof(ebuildfiles));
                        token = strtok_r(NULL, " ", &saveptr);
                        file->path = strdup(token);
                        token = strtok_r(NULL, " ", &saveptr);
                        file->md5 = strdup(token);

                        // we don't care about the datestamp

                        pkgcontents = realloc(pkgcontents, sizeof(ebuildfiles) * (j + 1));
                        pkgcontents[j] = *file;
                        j++;
                        free(file);
                      }

                    }
                  }
                }

              // Portage stores package names in the format category/package-version
              // e.g. dev-libs/libxml2-2.9.10
              // We need to split this into category, package, version
              char *catpkgver = strcat(catdp->d_name, pkgverdp->d_name);
              split_portage_cpv(catpkgver, &pkgcat, &pkgname, &pkgver);

              // add to pkgs array
              struct epkg *pkg = malloc(sizeof(struct epkg));
              pkg->name = pkgname;
              pkg->version = pkgver;
              pkg->category = pkgcat;
              pkg->slot = pkgslot;
              pkg->repo = pkgrepo;
              pkg->content = pkgcontents;
              pkgs = realloc(pkgs, sizeof(struct epkg) * (i + 1));
              pkgs[i] = *pkg;
              i++;
              free(pkg);
              free(pkgcontents);
              }
            }
          }
        }
      }
    }
  }

  msg(LOG_INFO, "Computing hashes for %d packages.", i);

  // loop through pkgs array, add files to backend
  for (int j = 0; j < i; j++) {
    struct epkg *pkg = &pkgs[j];
    for (int k = 0; k < sizeof(pkg->content); k++) {
      ebuildfiles *file = &pkg->content[k];
      char *path;
      if (asprintf(&path, "/usr/portage/%s/%s/%s/%s", pkg->category, pkg->name, pkg->version, file->path) == -1) {
        path = NULL;
      }
      if (path) {
        add_file_to_backend(path, hashtable_ptr, file->md5);
        free(path);
      }
    }
  }

// it's all ex-debian stuff from here on down...

  for (int i = 0; i < array.n_pkgs; i++) {
    struct pkginfo *package = array.pkgs[i];
    if (package->status != PKG_STAT_INSTALLED) {
      continue;
    }
    printf("\x1b[2K\rPackage %d / %d : %s", i + 1, array.n_pkgs,
           package->set->name);
    if (pkg_infodb_has_file(package, &package->installed, control_file))
      pkg_infodb_get_file(package, &package->installed, control_file);
    ensure_packagefiles_available(package);

    // Should not need this copy of code ...
    parse_filehash2(package, &package->installed);

    // This is causing segfault in linked lib :/
    // parse_filehash(package, &package->installed);
    // ensure_diversions();

    struct fsys_namenode_list *file = package->files;
    if (!file) {
      // Package does not have any files.
      continue;
    }
    // Loop over all files in the package, adding them to ebuilddb.
    while (file) {
      struct fsys_namenode *namenode = file->namenode;
      // Get the hash and path of the file.
      const char *hash =
          (namenode->newhash == NULL) ? namenode->oldhash : namenode->newhash;
      const char *path = (namenode->divert && !namenode->divert->camefrom)
                             ? namenode->divert->useinstead->name
                             : namenode->name;
      if (hash != NULL) {
        add_file_to_backend(path, hashtable_ptr, hash);
      }
      file = file->next;
    }
  }

  struct _hash_record *item, *tmp;
  HASH_ITER(hh, hashtable, item, tmp) {
    HASH_DEL(hashtable, item);
    free((void *)item->key);
    free((void *)item);
  }

  pkg_array_destroy(&array);
  return 0;
}

static int ebuild_init_backend() {
  dpkg_program_init(kEbuildBackend);
  list_init(&ebuild_backend.list);

  msg(LOG_INFO, "Loading ebuilddb backend");

  enum modstatdb_rw status = msdbrw_readonly;
  status = modstatdb_open(msdbrw_readonly);
  if (status != msdbrw_readonly) {
    msg(LOG_ERR, "Could not open database for reading. Status %d", status);
    return 1;
  }

  return 0;
}

static int ebuild_destroy_backend() {
  dpkg_program_done();
  list_empty(&ebuild_backend.list);
  modstatdb_shutdown();
  return 0;
}
