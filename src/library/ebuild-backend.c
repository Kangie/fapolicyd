#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "conf.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "message.h"
#include "md5-backend.h"

static const char kEbuildBackend[] = "ebuilddb";

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
	char *cpv;
	char *slot;
	char *repo;
	ebuildfiles *content;
};

/*
 * Portage stores data about installed packages in the VDB (/var/db/pkg/).
 * We care about /var/db/pkg/category/package-version/CONTENTS
 * which lists files and directories that are installed as part of a package 'merge'
 * operation. All files are prefixed with 'obj' and are in the format:
 * obj /path/to/file $(md5sum /path/to/file) $(date -r /path/to/file "+%s")
 * e.g.
 * obj /usr/bin/clamscan 3ade185bd024e29880e959e6ad187515 1693552964
 */
static int ebuild_load_list(const conf_t *conf) { // TODO: implement conf_t
	list_empty(&ebuild_backend.list);
	struct _hash_record *hashtable = NULL;
	struct _hash_record **hashtable_ptr = &hashtable;

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
								// CONTENTS
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

							// Construct a CPV string from VDB path fragments e.g. dev-libs/libxml2-2.9.10{-r0}
							// We're not processing based on this information, but it's useful for logging
							// If there's a need to split into components see
							// https://github.com/gentoo/portage-utils/blob/master/libq/atom.c
							char *catpkgver;
							strcpy(catdp->d_name, catpkgver);
							strcat(catpkgver, "/");
							strcat(catpkgver, pkgverdp->d_name);

							// add to pkgs array
							struct epkg *package = malloc(sizeof(struct epkg));
							package->cpv = catpkgver;
							package->slot = pkgslot;
							package->repo = pkgrepo;
							package->content = pkgcontents;
							pkgs = realloc(pkgs, sizeof(struct epkg) * (i + 1));
							pkgs[i] = *package;
							i++;
							free(catpkgver);
							free(package);
							free(pkgcontents);
							}
						}
					}
				}
			}
		}
	}

	msg(LOG_INFO, "Computing hashes for %d packages.", i);

	for (int j = 0; j < i; j++) {
		struct epkg *pkg = &pkgs[j];
		msg(LOG_INFO, "Computing hashes for %s:%s (%s)", pkg->cpv, pkg->slot, pkg->repo);
		for (int k = 0; k < sizeof(pkg->content); k++) {
			ebuildfiles *file = &pkg->content[k];
			add_file_to_backend(file->path, file->md5, hashtable_ptr, SRC_EBUILD, ebuild_backend);
		}
	}
	free(pkgs);
	return 0;
}

static int ebuild_init_backend(void)
{
	if (filter_init())
		return 1;

	if (filter_load_file()) {
		filter_destroy();
		return 1;
	}

	list_init(&ebuild_backend.list);

	return 0;
}

static int ebuild_destroy_backend(void)
{
	filter_destroy();
	list_empty(&ebuild_backend.list);
	return 0;
}
