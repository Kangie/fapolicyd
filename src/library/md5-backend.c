#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/types.h>

#include "file.h"
#include "fapolicyd-backend.h"
#include "message.h"
#include "md5-backend.h"

/*
 * Test file at path and make sure it's sane; return 0 on success.
 */

int test_file(const char *path) {
	struct stat path_stat;
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
	return 0;
}

/*
 * Exclude a known list of paths that shouldn't contain binaries
 * (installed by a package manager, anyway).
 */
int exclude_path(const char *path) {
	const char *excluded_paths[] = {
	"/usr/share/",
	"/usr/src/",
	};
	const int num_excluded_paths = sizeof(excluded_paths) / sizeof(excluded_paths[0]);
	for (int i = 0; i < num_excluded_paths; i++) {
		if (strncmp(path, excluded_paths[i], strlen(excluded_paths[i])) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Given a path to a file with an expected MD5 digest, add
 * the file to the trust database if it matches.
 *
 * Dpkg does not provide sha256 sums or file sizes to verify against.
 * The only source for verification is MD5. The logic implemented is:
 * 1) Calculate the MD5 sum and compare to the expected hash. If it does
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
int add_file_to_backend_by_md5(const char *path,
							const char *expected_md5,
							struct _hash_record **hashtable,
							trust_src_t trust_src,
							backend *backend)
{

	// we can ignore files under certain paths; they should never be binaries
	if(exclude_path(path)) {
		return 1;
	}

	// TODO: Get the backend name tha called us and output that; maybe we're on an insane system that uses portage _and_ deb?
	msg(LOG_DEBUG, "Adding %s", path);
	msg(LOG_DEBUG, "\tExpected MD5: %s", expected_md5);

	if (test_file(path)) {
		return 1;
	}
	int fd = open(path, O_RDONLY|O_NOFOLLOW);
	lseek(fd, 0, SEEK_SET);
	size_t file_size = lseek(fd, 0, SEEK_END);
	if (file_size == (size_t)-1) {
		close(fd);
		msg(LOG_ERR, "Error seeking the end of file %s", path);
		return 1;
	}

	msg(LOG_DEBUG, "\tFile size: %zu", file_size);

	char *md5_digest = get_hash_from_fd2(fd, file_size, 0);
	if (md5_digest == NULL) {
		close(fd);
		msg(LOG_ERR, "MD5 digest returned NULL");
		return 1;
	}
	if (strcmp(md5_digest, expected_md5) != 0) {
		msg(LOG_WARNING, "Skipping %s: hash mismatch. Got %s, expected %s",
				path, md5_digest, expected_md5);
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
	if (asprintf(&data, DATA_FORMAT, trust_src, file_size, sha_digest) == -1) {
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
			list_append(&backend->list, strdup(path), data);
		} else {
			free((void *)data);
		}
		return 0;
	}
	return 1;
}
