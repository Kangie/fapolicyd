/*
 * fapolicyd.c - Main file for the program
 * Copyright (c) 2016,2018-22 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Radovan Sroka <rsroka@redhat.com>
 */

#include <fcntl.h>           // for open, O_RDONLY, SEEK_SET
#include <limits.h>          // for PATH_MAX
#include <poll.h>            // for pollfd, POLLIN, POLLPRI
#include <signal.h>          // for sigaction
#include <stdatomic.h>       // for atomic_bool
#include <stdio.h>           // for fprintf, fputs, sscanf, FILE
#include <stdlib.h>          // for free, malloc, exit, size_t
#include <string.h>          // for strdup, strlen, strcmp, strtok_r, strncmp
#include <sys/resource.h>    // for rlimit
#include <syslog.h>          // for LOG_DEBUG, LOG_ERR
#include <unistd.h>          // for NULL, lseek
#include "avl.h"             // for avl_t, avl_init, avl_insert, avl_remove
#include "conf.h"            // for conf_t
#include "config.h"          // for DEBUG
#include "database.h"        // for database_report
#include "event.h"           // for do_cache_reports
#include "escape.h"          // for unescape_shell
#include "fd-fgets.h"        // for fd_fgets, fd_fgets_eof, fd_fgets_rewind
#include "gcc-attributes.h"  // for NORETURN
#include "message.h"         // for msg
#include "mounts.h"          // for mlist_append, mlist_create, mlist_find

#include "queue.h"           // for q_report


	// Global program variables
	unsigned int debug_mode = 0, permissive = 0;

	// Signal handler notifications
	volatile atomic_bool stop = 0, hup = 0, run_stats = 0;

	// Local variables
	static conf_t config;
	// This holds info about all file systems to watch
	struct fs_avl {
		avl_tree_t index;
	};
	// This is the data about a specific file system to watch
	typedef struct fs_data {
			avl_t avl;        // This has to be first
			const char *fs_name;
	} fs_data_t;
	static struct fs_avl filesystems;

	// List of mounts being watched
	static mlist *m = NULL;

	static void usage(void) NORETURN;

static int cmp_fs(void *a, void *b)
{
	return strcmp(((fs_data_t *)a)->fs_name, ((fs_data_t *)b)->fs_name);
}


static void free_filesystem(fs_data_t *s)
{
	free((void *)s->fs_name);
	free((void *)s);
}


static void destroy_filesystem(void)
{
	avl_t *cur = filesystems.index.root;

	fs_data_t *tmp =(fs_data_t *)avl_remove(&filesystems.index, cur);
	if ((avl_t *)tmp != cur)
		msg(LOG_DEBUG, "filesystem: removal of invalid node");
	free_filesystem(tmp);
}


static void destroy_fs_list(void)
{
	while (filesystems.index.root)
		destroy_filesystem();
}


static int add_filesystem(fs_data_t *f)
{
	fs_data_t *tmp=(fs_data_t *)avl_insert(&filesystems.index,(avl_t *)(f));
	if (tmp) {
		if (tmp != f) {
			msg(LOG_DEBUG, "fs_list: duplicate filesystem found");
			free_filesystem(f);
		}
		return 1;
	}
	return 0;
}


static fs_data_t *new_filesystem(const char *fs)
{
	fs_data_t *tmp = malloc(sizeof(fs_data_t));
	if (tmp) {
		tmp->fs_name = fs ? strdup(fs) : strdup("");
		if (add_filesystem(tmp) != 0)
			return NULL;
	}
	return tmp;
}


static fs_data_t *find_filesystem(const char *f)
{
	fs_data_t tmp;

	tmp.fs_name = f;
	return (fs_data_t *)avl_search(&filesystems.index, (avl_t *) &tmp);
}


static void init_fs_list(const char *watch_fs)
{
	if (watch_fs == NULL) {
		msg(LOG_ERR, "File systems to watch is empty");
		exit(1);
	}
	avl_init(&filesystems.index, cmp_fs);

	// Now parse up list and push into avl
	char *ptr, *saved, *tmp = strdup(watch_fs);
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		new_filesystem(ptr);
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);
}


// Returns 1 if we care about the entry and 0 if we do not
static int check_mount_entry(const char *point, const char *type)
{
	// Some we know we don't want
	if (strcmp(point, "/run") == 0)
		return 0;
	if (strncmp(point, "/sys", 4) == 0)
		return 0;

	if (find_filesystem(type))
		return 1;
	else
		return 0;
}

static void handle_mounts(int fd)
{
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno;

	if (m == NULL) {
		m = malloc(sizeof(mlist));
		mlist_create(m);
	}

	// Rewind the descriptor
	lseek(fd, 0, SEEK_SET);
	fd_fgets_rewind();
	mlist_mark_all_deleted(m);
	do {
		int rc = fd_fgets(buf, sizeof(buf), fd);
		// Get a line
		if (rc > 0) {
			// Parse it
			#ifdef DEBUG
			msg(LOG_DEBUG, "mounts: %s", buf);
			#endif
			sscanf(buf, "%1024s %4096s %31s %127s %d %d\n",
			    device, point, type, mntops, &fs_req, &fs_passno);
			#ifdef DEBUG
			msg(LOG_DEBUG, "device: %s", device);
			msg(LOG_DEBUG, "device_addr: %p", &device);
			msg(LOG_DEBUG, "mount point: %s", point);
			msg(LOG_DEBUG, "point_addr: %p", &point);
			#endif
			unescape_shell(device, strlen(device));
			unescape_shell(point, strlen(point));
			// Is this one that we care about?
			if (check_mount_entry(point, type)) {
				// Can we find it in the old list?
				if (mlist_find(m, point)) {
					// Mark no change
					m->cur->status = NO_CHANGE;
				} else
					mlist_append(m, point);
			}
		} else if (rc < 0) // Some kind of error - stop
			break;
	} while (!fd_fgets_eof());

	// update marks
	//fanotify_update(m);
}




int main(void)
{
	struct pollfd pfd[2];
	struct sigaction sa;
	struct rlimit limit;

	// Initialize the file watch system
	pfd[0].fd = open("/proc/mounts", O_RDONLY);
	pfd[0].events = POLLPRI;
	handle_mounts(pfd[0].fd);
	//pfd[1].fd = init_fanotify(&config, m);
	pfd[1].events = POLLIN;

	// meat and potatoes of the code used to be here

}
