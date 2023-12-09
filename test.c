#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include "fd-fgets.h"
#include "message.h"
#include <syslog.h>

#define isoctal(a) (((a) & ~7) == '0')
void unescape_shell(char *s, const size_t len)
{
    size_t sz = 0;
    char *buf = s;
    msg(LOG_DEBUG, "Unescaping shell sequence: %s", s);
    msg(LOG_DEBUG, "Shell sequence length: %zu", len);
    msg(LOG_DEBUG, "Shell sequence len: %zu", strlen(s));

    while (*s) {
        msg(LOG_DEBUG, "Processing char: %c", *s);
        msg(LOG_DEBUG, "Processing index: %zu", sz);
        // "\000"
        if (*s == '\\' && sz + 3 < len && isoctal(s[1]) &&
            isoctal(s[2]) && isoctal(s[3])) {
            // Turn octal into decimal and advance by 4 chars
            *buf++ = 64*(s[1] & 7) + 8*(s[2] & 7) + (s[3] & 7);
            s += 4;
            sz += 4;
        } else if (*s == '\\' && sz + 2 < len) {
            // strip \ and copy character to buffer
            *buf++ = s[1];
            s += 2;
            sz += 2;
        } else {
            *buf++ = *s++;
            sz++;
        }
        msg(LOG_DEBUG, "buf: %s", buf);
        msg(LOG_DEBUG, "s: %s", s);
    }
    *buf = '\0';
}

static void handle_mounts(int fd)
{
	char buf[PATH_MAX * 2], device[1025], point[4097];
	char type[32], mntops[128];
	int fs_req, fs_passno;

	// Rewind the descriptor
	lseek(fd, 0, SEEK_SET);
	fd_fgets_rewind();
	do {
		int rc = fd_fgets(buf, sizeof(buf), fd);
		// Get a line
		if (rc > 0) {
			// Parse it
			sscanf(buf, "%1024s %4096s %31s %127s %d %d\n",
			    device, point, type, mntops, &fs_req, &fs_passno);
			unescape_shell(device, strlen(device));
			unescape_shell(point, strlen(point));
		} else if (rc < 0) // Some kind of error - stop
			break;
	} while (!fd_fgets_eof());
}


int main() {
    int fd = open("/proc/mounts", O_RDONLY);
    handle_mounts(fd);
    return 0;
}
