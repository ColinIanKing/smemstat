/*
 * Copyright (C) 2014-2021 Canonical, Ltd.
 * Copyright (C) 2021-2024 Colin Ian King.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Colin Ian King <colin.king@canonical.com>
 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE_EXTENDED

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <ncurses.h>
#include <math.h>
#include <locale.h>

#define UNAME_HASH_TABLE_SIZE	(521)
#define PROC_HASH_TABLE_SIZE 	(503)

#define OPT_QUIET		(0x00000001)
#define OPT_CMD_SHORT		(0x00000002)
#define OPT_CMD_LONG		(0x00000004)
#define OPT_CMD_COMM		(0x00000008)
#define OPT_CMD_ALL		(OPT_CMD_SHORT | OPT_CMD_LONG | OPT_CMD_COMM)
#define OPT_DIRNAME_STRIP	(0x00000010)
#define OPT_MEM_IN_KBYTES	(0x00000020)
#define OPT_MEM_IN_MBYTES	(0x00000040)
#define OPT_MEM_IN_GBYTES	(0x00000080)
#define OPT_MEM_ALL		(OPT_MEM_IN_KBYTES | OPT_MEM_IN_MBYTES | OPT_MEM_IN_GBYTES)
#define OPT_TOP			(0x00000100)
#define OPT_TOP_TOTAL		(0x00000200)
#define OPT_ARROW		(0x00000400)

/* process specific information */
typedef struct proc_info {
	struct proc_info *next;		/* next in hash */
	char		*cmdline;	/* Process name from cmdline */
	pid_t		pid;		/* PID */
	bool		kernel_thread;	/* true if process is kernel thread */
} proc_info_t;

/* UID cache */
typedef struct uname_cache_t {
	struct uname_cache_t *next;
	char *		name;		/* User name */
	uid_t		uid;		/* User UID */
} uname_cache_t;

/* wakeup event information per process */
typedef struct mem_info_t {
	pid_t		pid;		/* process id */
	uid_t		uid;		/* process' UID */
	proc_info_t 	*proc;		/* cached process info */
	uname_cache_t	*uname;		/* cached uname info */
	int64_t		size;		/* region size */
	int64_t		rss;		/* RSS size */
	int64_t		pss;		/* PSS size */
	int64_t		uss;		/* USS size */
	int64_t		swap;		/* Swapped out size */
	int64_t		d_rss;		/* Delta RSS */
	int64_t		d_pss;		/* Delta PSS */
	int64_t		d_uss;		/* Delta USS */
	int64_t		d_swap;		/* Delta swap */
	struct mem_info_t *d_next;	/* sorted deltas by total */
	struct mem_info_t *s_next;	/* sorted by total */
	struct mem_info_t *next;	/* for free list */
	bool		alive;		/* true if proc is alive */
} mem_info_t;

typedef struct pid_list {
	struct pid_list	*next;		/* next in list */
	char 		*name;		/* process name */
	pid_t		pid;		/* process id */
} pid_list_t;

typedef struct {
	void (*df_setup)(void);		/* display setup */
	void (*df_endwin)(void);	/* display end */
	void (*df_clear)(void);		/* display clear */
	void (*df_refresh)(void);	/* display refresh */
	void (*df_winsize)(const bool redo);	/* display get size */
	void (*df_printf)(const char *str, ...) __attribute__((format(printf, 1, 2)));
} display_funcs_t;

static uname_cache_t *uname_cache[UNAME_HASH_TABLE_SIZE];
static proc_info_t *proc_cache_hash[PROC_HASH_TABLE_SIZE];
static const char *const app_name = "smemstat";

static bool stop_smemstat = false;	/* set by sighandler */
static unsigned int opt_flags;		/* options */
static mem_info_t *mem_info_cache;	/* cache of mem infos */
static pid_list_t *pids;		/* PIDs to check against */
static display_funcs_t df;		/* display functions */
static bool resized;			/* true when SIGWINCH occurs */
static int rows = 25;			/* display rows */
static int cols = 80;			/* display columns */
static int cury = 0;			/* current display y position */

static void smemstat_top_printf(const char *fmt, ...) \
	__attribute__((format(printf, 1, 2)));

static void smemstat_normal_printf(const char *fmt, ...) \
	__attribute__((format(printf, 1, 2)));

/*
 *  Attempt to catch a range of signals so
 *  we can clean
 */
static const int signals[] = {
	/* POSIX.1-1990 */
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGINT
	SIGINT,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGFPE
	SIGFPE,
#endif
#ifdef SIGTERM
	SIGTERM,
#endif
#ifdef SIGUSR1
	SIGUSR1,
#endif
#ifdef SIGUSR2
	SIGUSR2,
	/* POSIX.1-2001 */
#endif
#ifdef SIGXCPU
	SIGXCPU,
#endif
#ifdef SIGXFSZ
	SIGXFSZ,
#endif
	/* Linux various */
#ifdef SIGIOT
	SIGIOT,
#endif
#ifdef SIGSTKFLT
	SIGSTKFLT,
#endif
#ifdef SIGPWR
	SIGPWR,
#endif
#ifdef SIGINFO
	SIGINFO,
#endif
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	-1,
};

/*
 *  pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
static int pid_max_digits(void)
{
	static int max_digits;
	ssize_t n;
	int fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	if (max_digits)
		goto ret;

	max_digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	max_digits = 0;
	while ((max_digits < n) && (buf[max_digits] >= '0') && (buf[max_digits] <= '9'))
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;

}

/*
 *  handle_sigwinch()
 *      flag window resize on SIGWINCH
 */
static void handle_sigwinch(int sig)
{
	(void)sig;

	resized = true;
}

/*
 *  smemstat_noop()
 *	no-operation display handler
 */
static void smemstat_noop(void)
{
}

/*
 *  smemstat_top_setup()
 *	setup display for ncurses top mode
 */
static void smemstat_top_setup(void)
{
	(void)initscr();
	(void)cbreak();
	(void)noecho();
	(void)nodelay(stdscr, 1);
	(void)keypad(stdscr, 1);
	(void)curs_set(0);
}

/*
 *  smemstat_top_endwin()
 *	end display for ncurses top mode
 */
static void smemstat_top_endwin(void)
{
	df.df_winsize(true);
	(void)resizeterm(rows, cols);
	(void)refresh();
	resized = false;
	(void)clear();
	(void)endwin();
}

/*
 *  smemstat_top_clear()
 *	clear display for ncurses top mode
 */
static void smemstat_top_clear(void)
{
	(void)clear();
}

/*
 *  smemstat_top_refresh()
 *	refresh display for ncurses top mode
 */
static void smemstat_top_refresh(void)
{
	(void)refresh();
}

/*
 *  smemstat_generic_winsize()
 *	get tty size in all modes
 */
static void smemstat_generic_winsize(const bool redo)
{
	if (redo) {
		struct winsize ws;

		(void)memset(&ws, 0, sizeof(ws));
		if ((ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)) {
			rows = ws.ws_row;
			cols = ws.ws_col;
		} else {
			rows = 25;
			cols = 80;
		}
	}
}

/*
 *  smemstat_top_winsize()
 *	get tty size in top mode
 */
static void smemstat_top_winsize(const bool redo)
{
	(void)redo;

	smemstat_generic_winsize(true);
	(void)resizeterm(rows, cols);
}

/*
 *  smemstat_top_printf
 *	print text to display width in top mode
 */
static void smemstat_top_printf(const char *fmt, ...)
{
	va_list ap;
	char buf[4096];
	size_t n, sz = sizeof(buf) - 1;

	smemstat_top_winsize(true);

	if (cury >= rows)
		return;

	move(cury, 0);
	if ((size_t)cols < sz)
		sz = (size_t)cols;

	memset(buf, 0, sizeof(buf));
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (n > sizeof(buf))
		n = sizeof(buf) - 1;
	if (n > sz)
		n = sz;
	buf[n] = '\0';
	(void)mvprintw(cury, 0, "%s", buf);
	va_end(ap);
	cury++;
}

/*
 *  smemstat_normal_printf
 *	normal tty printf
 */
static void smemstat_normal_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stdout, fmt, ap);
	(void)fflush(stdout);
	va_end(ap);
}

/* ncurses based "top" mode display functions */
static const display_funcs_t df_top = {
	smemstat_top_setup,
	smemstat_top_endwin,
	smemstat_top_clear,
	smemstat_top_refresh,
	smemstat_top_winsize,
	smemstat_top_printf,
};

/* normal tty mode display functions */
static const display_funcs_t df_normal = {
	smemstat_noop,
	smemstat_noop,
	smemstat_noop,
	smemstat_noop,
	smemstat_generic_winsize,
	smemstat_normal_printf,
};

/*
 *  display_restore()
 *	restore display back to normal tty
 */
static void display_restore(void)
{
	df.df_endwin();
	df = df_normal;
}

/*
 *  out_of_memory()
 *      report out of memory condition
 */
static void out_of_memory(const char *msg)
{
	display_restore();
	(void)fprintf(stderr, "Out of memory: %s.\n", msg);
}

/*
 *  uname_name()
 *	fetch name from uname, handle
 *	unknown NULL unames too
 */
static inline const char *uname_name(const uname_cache_t * const uname)
{
	return uname ? uname->name : "<unknown>";
}

/*
 *  count_bits()
 */
#if defined(__GNUC__)
/*
 *  use GCC built-in
 */
static inline unsigned int count_bits(const unsigned int val)
{
	return __builtin_popcount(val);
}
#else
/*
 *  count bits set, from C Programming Language 2nd Ed
 */
static inline unsigned int OPTIMIZE3 HOT count_bits(const unsigned int val)
{
	register unsigned int c, n = val;

	for (c = 0; n; c++)
		n &= n - 1;

	return c;
}
#endif

/*
 *  mem_to_str()
 *	report memory in different units
 */
static void mem_to_str(const double val, char *buf, const size_t buflen)
{
	double s;
	double v = (val < 0.0) ? -val : val;
	char unit;

	(void)memset(buf, 0, buflen);

	if (opt_flags & OPT_MEM_IN_KBYTES) {
		(void)snprintf(buf, buflen, "%9.0f", val / 1024.0);
		return;
	}
	if (opt_flags & OPT_MEM_IN_MBYTES) {
		(void)snprintf(buf, buflen, "%9.3f", val / (1024.0 * 1024.0));
		return;
	}
	if (opt_flags & OPT_MEM_IN_GBYTES) {
		(void)snprintf(buf, buflen, "%9.3f", val / (1024.0 * 1024.0 * 1024.0));
		return;
	}

	if (v < 10.0 * 1024.0) {
		s = (double)val;
		unit = 'B';
	} else if (v < 10.0 * 1024.0 * 1024.0) {
		s = (double)val / 1024.0;
		unit = 'K';
	} else if (v < 10.0 * 1024.0 * 1024.0 * 1024.0) {
		s = (double)val / (1024.0 * 1024.0);
		unit = 'M';
	} else {
		s = (double)val / (1024.0 * 1024.0 * 1024.0);
		unit = 'G';
	}
	(void)snprintf(buf, buflen, "%7.1f %c", s, unit);
}

/*
 *  mem_report_size()
 *	report units used in memory size
 */
static void mem_report_size(void)
{
	char *unit = "";

	if (!(opt_flags & OPT_MEM_ALL))
		return;
	else if (opt_flags & OPT_MEM_IN_KBYTES)
		unit = "kilo";
	else if (opt_flags & OPT_MEM_IN_MBYTES)
		unit = "mega";
	else if (opt_flags & OPT_MEM_IN_GBYTES)
		unit = "giga";

	if (!(opt_flags & OPT_QUIET))
		(void)printf("Note: Memory reported in units of %sbytes.\n", unit);
}

/*
 *  get_pid_comm
 *	get comm name of a pid
 */
static char *get_pid_comm(const pid_t pid)
{
	char buffer[4096];
	int fd;
	ssize_t ret;

	(void)snprintf(buffer, sizeof(buffer), "/proc/%i/comm", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		return NULL;
	}
	(void)close(fd);
	buffer[ret - 1] = '\0';

	return strdup(buffer);
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t pid)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	(void)snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		return NULL;
	}
	(void)close(fd);

	if (ret >= (ssize_t)sizeof(buffer))
		ret = sizeof(buffer) - 1;
	buffer[ret] = '\0';

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret - 1; ptr++) {
			if (*ptr == '\0')
				*ptr = ' ';
		}
		*ptr = '\0';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ')
				*ptr = '\0';
		}
	}

	if (opt_flags & OPT_DIRNAME_STRIP) {
		char *base = buffer;

		for (ptr = buffer; *ptr; ptr++) {
			if (isblank(*ptr))
				break;
			if (*ptr == '/')
				base = ptr + 1;
		}
		return strdup(base);
	}

	return strdup(buffer);
}

/*
 *  pid_exists()
 *	true if given process with given pid exists
 */
static bool pid_exists(const pid_t pid)
{
	char path[PATH_MAX];
	struct stat statbuf;

	(void)snprintf(path, sizeof(path), "/proc/%i", pid);
	return stat(path, &statbuf) == 0;
}

/*
 *  proc_cache_hash_pid()
 *	hash a process id
 */
static inline unsigned long proc_cache_hash_pid(const pid_t pid)
{
	unsigned long h = (unsigned long)pid;

	return h % PROC_HASH_TABLE_SIZE;
}

/*
 *  proc_cache_add_at_hash_index()
 *	helper function to add proc info to the proc cache and list
 */
static proc_info_t *proc_cache_add_at_hash_index(
	const unsigned long h,
	const pid_t pid)
{
	proc_info_t *p;

	if ((p = calloc(1, sizeof(*p))) == NULL) {
		out_of_memory("allocating proc cache");
		return NULL;
	}

	p->pid = pid;
	p->cmdline = get_pid_cmdline(pid);
	if (p->cmdline == NULL)
		p->kernel_thread = true;

	if ((p->cmdline == NULL) || (opt_flags & OPT_CMD_COMM)) {
		if (p->cmdline)
			free(p->cmdline);
		p->cmdline = get_pid_comm(pid);
	}
	p->next = proc_cache_hash[h];
	proc_cache_hash[h] = p;

	return p;
}

/*
 *  proc_cache_find_by_pid()
 *	find process info by the process id, if it is not found
 * 	and it is a traceable process then cache it
 */
static proc_info_t *proc_cache_find_by_pid(const pid_t pid)
{
	unsigned long h;
	proc_info_t *p;

	h = proc_cache_hash_pid(pid);
	for (p = proc_cache_hash[h]; p; p = p->next)
		if (p->pid == pid)
			return p;

	/*
	 *  Not found, so add it and return it if it is a legitimate
	 *  process to trace
	 */
	if (!pid_exists(pid))
		return NULL;

	return proc_cache_add_at_hash_index(h, pid);
}

/*
 *  proc_cache_cleanup()
 *	free up proc cache hash table
 */
static void proc_cache_cleanup(void)
{
	size_t i;

	for (i = 0; i < PROC_HASH_TABLE_SIZE; i++) {
		proc_info_t *p = proc_cache_hash[i];

		while (p) {
			proc_info_t *next = p->next;

			free(p->cmdline);
			free(p);

			p = next;
		}
	}
}

/*
 *  timeval_to_double
 *      timeval to a double
 */
static inline double timeval_to_double(const struct timeval * const tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  double_to_timeval
 *      seconds in double to timeval
 */
static inline void double_to_timeval(
	const double val,
	struct timeval * const tv)
{
	tv->tv_sec = val;
	tv->tv_usec = (val - (time_t)val) * 1000000.0;
}

/*
 *  gettime_to_double()
 *      get time as a double
 */
static double gettime_to_double(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		display_restore();
		(void)fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
			errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return timeval_to_double(&tv);
}

static inline unsigned long hash_uid(const uid_t uid)
{
        unsigned long h = (unsigned long)uid;

        return h % UNAME_HASH_TABLE_SIZE;
}

/*
 *  uname_cache_find()
 *	lookup uname info on uid and cache data
 */
static uname_cache_t *uname_cache_find(const uid_t uid)
{
	struct passwd *pw;
	uname_cache_t *uname;
	unsigned long h = hash_uid(uid);

	for (uname = uname_cache[h]; uname; uname = uname->next) {
		if (uname->uid == uid)
			return uname;
	}

	if ((uname = calloc(1, sizeof(*uname))) == NULL) {
		out_of_memory("allocating pwd cache item");
		return NULL;
	}

	if ((pw = getpwuid(uid)) == NULL) {
		char buf[16];

		(void)snprintf(buf, sizeof(buf), "%i", uid);
		uname->name = strdup(buf);
	} else {
		uname->name = strdup(pw->pw_name);
	}

	if (uname->name == NULL) {
		out_of_memory("allocating pwd cache item");
		free(uname);
		return NULL;
	}

	uname->uid = uid;
	uname->next = uname_cache[h];
	uname_cache[h] = uname;

	return uname;
}

/*
 *  uname_cache_cleanup()
 *	free cache
 */
static void uname_cache_cleanup(void)
{
	size_t i;

	for (i = 0; i < UNAME_HASH_TABLE_SIZE; i++) {
		uname_cache_t *u = uname_cache[i];

		while (u) {
			uname_cache_t *next = u->next;

			free(u->name);
			free(u);
			u = next;
		}
	}
}

/*
 *  mem_get_size()
 *	parse proc sizes in K bytes
 */
static int mem_get_size(
	FILE * const fp,
	const char * const field,
	const size_t len,
	uint64_t *size)
{
	char buf[4096];
	uint64_t size_k;

	*size = 0;

	/*
	 *  scanf is expensive, so.. read a line in at a time
	 *  and if we have a potential match then parse with
	 *  sscanf
	 */
	while (fgets(buf, sizeof(buf) - 1, fp)) {
		if (!strncmp(buf, field, len) &&
		    sscanf(buf + len, "%" SCNi64, &size_k) == 1) {
			*size = size_k * 1024;
			return 0;
		}
	}
	return -1;
}

/*
 *  mem_get_entry()
 *	parse a single memory mapping entry
 */
static int mem_get_entry(
	FILE * const fp,
	mem_info_t * const mem)
{
	uint64_t addr_start, addr_end, addr_offset;
	int major, minor;
	char path[PATH_MAX];
	uint64_t rss, pss, priv_clean, priv_dirty, swap;

	for (;;) {
		char buffer[4096];

		if (fgets(buffer, sizeof(buffer), fp) == NULL)
			return -1;
		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %x:%x %*u %s",
			&addr_start, &addr_end, &addr_offset, &major, &minor, path) == 6)
			break;
		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %x:%x %*u",
			&addr_start, &addr_end, &addr_offset, &major, &minor) == 5) {
			*path = '\0';
			break;
		}
	}

	if (mem_get_size(fp, "Rss:", 4, &rss) < 0)
		return -1;
	if (mem_get_size(fp, "Pss:", 4, &pss) < 0)
		return -1;
	if (mem_get_size(fp, "Private_Clean:", 14, &priv_clean) < 0)
		return -1;
	if (mem_get_size(fp, "Private_Dirty:", 14, &priv_dirty) < 0)
		return -1;
	if (mem_get_size(fp, "Swap:", 5, &swap) < 0)
		return -1;

	mem->rss += rss;
	mem->pss += pss;
	mem->uss += priv_clean + priv_dirty;
	mem->swap += swap;
	return 0;
}

/*
 *  mem_cache_alloc()
 *	allocate a mem_info_t, first try the cache of
 *	unused mem_info's, if none available fall back
 *	to calloc
 */
static mem_info_t *mem_cache_alloc(void)
{
	mem_info_t *mem;

	if (mem_info_cache) {
		mem = mem_info_cache;
		mem_info_cache = mem_info_cache->next;

		(void)memset(mem, 0, sizeof(*mem));

		return mem;
	}

	if ((mem = calloc(1, sizeof(*mem))) == NULL) {
		out_of_memory("allocating memory tracking information");
		return NULL;
	}
	return mem;
}

/*
 *  mem_cache_free()
 *	free a mem_info_t by just adding it to the
 *	mem_info_cache free list
 */
static void mem_cache_free(mem_info_t * const mem)
{
	mem->next = mem_info_cache;
	mem_info_cache = mem;
}

/*
 *  mem_cache_free_list()
 *	free up a list of mem_info_t items by
 *	adding them to the mem_info_cache free list
 */
static void mem_cache_free_list(mem_info_t *mem)
{
	while (mem) {
		mem_info_t *next = mem->next;

		mem_cache_free(mem);
		mem = next;
	}
}

/*
 *  mem_cache_prealloc()
 *	create some spare mem_info_t items on
 *	the free list so that we don't keep on
 *	hitting the heap during the run
 */
static void mem_cache_prealloc(const size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		mem_info_t *mem;

		if ((mem = calloc(1, sizeof(*mem))) != NULL)
			mem_cache_free_list(mem);
	}
}

/*
 *  mem_cache_cleanup()
 *	free the mem_info_cache free list
 */
static void mem_cache_cleanup(void)
{
	while (mem_info_cache) {
		mem_info_t *next = mem_info_cache->next;

		free(mem_info_cache);
		mem_info_cache = next;
	}
}

/*
 *  mem_get_by_proc()
 *	get mem info for a specific proc
 */
static int mem_get_by_proc(const pid_t pid, mem_info_t ** const mem)
{
	FILE *fp;
	char path[PATH_MAX];
	char buffer[4096];
	mem_info_t m, *new_m;
	proc_info_t *proc;

	if (getpgid(pid) == 0)
		return 0;	/* Kernel thread */

	if ((proc = proc_cache_find_by_pid(pid)) == NULL)
		return 0;	/* It died before we could get info */

	if (proc->kernel_thread)
		return 0;	/* Ignore */

	if (pids) {
		pid_list_t *p;
		char *tmp = basename(proc->cmdline);

		for (p = pids; p; p = p->next) {
			if (p->pid == pid)
				break;
			if (tmp && p->name && strcmp(p->name, tmp) == 0)
				break;
		}
		if (!p)
			return 0;
	}

	(void)snprintf(path, sizeof(path), "/proc/%i/smaps", pid);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;	/* Gone away? */

	(void)memset(&m, 0, sizeof(m));

	errno = 0;
	while (mem_get_entry(fp, &m) != -1)
		;

	/* Can't read it, no access rights? */
	if (errno == EACCES) {
		(void)fclose(fp);
		return 0;
	}
	(void)fclose(fp);

	if ((new_m = mem_cache_alloc()) == NULL)
		return -1;

	(void)memcpy(new_m, &m, sizeof(m));
	new_m->pid = pid;
	new_m->proc = proc_cache_find_by_pid(pid);
	new_m->uid = 0;
	new_m->uname = NULL;
	new_m->next = *mem;
	*mem = new_m;

	(void)snprintf(path, sizeof(path), "/proc/%i/status", pid);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;

	/*
	 *  Find Uid and uname. Note that it may
	 *  not be found, in which case new->uname is
	 *  still NULL, so we need to always use
	 *  uname_name() to fetch the uname to handle
	 *  the NULL uname cases.
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!strncmp(buffer, "Uid:", 4)) {
			if (sscanf(buffer + 5, "%9i", &new_m->uid) == 1) {
				new_m->uname = uname_cache_find(new_m->uid);
				if (new_m->uname == NULL) {
					(void)fclose(fp);
					return -1;
				}
				break;
			}
		}
	}
	(void)fclose(fp);

	return 0;
}

/*
 *  mem_get_all_pids()
 *	scan mem and get mmap info
 */
static int mem_get_all_pids(mem_info_t ** const mem, size_t * const npids)
{
	DIR *dir;
	struct dirent *entry;
	*npids = 0;

	if ((dir = opendir("/proc")) == NULL) {
		display_restore();
		(void)fprintf(stderr, "Cannot read directory /proc\n");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		pid_t pid;

		if (!isdigit(entry->d_name[0]))
			continue;
		pid = (pid_t)strtoul(entry->d_name, NULL, 10);

		if (mem_get_by_proc(pid, mem) < 0) {
			(void)closedir(dir);
			return -1;
		}
		(*npids)++;
	}

	(void)closedir(dir);

	return 0;
}


/*
 *  mem_delta()
 *	compute memory size change
 */
static void mem_delta(mem_info_t * const mem_new, mem_info_t *const mem_old_list)
{
	mem_info_t *mem_old;

	for (mem_old = mem_old_list; mem_old; mem_old = mem_old->next) {
		if (mem_new->pid == mem_old->pid) {
			mem_new->d_uss = mem_new->uss - mem_old->uss;
			mem_new->d_rss = mem_new->rss - mem_old->rss;
			mem_new->d_pss = mem_new->pss - mem_old->pss;
			mem_new->d_swap = mem_new->swap - mem_old->swap;
			mem_old->alive = true;
			return;
		}
	}
	mem_new->d_uss = mem_new->uss;
	mem_new->d_rss = mem_new->rss;
	mem_new->d_pss = mem_new->pss;
	mem_new->d_swap = mem_new->swap;
}

/*
 *  mem_cmdline()
 *	get command line if it is defined
 */
static inline char *mem_cmdline(const mem_info_t * const m)
{
	if (m->proc && m->proc->cmdline)
		return m->proc->cmdline;

	return "<unknown>";
}

/*
 *  mem_dump()
 *	dump out memory usage
 */
static int mem_dump(
	FILE * const json,
	mem_info_t * const mem_info_old,
	mem_info_t * const mem_info_new,
	const bool one_shot)
{
	mem_info_t *m, **l;
	mem_info_t *sorted = NULL;
	int64_t	t_swap = 0, t_uss = 0, t_pss = 0, t_rss = 0;
	char s_swap[12], s_uss[12], s_pss[12], s_rss[12];
	const int pid_size = pid_max_digits();

	if (one_shot)
		opt_flags &= ~OPT_ARROW;

	for (m = mem_info_new; m; m = m->next) {
		mem_delta(m, mem_info_old);
		for (l = &sorted; *l; l = &(*l)->s_next) {
			if ((*l)->pss < m->pss) {
				m->s_next = (*l);
				break;
			}
		}
		*l = m;

		t_swap += m->swap;
		t_uss  += m->uss;
		t_pss  += m->pss;
		t_rss  += m->rss;
	}

	for (m = mem_info_old; m; m = m->next) {
		if (m->alive)
			continue;

		/* Process has died, so include it as -ve delta */
		for (l = &sorted; *l; l = &(*l)->d_next) {
			if ((*l)->d_pss < m->d_pss) {
				m->d_next = (*l);
				break;
			}
		}
		*l = m;

		t_swap -= m->swap;
		t_uss  -= m->uss;
		t_pss  -= m->pss;
		t_rss  -= m->rss;

		m->d_swap = -m->swap;
		m->d_uss  = -m->uss;
		m->d_pss  = -m->pss;
		m->d_rss  = -m->rss;

		m->swap = 0;
		m->uss = 0;
		m->pss = 0;
		m->rss = 0;
	}

	if (json) {
		(void)fprintf(json, "    \"smem-per-process\":[\n");
	}

	if (!(opt_flags & OPT_QUIET))
		df.df_printf("%*.*s      Swap       USS       PSS       RSS %sUser       Command\n",
			pid_size, pid_size, "PID",
			opt_flags & OPT_ARROW ? "D " : "");

	for (m = sorted; m; m = m->s_next) {
		const char *cmd = mem_cmdline(m);

		mem_to_str((double)m->swap, s_swap, sizeof(s_swap));
		mem_to_str((double)m->uss, s_uss, sizeof(s_uss));
		mem_to_str((double)m->pss, s_pss, sizeof(s_pss));
		mem_to_str((double)m->rss, s_rss, sizeof(s_rss));

		if (!(opt_flags & OPT_QUIET)) {
			int64_t delta = m->d_swap + m->d_uss + m->d_pss + m->d_rss;
			const char * const arrow = (delta < 0) ? "\u2193 " :
						   ((delta > 0) ? "\u2191 "  : "  ");

			df.df_printf("%*d %9s %9s %9s %9s %s%-10.10s %s\n",
				pid_size, m->pid, s_swap, s_uss, s_pss, s_rss,
				opt_flags & OPT_ARROW ? arrow : "",
				uname_name(m->uname), cmd);
		}

		if (json) {
			(void)fprintf(json, "      {\n");
			(void)fprintf(json, "        \"pid\":%d,\n", m->pid);
			(void)fprintf(json, "        \"user\":\"%s\",\n",
				uname_name(m->uname));
			(void)fprintf(json, "        \"command\":\"%s\",\n", cmd);
			(void)fprintf(json, "        \"swap\":%" PRIi64 ",\n", m->swap);
			(void)fprintf(json, "        \"uss\":%" PRIi64 ",\n", m->uss);
			(void)fprintf(json, "        \"pss\":%" PRIi64 ",\n", m->pss);
			(void)fprintf(json, "        \"rss\":%" PRIi64 "\n", m->rss);
			(void)fprintf(json, "      }%s\n",
				m->s_next ? "," : "");
		}
	}

	mem_to_str((double)t_swap, s_swap, sizeof(s_swap));
	mem_to_str((double)t_uss, s_uss, sizeof(s_uss));
	mem_to_str((double)t_pss, s_pss, sizeof(s_pss));
	mem_to_str((double)t_rss, s_rss, sizeof(s_rss));

	if (!(opt_flags & OPT_QUIET))
		df.df_printf("%-*.*s %9s %9s %9s %9s\n\n",
			pid_size, pid_size, "Total:",
			s_swap, s_uss, s_pss, s_rss);

	if (json) {
		(void)fprintf(json, "    ],\n");
		(void)fprintf(json, "    \"smem-total\":{\n");
		(void)fprintf(json, "      \"swap\":%" PRIi64 ",\n", t_swap);
		(void)fprintf(json, "      \"uss\":%" PRIi64 ",\n", t_uss);
		(void)fprintf(json, "      \"pss\":%" PRIi64 ",\n", t_pss);
		(void)fprintf(json, "      \"rss\":%" PRIi64 "\n", t_rss);
		(void)fprintf(json, "    }\n");
	}

	return 0;
}

/*
 *  mem_dump_diff()
 *	dump differences between old and new events
 */
static int mem_dump_diff(
	FILE * const json,
	mem_info_t * const mem_info_old,
	mem_info_t * const mem_info_new,
	const double duration)
{
	mem_info_t *m, **l;
	mem_info_t *sorted_deltas = NULL;
	int64_t	t_swap = 0, t_uss = 0, t_pss = 0, t_rss = 0;
	int64_t	t_d_swap = 0, t_d_uss = 0, t_d_pss = 0, t_d_rss = 0;
	char s_swap[12], s_uss[12], s_pss[12], s_rss[12];
	const int pid_size = pid_max_digits();

	for (m = mem_info_new; m; m = m->next) {
		mem_delta(m, mem_info_old);
		if ((m->d_uss + m->d_pss + m->d_rss) == 0)
			continue;

		for (l = &sorted_deltas; *l; l = &(*l)->d_next) {
			if ((*l)->d_pss < m->d_pss) {
				m->d_next = (*l);
				break;
			}
		}
		*l = m;

		t_swap += m->swap;
		t_uss  += m->uss;
		t_pss  += m->pss;
		t_rss  += m->rss;

		t_d_swap += m->d_swap;
		t_d_uss  += m->d_uss;
		t_d_pss  += m->d_pss;
		t_d_rss  += m->d_rss;
	}

	for (m = mem_info_old; m; m = m->next) {
		if (m->alive)
			continue;

		/* Process has died, so include it as -ve delta */
		for (l = &sorted_deltas; *l; l = &(*l)->d_next) {
			if ((*l)->d_pss < m->d_pss) {
				m->d_next = (*l);
				break;
			}
		}
		*l = m;

		t_swap -= m->swap;
		t_uss  -= m->uss;
		t_pss  -= m->pss;
		t_rss  -= m->rss;

		m->d_swap = -m->swap;
		m->d_uss  = -m->uss;
		m->d_pss  = -m->pss;
		m->d_rss  = -m->rss;

		t_d_swap += m->d_swap;
		t_d_uss  += m->d_uss;
		t_d_pss  += m->d_pss;
		t_d_rss  += m->d_rss;
		t_d_rss  -= m->rss;

		m->swap = 0;
		m->uss = 0;
		m->pss = 0;
		m->rss = 0;
	}

	if (json) {
		static bool first = true;

		if (!first) {
			fprintf(json, "      ,\n");
		}
		first = false;
		(void)fprintf(json, "      {\n");
		(void)fprintf(json, "        \"smem-per-process\":[\n");
	}

	if (!(opt_flags & OPT_QUIET))
		df.df_printf("%*.*s      Swap       USS       PSS       RSS User       Command\n",
			pid_size, pid_size, "PID");
	for (m = sorted_deltas; m; ) {
		const char *cmd = mem_cmdline(m);
		mem_info_t *next = m->d_next;

		mem_to_str((double)m->d_swap / duration, s_swap, sizeof(s_swap));
		mem_to_str((double)m->d_uss / duration, s_uss, sizeof(s_uss));
		mem_to_str((double)m->d_pss / duration, s_pss, sizeof(s_pss));
		mem_to_str((double)m->d_rss / duration, s_rss, sizeof(s_rss));

		if (!(opt_flags & OPT_QUIET)) {
			df.df_printf("%*d %9s %9s %9s %9s %-10.10s %s\n",
				pid_size, m->pid, s_swap, s_uss, s_pss, s_rss,
				uname_name(m->uname), cmd);
		}

		if (json) {
			(void)fprintf(json, "          {\n");
			(void)fprintf(json, "            \"pid\":%d,\n", m->pid);
			(void)fprintf(json, "            \"command\":\"%s\",\n", cmd);
			(void)fprintf(json, "            \"user\":\"%s\",\n",
				uname_name(m->uname));
			(void)fprintf(json, "            \"swap\":%" PRIi64 ",\n", m->swap);
			(void)fprintf(json, "            \"uss\":%" PRIi64 ",\n", m->uss);
			(void)fprintf(json, "            \"pss\":%" PRIi64 ",\n", m->pss);
			(void)fprintf(json, "            \"rss\":%" PRIi64 ",\n", m->rss);
			(void)fprintf(json, "            \"swap-delta\":%" PRIi64 ",\n", m->d_swap);
			(void)fprintf(json, "            \"uss-delta\":%" PRIi64 ",\n", m->d_uss);
			(void)fprintf(json, "            \"pss-delta\":%" PRIi64 ",\n", m->d_pss);
			(void)fprintf(json, "            \"rss-delta\":%" PRIi64 "\n", m->d_rss);
			(void)fprintf(json, "          }%s\n",
				m->d_next ? "," : "");
		}
		m->d_next = NULL;	/* Nullify for next round */
		m = next;
	}

	mem_to_str((double)t_d_swap / duration, s_swap, sizeof(s_swap));
	mem_to_str((double)t_d_uss / duration, s_uss, sizeof(s_uss));
	mem_to_str((double)t_d_pss / duration, s_pss, sizeof(s_pss));
	mem_to_str((double)t_d_rss / duration, s_rss, sizeof(s_rss));

	if (!(opt_flags & OPT_QUIET))
		df.df_printf("%-*.*s %9s %9s %9s %9s\n\n", pid_size, pid_size, "Total:", s_swap, s_uss, s_pss, s_rss);

	if (json) {
		(void)fprintf(json, "        ],\n");
		(void)fprintf(json, "        \"smem-total\":{\n");
		(void)fprintf(json, "          \"swap\":%" PRIi64 ",\n", t_swap);
		(void)fprintf(json, "          \"uss\":%" PRIi64 ",\n", t_uss);
		(void)fprintf(json, "          \"pss\":%" PRIi64 ",\n", t_pss);
		(void)fprintf(json, "          \"rss\":%" PRIi64 ",\n", t_rss);
		(void)fprintf(json, "          \"swap-delta\":%" PRIi64 ",\n", t_d_swap);
		(void)fprintf(json, "          \"uss-delta\":%" PRIi64 ",\n", t_d_uss);
		(void)fprintf(json, "          \"pss-delta\":%" PRIi64 ",\n", t_d_pss);
		(void)fprintf(json, "          \"rss-delta\":%" PRIi64 "\n", t_d_rss);
		(void)fprintf(json, "        }\n");
		(void)fprintf(json, "      }\n");
	}

	return 0;
}

/*
 *  handle_sig()
 *      catch signals and flag a stop
 */
static void handle_sig(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	stop_smemstat = true;
}

/*
 * pid_list_cleanup()
 *	free pid list
 */
static void pid_list_cleanup(void)
{
	pid_list_t *p;

	for (p = pids; p; ) {
		pid_list_t *next = p->next;
		if (p->name)
			free(p->name);
		free(p);
		p = next;
	}
}

/*
 *  parse_pid_list()
 *	parse list of process IDs,
 *	collect process info in pids list
 */
static int parse_pid_list(char * const arg)
{
	char *str, *token;
	pid_list_t *p;

	for (str = arg; (token = strtok(str, ",")) != NULL; str = NULL) {
		if (isdigit(token[0])) {
			pid_t pid;

			errno = 0;
			pid = strtol(token, NULL, 10);
			if (errno) {
				(void)fprintf(stderr, "Invalid pid specified.\n");
				pid_list_cleanup();
				return -1;
			}
			for (p = pids; p; p = p->next) {
				if (p->pid == pid)
					break;
			}
			if (!p) {
				if ((p = calloc(1, sizeof(*p))) == NULL)
					goto nomem;
				p->pid = pid;
				p->name = NULL;
				p->next = pids;
				pids = p;
			}
		} else {
			if ((p = calloc(1, sizeof(*p))) == NULL)
				goto nomem;
			if ((p->name = strdup(token)) == NULL) {
				free(p);
				goto nomem;
			}
			p->pid = 0;
			p->next = pids;
			pids = p;
		}
	}

	return 0;
nomem:
	out_of_memory("allocating pid list.\n");
	pid_list_cleanup();
	return -1;
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	(void)printf("%s, version %s\n\n"
		"Usage: %s [options] [duration] [count]\n"
		"Options are:\n"
		"  -a\t\tshow memory change with up/down arrows\n"
		"  -c\t\tget command name from processes comm field\n"
		"  -d\t\tstrip directory basename off command information\n"
		"  -g\t\treport memory in gigabytes\n"
		"  -h\t\tshow this help information\n"
		"  -k\t\treport memory in kilobytes\n"
		"  -l\t\tshow long (full) command information\n"
		"  -m\t\treport memory in megabytes\n"
		"  -o file\tdump data to json formatted file\n"
		"  -p proclist\tspecify comma separated list of processes to monitor\n"
		"  -q\t\trun quietly, useful for -o output only\n"
		"  -s\t\tshow short command information\n"
		"  -t\t\ttop mode, show only changes in memory\n"
		"  -T\t\ttop mode, show top memory hoggers\n",
		app_name, VERSION, app_name);
}

int main(int argc, char **argv)
{
	mem_info_t *mem_info_old = NULL;
	mem_info_t *mem_info_new = NULL;

	char *json_filename = NULL;
	FILE *json_file = NULL;
	double duration = 1.0;
	struct timeval tv1;
	bool forever = true;
	long int count = 0;
	size_t npids;

	df = df_normal;

	for (;;) {
		int c = getopt(argc, argv, "acCdghklmo:p:qstT");

		if (c == -1)
			break;
		switch (c) {
		case 'a':
			opt_flags |= OPT_ARROW;
			break;
		case 'c':
			opt_flags |= OPT_CMD_COMM;
			break;
		case 'd':
			opt_flags |= OPT_DIRNAME_STRIP;
			break;
		case 'g':
			opt_flags |= OPT_MEM_IN_GBYTES;
			break;
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'k':
			opt_flags |= OPT_MEM_IN_KBYTES;
			break;
		case 'l':
			opt_flags |= OPT_CMD_LONG;
			break;
		case 'm':
			opt_flags |= OPT_MEM_IN_MBYTES;
			break;
		case 'o':
			json_filename = optarg;
			break;
		case 'p':
			if (parse_pid_list(optarg) < 0)
				exit(EXIT_FAILURE);
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 's':
			opt_flags |= OPT_CMD_SHORT;
			break;
		case 'T':
			opt_flags |= OPT_TOP_TOTAL;
			/* fall through */
		case 't':
			opt_flags |= OPT_TOP;
			count = -1;
			break;
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (count_bits(opt_flags & OPT_CMD_ALL) > 1) {
		(void)fprintf(stderr, "Cannot have -c, -l, -s at same time.\n");
		exit(EXIT_FAILURE);
	}
	if (count_bits(opt_flags & OPT_MEM_ALL) > 1) {
		(void)fprintf(stderr, "Cannot have -k, -m, -g at same time.\n");
		exit(EXIT_FAILURE);
	}

	setlocale(LC_ALL, "");

	if (optind < argc) {
		errno = 0;
		duration = strtof(argv[optind++], NULL);
		if (errno) {
			(void)fprintf(stderr, "Invalid or out of range value for duration\n");
			exit(EXIT_FAILURE);
		}
		if (duration < 1.0) {
			(void)fprintf(stderr, "Duration must be 1.0 or more seconds.\n");
			exit(EXIT_FAILURE);
		}
		count = -1;
	}

	if (optind < argc) {
		forever = false;
		errno = 0;
		count = strtol(argv[optind++], NULL, 10);
		if (errno) {
			(void)fprintf(stderr, "Invalid or out of range value for count\n");
			exit(EXIT_FAILURE);
		}
		if (count < 1) {
			(void)fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (json_filename) {
		if ((json_file = fopen(json_filename, "w")) == NULL) {
			(void)fprintf(stderr, "Cannot open json output file '%s'.\n", json_filename);
			exit(EXIT_FAILURE);
		}
		(void)fprintf(json_file, "{\n  \"%s\":{\n", app_name);
	}

	if (count == 0) {
		if (mem_get_all_pids(&mem_info_new, &npids) == 0) {
			mem_dump(json_file, mem_info_old, mem_info_new, true);
			mem_report_size();
		}
	} else {
		struct sigaction new_action;
		uint64_t t = 1;
		int i;
		bool redo = false;
		double duration_secs = (double)duration, time_start, time_now;

		if (opt_flags & OPT_TOP)
			df = df_top;
		/*
		 *  Pre-cache, this way we reduce
		 *  the amount of mem infos we alloc during
		 *  sampling
		 */
		if (mem_get_all_pids(&mem_info_old, &npids) < 0)
			goto free_cache;
		mem_cache_prealloc((npids * 5) / 4);

		if (gettimeofday(&tv1, NULL) < 0) {
			(void)fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (!(opt_flags & (OPT_TOP | OPT_QUIET)))
			(void)printf("Change in memory (average per second):\n");

		(void)memset(&new_action, 0, sizeof(new_action));
		for (i = 0; signals[i] != -1; i++) {
			new_action.sa_handler = handle_sig;
			sigemptyset(&new_action.sa_mask);
			new_action.sa_flags = 0;

			if (sigaction(signals[i], &new_action, NULL) < 0) {
				(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
					errno, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		(void)memset(&new_action, 0, sizeof(new_action));
		new_action.sa_handler = handle_sigwinch;
		if (sigaction(SIGWINCH, &new_action , NULL) < 0) {
			(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (json_file) {
			(void)fprintf(json_file, "    \"periodic-samples\":[\n");
		}

		time_now = time_start = gettime_to_double();

		df.df_setup();
		df.df_winsize(true);

		while (!stop_smemstat && (forever || count--)) {
			struct timeval tv;
			double secs;
			int nchar;

			df.df_clear();
			cury = 0;

			/* Timeout to wait for in the future for this sample */
			secs = time_start + ((double)t * duration_secs) - time_now;
			/* Play catch-up, probably been asleep */
			if (secs < 0.0) {
				t = ceil((time_now - time_start) / duration_secs);
				secs = time_start +
					((double)t * duration_secs) - time_now;
				/* We don't get sane stats if duration is too small */
				if (secs < 0.5)
					secs += duration_secs;
			} else {
				if (!redo)
					t++;
			}
			redo = false;

			double_to_timeval(secs, &tv);
retry:
			if (select(0, NULL, NULL, NULL, &tv) < 0) {
				if (errno == EINTR) {
					if (!resized) {
						stop_smemstat = true;
					} else {
						redo = true;
						df.df_winsize(true);
						if (timeval_to_double(&tv) > 0.0)
							goto retry;
					}
				} else {
					display_restore();
					(void)fprintf(stderr, "Select failed: %s\n", strerror(errno));
					break;
				}
			}

			nchar = 0;
			if ((ioctl(0, FIONREAD, &nchar) == 0) && (nchar > 0)) {
				char ch;

				nchar = read(0, &ch, 1);
				if (nchar == 1) {
					switch (ch) {
					case 'q':
					case 'Q':
					case 27:
						stop_smemstat = true;
						break;
					case 'a':
						opt_flags ^= OPT_ARROW;
						break;
					case 't':
						opt_flags ^= OPT_TOP_TOTAL;
						break;
					}
				}
			}


			if (mem_get_all_pids(&mem_info_new, &npids) < 0)
				goto free_cache;

			if (opt_flags & OPT_TOP_TOTAL) {
				mem_dump(json_file, mem_info_old, mem_info_new, false);
			} else {
				mem_dump_diff(json_file, mem_info_old, mem_info_new, duration);
			}
			df.df_refresh();

			mem_cache_free_list(mem_info_old);
			mem_info_old = mem_info_new;
			mem_info_new = NULL;
			time_now = gettime_to_double();
		}
		mem_report_size();

		if (json_file)
			(void)fprintf(json_file, "    ]\n");

free_cache:
		mem_cache_free_list(mem_info_old);
	}

	display_restore();
	uname_cache_cleanup();
	proc_cache_cleanup();
	mem_cache_cleanup();
	pid_list_cleanup();

	if (json_file) {
		(void)fprintf(json_file, "  }\n}\n");
		(void)fclose(json_file);
	}

	exit(EXIT_SUCCESS);
}
