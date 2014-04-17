/*
 * Copyright (C) 2014 Canonical, Ltd.
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#define APP_NAME		"smemstat"

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

/* process specific information */
typedef struct __attribute__ ((__packed__)) proc_info {
	pid_t		pid;		/* PID */
	bool		kernel_thread;	/* true if process is kernel thread */
	char		*cmdline;	/* Process name from cmdline */
	struct proc_info *next;		/* next in hash */
} proc_info_t;

/* UID cache */
typedef struct __attribute__ ((__packed__)) uname_cache_t {
	uid_t		uid;		/* User UID */
	char *		name;		/* User name */
	struct uname_cache_t *next;
} uname_cache_t;

/* wakeup event information per process */
typedef struct __attribute__ ((__packed__)) mem_info_t {
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
	bool		alive;		/* true if proc is alive */

	struct mem_info_t *d_next;	/* sotted deltas by total */
	struct mem_info_t *s_next;	/* sorted by total */
	struct mem_info_t *next;	/* for free list */
} mem_info_t;

static uname_cache_t *uname_cache[UNAME_HASH_TABLE_SIZE];
static proc_info_t *proc_cache_hash[PROC_HASH_TABLE_SIZE];

static bool stop_smemstat = false;	/* set by sighandler */
static unsigned int opt_flags;		/* options */
static mem_info_t *mem_info_cache = NULL;


/*
 *  out_of_memory()
 *      report out of memory condition
 */
static void out_of_memory(const char *msg)
{
	fprintf(stderr, "Out of memory: %s.\n", msg);
}

/*
 *  count_bits()
 *	count bits set, from C Programming Language 2nd Ed
 */
static unsigned int count_bits(unsigned int n)
{
	unsigned int c;

	for (c = 0; n; c++) 
		n &= n - 1;

	return c;
}

/*
 *  mem_to_str()
 *	report memory in different units
 */
static void mem_to_str(const double val, char *buf, const size_t buflen)
{
	double s;
	double v = (val < 0) ? -val : val;
	char unit;

	memset(buf, 0, buflen);

	if (opt_flags & OPT_MEM_IN_KBYTES) {
		snprintf(buf, buflen, "%9.0f", val / 1024.0);
		return;
	}
	if (opt_flags & OPT_MEM_IN_MBYTES) {
		snprintf(buf, buflen, "%9.3f", val / (1024.0 * 1024.0));
		return;
	}
	if (opt_flags & OPT_MEM_IN_GBYTES) {
		snprintf(buf, buflen, "%9.3f", val / (1024.0 * 1024.0 * 1024.0));
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
	snprintf(buf, buflen, "%7.1f %c", s, unit);
}

/*
 *  mem_report_size()
 *	report units used in memory size
 */
static void mem_report_size(void)
{
	char *unit;

	if (!(opt_flags & OPT_MEM_ALL))
		return;

	if (opt_flags & OPT_MEM_IN_KBYTES) 
		unit = "kilo";
	if (opt_flags & OPT_MEM_IN_MBYTES) 
		unit = "mega";
	if (opt_flags & OPT_MEM_IN_GBYTES) 
		unit = "giga";

	printf("Note: Memory reported in units of %sbytes.\n", unit);
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

	snprintf(buffer, sizeof(buffer), "/proc/%i/comm", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);
	buffer[ret-1] = '\0';

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

	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);

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

	if (opt_flags & OPT_DIRNAME_STRIP)
		return strdup(basename(buffer));

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

	snprintf(path, sizeof(path), "/proc/%i", pid);
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

	p->pid  = pid;
	p->cmdline = get_pid_cmdline(pid);
	if (p->cmdline == NULL)
		p->kernel_thread = true;

	if ((p->cmdline == NULL) || (opt_flags & OPT_CMD_COMM))
		p->cmdline = get_pid_comm(pid);
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
	int i;

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
 *  timeval_double
 *      timeval to a double
 */
static inline double timeval_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  timeval_sub()
 *	timeval a - b
 */
static struct timeval timeval_sub(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret, _b;

	_b.tv_sec = b->tv_sec;
	_b.tv_usec = b->tv_usec;

	if (a->tv_usec < _b.tv_usec) {
		int nsec = ((_b.tv_usec - a->tv_usec) / 1000000) + 1;
		_b.tv_sec += nsec;
		_b.tv_usec -= (1000000 * nsec);
	}
	if (a->tv_usec - _b.tv_usec > 1000000) {
		int nsec = (a->tv_usec - _b.tv_usec) / 1000000;
		_b.tv_sec -= nsec;
		_b.tv_usec += (1000000 * nsec);
	}

	ret.tv_sec = a->tv_sec - _b.tv_sec;
	ret.tv_usec = a->tv_usec - _b.tv_usec;

	return ret;
}

/*
 *  timeval_add()
 *	timeval a + b
 */
static struct timeval timeval_add(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret;

	ret.tv_sec = a->tv_sec + b->tv_sec;
	ret.tv_usec = a->tv_usec + b->tv_usec;
	if (ret.tv_usec > 1000000) {
		int nsec = (ret.tv_usec / 1000000);
		ret.tv_sec += nsec;
		ret.tv_usec -= (1000000 * nsec);
	}

	return ret;
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

		snprintf(buf, sizeof(buf), "%i", uid);
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
	int i;

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
static int mem_get_size(FILE *fp, const char *field, uint64_t *size)
{
	char tmp[4096];
	uint64_t size_k;

	*size = 0;

	while (!feof(fp)) {
		if (fscanf(fp, "%4095[^:]: %" SCNi64 "%*[^\n]%*c", tmp, &size_k) == 2) {
			if (strcmp(tmp, field) == 0) {
				*size = size_k * 1024;
				return 0;
			}
		}
	}
	return -1;
}

/*
 *  mem_get_entry()
 *	parse a single memory mapping entry
 */
static int mem_get_entry(FILE *fp, mem_info_t *mem)
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

	if (mem_get_size(fp, "Rss", &rss) < 0)
		return -1;
	if (mem_get_size(fp, "Pss", &pss) < 0)
		return -1;
	if (mem_get_size(fp, "Private_Clean", &priv_clean) < 0)
		return -1;
	if (mem_get_size(fp, "Private_Dirty", &priv_dirty) < 0)
		return -1;
	if (mem_get_size(fp, "Swap", &swap) < 0)
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

		memset(mem, 0, sizeof(*mem));

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
static void mem_cache_free(mem_info_t *mem)
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
static int mem_get_by_proc(const pid_t pid, mem_info_t **mem)
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

	snprintf(path, sizeof(path), "/proc/%i/smaps", pid);
	if ((fp = fopen(path, "r")) == NULL) {
		return 0;	/* Gone away? */
	}

	memset(&m, 0, sizeof(m));

	errno = 0;
	while (mem_get_entry(fp, &m) != -1)
		;

	/* Can't read it, no access rights? */
	if (errno == EACCES) {
		fclose(fp);
		return 0;
	}
	fclose(fp);

	if ((new_m = mem_cache_alloc()) == NULL)
		return -1;

	memcpy(new_m, &m, sizeof(m));
	new_m->pid = pid;
	new_m->proc = proc_cache_find_by_pid(pid);
	new_m->uid = 0;
	new_m->uname = NULL;
	new_m->next = *mem;
	*mem = new_m;

	snprintf(path, sizeof(path), "/proc/%i/status", pid);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!strncmp(buffer, "Uid:", 4)) {
			if (sscanf(buffer + 5, "%9i", &new_m->uid) == 1) {
				new_m->uname = uname_cache_find(new_m->uid);
				if (new_m->uname == NULL) {
					fclose(fp);
					return -1;
				}
				break;
			}
		}
	}
	fclose(fp);

	return 0;
}

/*
 *  mem_get_all_pids()
 *	scan mem and get mmap info
 */
static int mem_get_all_pids(mem_info_t **mem, size_t *npids)
{
	DIR *dir;
	struct dirent *entry;
	*npids = 0;

	if ((dir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot read directory /proc\n");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		pid_t pid;
		if (!isdigit(entry->d_name[0]))
			continue;

		pid = (pid_t)strtoul(entry->d_name, NULL, 10);
		if (mem_get_by_proc(pid, mem) < 0) {
			closedir(dir);
			return -1;
		}
		(*npids)++;
	}

	closedir(dir);

	return 0;
}


/*
 *  mem_delta()
 *	compute memory size change
 */
static void mem_delta(mem_info_t *mem_new, mem_info_t *mem_old_list)
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
static inline char *mem_cmdline(const mem_info_t *m)
{
	if (m->proc && m->proc->cmdline)
		return m->proc->cmdline;

	return "<unknown>";
}

/*
 *  mem_dump()
 *	dump out memory usage
 */
static int mem_dump(FILE *json, mem_info_t *mem_info)
{
	mem_info_t *m, **l;
	mem_info_t *sorted = NULL;
	int64_t	t_swap = 0, t_uss = 0, t_pss = 0, t_rss = 0;
	char s_swap[12], s_uss[12], s_pss[12], s_rss[12];

	for (m = mem_info; m; m = m->next) {
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

	if (json) {
		fprintf(json, "    \"smem-per-process\":[\n");
	}

	if (!(opt_flags & OPT_QUIET))
		printf("  PID       Swap       USS       PSS       RSS User       Command\n");

	for (m = sorted; m; m = m->s_next) {
		const char *cmd = mem_cmdline(m);
		mem_to_str((double)m->swap, s_swap, sizeof(s_swap));
		mem_to_str((double)m->uss, s_uss, sizeof(s_uss));
		mem_to_str((double)m->pss, s_pss, sizeof(s_pss));
		mem_to_str((double)m->rss, s_rss, sizeof(s_rss));

		if (!(opt_flags & OPT_QUIET))
			printf(" %5d %9s %9s %9s %9s %-10.10s %s\n",
				m->pid, s_swap, s_uss, s_pss, s_rss, m->uname->name, cmd);

		if (json) {
			fprintf(json, "      {\n");
			fprintf(json, "        \"pid\":%d,\n", m->pid);
			fprintf(json, "        \"user\":\"%s\",\n", m->uname->name);
			fprintf(json, "        \"command\":\"%s\",\n", cmd);
			fprintf(json, "        \"swap\":%" PRIi64 ",\n", m->swap);
			fprintf(json, "        \"uss\":%" PRIi64 ",\n", m->uss);
			fprintf(json, "        \"pss\":%" PRIi64 ",\n", m->pss);
			fprintf(json, "        \"rss\":%" PRIi64 "\n", m->rss);
			fprintf(json, "      }%s\n",
				m->s_next ? "," : "");
		}
	}

	mem_to_str((double)t_swap, s_swap, sizeof(s_swap));
	mem_to_str((double)t_uss, s_uss, sizeof(s_uss));
	mem_to_str((double)t_pss, s_pss, sizeof(s_pss));
	mem_to_str((double)t_rss, s_rss, sizeof(s_rss));

	if (!(opt_flags & OPT_QUIET))
		printf("Total: %9s %9s %9s %9s\n\n", s_swap, s_uss, s_pss, s_rss);

	if (json) {
		fprintf(json, "    ],\n");
		fprintf(json, "    \"smem-total\":{\n");
		fprintf(json, "      \"swap\":%" PRIi64 ",\n", t_swap);
		fprintf(json, "      \"uss\":%" PRIi64 ",\n", t_uss);
		fprintf(json, "      \"pss\":%" PRIi64 ",\n", t_pss);
		fprintf(json, "      \"rss\":%" PRIi64 "\n", t_rss);
		fprintf(json, "    }\n");
	}

	return 0;
}

/*
 *  mem_dump_diff()
 *	dump differences between old and new events
 */
static int mem_dump_diff(
	FILE *json,
	mem_info_t *mem_info_old,
	mem_info_t *mem_info_new,
	const double duration)
{
	mem_info_t *m, **l;
	mem_info_t *sorted_deltas = NULL;
	int64_t	t_swap = 0, t_uss = 0, t_pss = 0, t_rss = 0;
	int64_t	t_d_swap = 0, t_d_uss = 0, t_d_pss = 0, t_d_rss = 0;
	char s_swap[12], s_uss[12], s_pss[12], s_rss[12];

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
		fprintf(json, "      {\n");
		fprintf(json, "        \"smem-per-process\":[\n");
	}

	if (!(opt_flags & OPT_QUIET))
		printf("  PID       Swap       USS       PSS       RSS User       Command\n");
	for (m = sorted_deltas; m; m = m->d_next) {
		const char *cmd = mem_cmdline(m);

		mem_to_str((double)m->d_swap / duration, s_swap, sizeof(s_swap));
		mem_to_str((double)m->d_uss / duration, s_uss, sizeof(s_uss));
		mem_to_str((double)m->d_pss / duration, s_pss, sizeof(s_pss));
		mem_to_str((double)m->d_rss / duration, s_rss, sizeof(s_rss));

		if (!(opt_flags & OPT_QUIET))
			printf(" %5d %9s %9s %9s %9s %-10.10s %s\n",
				m->pid, s_swap, s_uss, s_pss, s_rss, m->uname->name, cmd);

		if (json) {
			fprintf(json, "          {\n");
			fprintf(json, "            \"pid\":%d,\n", m->pid);
			fprintf(json, "            \"command\":\"%s\",\n", cmd);
			fprintf(json, "            \"user\":\"%s\",\n", m->uname->name);
			fprintf(json, "            \"swap\":%" PRIi64 ",\n", m->swap);
			fprintf(json, "            \"uss\":%" PRIi64 ",\n", m->uss);
			fprintf(json, "            \"pss\":%" PRIi64 ",\n", m->pss);
			fprintf(json, "            \"rss\":%" PRIi64 ",\n", m->rss);
			fprintf(json, "            \"swap-delta\":%" PRIi64 ",\n", m->d_swap);
			fprintf(json, "            \"uss-delta\":%" PRIi64 ",\n", m->d_uss);
			fprintf(json, "            \"pss-delta\":%" PRIi64 ",\n", m->d_pss);
			fprintf(json, "            \"rss-delta\":%" PRIi64 "\n", m->d_rss);
			fprintf(json, "          }%s\n",
				m->d_next ? "," : "");
		}
	}

	mem_to_str((double)t_d_swap / duration, s_swap, sizeof(s_swap));
	mem_to_str((double)t_d_uss / duration, s_uss, sizeof(s_uss));
	mem_to_str((double)t_d_pss / duration, s_pss, sizeof(s_pss));
	mem_to_str((double)t_d_rss / duration, s_rss, sizeof(s_rss));
	if (!(opt_flags & OPT_QUIET))
		printf("Total: %9s %9s %9s %9s\n\n", s_swap, s_uss, s_pss, s_rss);

	if (json) {
		fprintf(json, "        ],\n");
		fprintf(json, "        \"smem-total\":{\n");
		fprintf(json, "          \"swap\":%" PRIi64 ",\n", t_swap);
		fprintf(json, "          \"uss\":%" PRIi64 ",\n", t_uss);
		fprintf(json, "          \"pss\":%" PRIi64 ",\n", t_pss);
		fprintf(json, "          \"rss\":%" PRIi64 ",\n", t_rss);
		fprintf(json, "          \"swap-delta\":%" PRIi64 ",\n", t_d_swap);
		fprintf(json, "          \"uss-delta\":%" PRIi64 ",\n", t_d_uss);
		fprintf(json, "          \"pss-delta\":%" PRIi64 ",\n", t_d_pss);
		fprintf(json, "          \"rss-delta\":%" PRIi64 "\n", t_d_rss);
		fprintf(json, "        }\n");
		fprintf(json, "      }\n");
	}

	return 0;
}

/*
 *  handle_sigint()
 *      catch SIGINT and flag a stop
 */
static void handle_sigint(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	stop_smemstat = true;
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage: %s [options] [duration] [count]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -c\t\tget command name from processes comm field\n");
	printf("  -d\t\tstrip directory basename off command information\n");
	printf("  -g\t\treport memory in gigabytes\n");
	printf("  -h\t\tshow this help information\n");
	printf("  -k\t\treport memory in kilobytes\n");
	printf("  -l\t\tshow long (full) command information\n");
	printf("  -m\t\treport memory in megabytes\n");
	printf("  -o file\tdump data to json formatted file\n");
	printf("  -q\t\trun quietly, useful for -o output only\n");
	printf("  -s\t\tshow short command information\n");
}

int main(int argc, char **argv)
{
	mem_info_t *mem_info_old = NULL;
	mem_info_t *mem_info_new = NULL;

	char *json_filename = NULL;
	FILE *json_file = NULL;
	double duration_secs = 1.0;
	struct timeval tv1, tv2, duration, whence;
	bool forever = true;
	int count = 0;
	size_t npids;

	for (;;) {
		int c = getopt(argc, argv, "cdghklmo:qs");
		if (c == -1)
			break;
		switch (c) {
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
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 's':
			opt_flags |= OPT_CMD_SHORT;
			break;
		}
	}

	if (count_bits(opt_flags & OPT_CMD_ALL) > 1) {
		fprintf(stderr, "Cannot have -c, -l, -s at same time.\n");
		exit(EXIT_FAILURE);
	}
	if (count_bits(opt_flags & OPT_MEM_ALL) > 1) {
		fprintf(stderr, "Cannot have -k, -m, -g at same time.\n");
		exit(EXIT_FAILURE);
	}

	if (optind < argc) {
		duration_secs = atof(argv[optind++]);
		if (duration_secs < 1.0) {
			fprintf(stderr, "Duration must be 1.0 or more seconds.\n");
			exit(EXIT_FAILURE);
		}
		count = -1;
	}

	if (optind < argc) {
		forever = false;
		count = atoi(argv[optind++]);
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (json_filename) {
		if ((json_file = fopen(json_filename, "w")) == NULL) {
			fprintf(stderr, "Cannot open json output file '%s'.\n", json_filename);
			exit(EXIT_FAILURE);
		}
		fprintf(json_file, "{\n  \"" APP_NAME "\":{\n");
	}

	if (count == 0) {
		if (mem_get_all_pids(&mem_info_new, &npids) < 0)
			goto tidy;
		mem_dump(json_file, mem_info_new);
		mem_report_size();
		goto tidy;
	} else {
		/*
		 *  Pre-cache, this way we reduce
		 *  the amount of mem infos we alloc during
		 *  sampling
		 */
		if (mem_get_all_pids(&mem_info_old, &npids) < 0)
			goto free_cache;
		mem_cache_prealloc((npids * 5) / 4);

		duration.tv_sec = (time_t)duration_secs;
		duration.tv_usec = (suseconds_t)(duration_secs * 1000000.0) - (duration.tv_sec * 1000000);
		whence.tv_sec = 0;
		whence.tv_usec = 0;
		gettimeofday(&tv1, NULL);

		printf("Change in memory:\n");
		signal(SIGINT, &handle_sigint);

		if (json_file) {
			fprintf(json_file, "    \"periodic-samples\":[\n");
		}


		while (!stop_smemstat && (forever || count--)) {
			struct timeval tv;
			int ret;

			gettimeofday(&tv2, NULL);

			tv = timeval_add(&duration, &whence);
			tv = timeval_add(&tv, &tv1);
			tv2 = tv = timeval_sub(&tv, &tv2);

			/* Play catch-up, probably been asleep */
			if (tv.tv_sec < 0) {
				tv.tv_sec = 0;
				tv.tv_usec = 0;
				tv2 = tv;
			}

			ret = select(0, NULL, NULL, NULL, &tv2);
			if (ret < 0) {
				if (errno == EINTR) {
					duration = timeval_sub(&tv, &tv2);
					stop_smemstat = true;
				} else {
					fprintf(stderr, "Select failed: %s\n", strerror(errno));
					break;
				}
			}

			if (mem_get_all_pids(&mem_info_new, &npids) < 0)
				goto free_cache;
			mem_dump_diff(json_file, mem_info_old, mem_info_new, timeval_double(&duration));

			mem_cache_free_list(mem_info_old);
			mem_info_old = mem_info_new;
			mem_info_new = NULL;

			whence = timeval_add(&duration, &whence);
		}
		mem_report_size();

		if (json_file) {
			fprintf(json_file, "    ]\n");
		}

free_cache:
		mem_cache_free_list(mem_info_old);
	}

tidy:
	uname_cache_cleanup();
	proc_cache_cleanup();
	mem_cache_cleanup();

	if (json_file) {
		fprintf(json_file, "  }\n}\n");
		fclose(json_file);
	}

	exit(EXIT_SUCCESS);
}
