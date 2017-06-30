#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>

#include "hlist.h"
#include "mhash.h"

/* enable using signal to enable or disable memory logging */
#define SIGNAL_TRIGGER
#define SIGNAL_NO	40

/* enable memory logging */
static int enable_log;
/* print memory ops */
static int print_to_console;

/* protect hash list */
static pthread_mutex_t mc_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *(*callocp)(size_t, size_t);
static void *(*mallocp)(size_t);
static void *(*reallocp)(void *, size_t);
static void *(*memalignp)(size_t, size_t);
static int  (*posix_memalignp)(void **, size_t, size_t);
static void (*freep)(void *);

#define DEFAULT_LOG_FILE_NAME "/ramdisk/memcheck_log"
static char log_file_name[128];
static FILE *fp;

/* already initted */
static int initialized;

/* tls, in logging flag */
static __thread int in_hook;

/* calloc memory used in app startup */
#define STATIC_CALLOC_LEN	4096
static char static_calloc_buf[STATIC_CALLOC_LEN];
static size_t static_calloc_len;
static pthread_mutex_t static_calloc_mutex = PTHREAD_MUTEX_INITIALIZER;

/* hash size used for saving malloc log */
#define mc_HASH_BITS	20	/* 1 M entries */
#define mc_TABLE_SIZE	(1 << mc_HASH_BITS)
static struct cds_hlist_head mc_table[mc_TABLE_SIZE];

#define SAVE_CALLER_NUM 3
struct mc_entry {
	struct cds_hlist_node hlist;
	void *ptr;
	size_t alloc_size;
	void *callers[SAVE_CALLER_NUM];
	char *caller_symbol[SAVE_CALLER_NUM];
};

static struct mc_entry *get_mc(const void *ptr)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct mc_entry *e;
	uint32_t hash;

	hash = mhash((const char*)&ptr, sizeof(ptr));
	head = &mc_table[hash & (mc_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (ptr == e->ptr)
			return e;
	}
	return NULL;
}

static void add_mc(void *ptr, size_t alloc_size, void **caller, int size)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct mc_entry *e;
	uint32_t hash;
//	Dl_info info;

	if (!ptr)
		return;
	hash = mhash((const char*)&ptr, sizeof(ptr));
	head = &mc_table[hash & (mc_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (ptr == e->ptr) {
			fprintf(stderr, "[warning] add_mc pointer %010p is already there\n",
					ptr);
			//assert(0);	/* already there */
		}
	}
	e = malloc(sizeof(*e));
	e->ptr = ptr;
	e->alloc_size = alloc_size;
	memcpy(&e->callers[0], &caller[1], SAVE_CALLER_NUM * sizeof(void*));
#if 0
	for (int i = 0; i < SAVE_CALLER_NUM; i++) {
		if (!e->callers[i]) {
			e->caller_symbol = NULL;
			continue;
		}

		if (dladdr(e->caller[i], &info) && info.dli_sname) {
			e->caller_symbol[i] = strdup(info.dli_sname);
		} else {
			e->caller_symbol[i] = NULL;
		}
	}
#else
	e->caller_symbol[0] = NULL;
#endif
	cds_hlist_add_head(&e->hlist, head);
}

static void del_mc(void *ptr, void **caller)
{
	struct mc_entry *e;

	if (!ptr)
		return;
	e = get_mc(ptr);
	if (!e) {
		fprintf(stderr,
				"[warning] trying to free unallocated ptr %010p caller %010p --> %010p --> %010p\n",
				ptr, caller[3], caller[2], caller[1]);
		return;
	}
	cds_hlist_del(&e->hlist);
	for (int i = 0; i < SAVE_CALLER_NUM; i++) {
		if (!e->caller_symbol[i])
			break;
		free(e->caller_symbol);
	}
	free(e);
}

static void clear_mc()
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node, *n;
	struct mc_entry *e;
	for (int i = 0 ; i < mc_TABLE_SIZE; i++) {
		head = &mc_table[i & (mc_TABLE_SIZE - 1)];
		cds_hlist_for_each_entry_safe(e, node, n, head, hlist) {
			cds_hlist_del(&e->hlist);
			for (int j = 0; j < SAVE_CALLER_NUM; j++) {
				if (!e->caller_symbol[j])
					break;
				free(e->caller_symbol[j]);
			}
			free(e);
		}
	}
	return;
}

#ifdef SIGNAL_TRIGGER
void stop_mem_log();
void start_mem_log();

/* Signal handler */
static void sighandler(int signo, siginfo_t *siginfo, void *context)
{
	if (enable_log)
		stop_mem_log();
	else
		start_mem_log();
}
#endif

static void do_init(void)
{
	char *env;

	if (initialized)
		return;

	callocp = (void * ( *) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
	mallocp = (void * ( *) (size_t)) dlsym (RTLD_NEXT, "malloc");
	reallocp = (void * ( *) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
	memalignp = (void * ( *)(size_t, size_t)) dlsym (RTLD_NEXT, "memalign");
	posix_memalignp = (int ( *)(void **, size_t, size_t)) dlsym (RTLD_NEXT, "posix_memalign");
	freep = (void ( *) (void *)) dlsym (RTLD_NEXT, "free");

	env = getenv("MEMCHECK_START");
	if (env && strcmp(env, "1") == 0)
		enable_log = 1;

	env = getenv("MEMCHECK_PRINT");
	if (env && strcmp(env, "1") == 0)
		print_to_console = 1;

	env = getenv("MEMCHECK_FILE");
	if (!env)
		strncpy(log_file_name, DEFAULT_LOG_FILE_NAME, sizeof(log_file_name));
	else
		strncpy(log_file_name, env, sizeof(log_file_name));

	initialized = 1;
#ifdef SIGNAL_TRIGGER
	struct sigaction act;

	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO | SA_RESTART;

	in_hook = 1;
	sigemptyset(&act.sa_mask);
	sigaction(SIGNAL_NO, &act, NULL);
#endif

	pthread_mutex_lock(&mc_mutex);
	fp = fopen(log_file_name, "w");
	if (!fp)
		fp = stderr;
	pthread_mutex_unlock(&mc_mutex);

	in_hook = 0;
}

static void *static_calloc(size_t nmemb, size_t size)
{
	size_t prev_len;

	pthread_mutex_lock(&static_calloc_mutex);
	if (nmemb * size > sizeof(static_calloc_buf) - static_calloc_len) {
		pthread_mutex_unlock(&static_calloc_mutex);
		return NULL;
	}
	prev_len = static_calloc_len;
	static_calloc_len += nmemb * size;
	pthread_mutex_unlock(&static_calloc_mutex);
	return &static_calloc_buf[prev_len];
}

void * calloc(size_t nmemb, size_t size)
{
	void *result;
	void *caller[SAVE_CALLER_NUM + 1];

	if (callocp == NULL) {
		return static_calloc(nmemb, size);
	}

	do_init();

	if (!enable_log || in_hook) {
		return callocp(nmemb, size);
	}

	in_hook = 1;

	/* Call resursively */
	result = callocp(nmemb, size);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));

	pthread_mutex_lock(&mc_mutex);
	add_mc(result, nmemb * size, &caller[0], sizeof(caller)/sizeof(caller[0]));
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "%010p --> %010p --> %010p c+(%8zu,%8zu) %010p\n",
		caller[3], caller[2], caller[1], nmemb, size, result);

	in_hook = 0;

	return result;
}

void * malloc(size_t size)
{
	void *result;
	void *caller[SAVE_CALLER_NUM+1] = {NULL};

	do_init();

	if (!enable_log || in_hook) {
		return mallocp(size);
	}

	in_hook = 1;
	/* Call resursively */
	result = mallocp(size);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));

	pthread_mutex_lock(&mc_mutex);
	add_mc(result, size, caller, sizeof(caller)/sizeof(caller[0]));
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "%010p --> %010p --> %010p: m+(%8zu) %010p\n",
		caller[3], caller[2], caller[1], size, result);

	in_hook = 0;

	return result;
}

void *realloc(void *ptr, size_t size)
{
	void *result;
	void *caller[SAVE_CALLER_NUM+1] = {NULL};

	/*
	 * Return NULL if called on an address returned by
	 * static_calloc(). TODO: mimick realloc behavior instead.
	 */
	if ((char *) ptr >= static_calloc_buf &&
		(char *) ptr < static_calloc_buf + STATIC_CALLOC_LEN) {
		return NULL;
	}

	do_init();

	if (!enable_log || in_hook) {
		return reallocp(ptr, size);
	}

	in_hook = 1;

	/* Call resursively */
	result = reallocp(ptr, size);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));

	pthread_mutex_lock(&mc_mutex);
	if (size == 0 && ptr) {
		/* equivalent to free() */
		del_mc(ptr, caller);
	} else if (result) {
		del_mc(ptr, caller);
		add_mc(result, size, caller, sizeof(caller)/sizeof(caller[0]));
	}
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call malloc, so protect it too. */
	if (print_to_console) {
		fprintf(stderr, "%010p --> %010p --> %010p: r-%010p\n", caller[3], caller[2], caller[1], ptr);
		fprintf(stderr, "%010p --> %010p --> %010p: r+(%8zu) returns %010p\n", caller[3], caller[2], caller[1], size, result);
	}
	in_hook = 0;

	return result;
}

void *memalign(size_t alignment, size_t size)
{
	void *result;
	void *caller[SAVE_CALLER_NUM+1] = {NULL};

	do_init();

	if (!enable_log || in_hook) {
		return memalignp(alignment, size);
	}

	in_hook = 1;

	/* Call resursively */
	result = memalignp(alignment, size);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));

	pthread_mutex_lock(&mc_mutex);
	add_mc(result, size, caller, sizeof(caller)/sizeof(caller[0]));
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "%010p --> %010p --> %010p: ma+(%8zu,%8zu) %010p\n",
				caller[3], caller[2], caller[1], alignment, size, result);

	in_hook = 0;

	return result;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int result;
	void *caller[SAVE_CALLER_NUM+1] = {NULL};

	do_init();

	if (!enable_log || in_hook) {
		return posix_memalignp(memptr, alignment, size);
	}

	in_hook = 1;

	/* Call resursively */
	result = posix_memalignp(memptr, alignment, size);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));

	pthread_mutex_lock(&mc_mutex);
	add_mc(*memptr, size, caller, sizeof(caller)/sizeof(caller[0]));
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "%010p --> %010p --> %010p: pm+(%8zu,%8zu) returns %d\n",
				caller[3], caller[2], caller[1], alignment, size, result);

	in_hook = 0;

	return result;
}

void free(void *ptr)
{
	void *caller[SAVE_CALLER_NUM+1] = {NULL};

	/*
	 * Ensure that we skip memory allocated by static_calloc().
	 */
	if ((char *) ptr >= static_calloc_buf &&
		(char *) ptr < static_calloc_buf + STATIC_CALLOC_LEN) {
		return;
	}

	do_init();

	if (!enable_log || in_hook) {
		freep(ptr);
		return;
	}

	in_hook = 1;

	/* Call resursively */
	freep(ptr);

	backtrace(caller, sizeof(caller)/sizeof(caller[0]));
	pthread_mutex_lock(&mc_mutex);
	del_mc(ptr, caller);
	pthread_mutex_unlock(&mc_mutex);

	/* printf might call free, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "%010p --> %010p, f- %010p\n", caller[2], caller[1], ptr);

	in_hook = 0;
}

static void print_allocated(void)
{
	unsigned long i;

	for (i = 0; i < mc_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct cds_hlist_node *node;
		struct mc_entry *e;

		head = &mc_table[i];
		cds_hlist_for_each_entry(e, node, head, hlist) {
			fprintf(fp ? fp : stderr, "%010p(%8zu): %010p --> %010p --> %010p\n",
					e->ptr, e->alloc_size, e->callers[2], e->callers[1], e->callers[0]);
		}
	}

	fflush(fp);
}

void stop_mem_log()
{
	in_hook = 1;
	print_allocated();
	clear_mc();
	in_hook = 0;

	enable_log = 0;
}

void start_mem_log()
{
	if (enable_log)
		return;

#if 1
	in_hook = 1;
	clear_mc();
	in_hook = 0;
#else
	stop_mem_log();
#endif
	fprintf(fp ? fp : stderr, "---- new start---- \n");

	enable_log = 1;
}
