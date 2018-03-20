#ifdef HAS_MLOG_FEATURE

#include "smd_lite.h"
#include "rcinit.h"
#include "task.h"
#include "rex.h"
#include "list.h"

#define MLOG_EVENT_READ		(1<<0)
#define MLOG_EVENT_WRITE		(1<<1)

#define SMD_BUFFER_SIZE SMD_MIN_FIFO
#define EARLY_BUFFER_SIZE SMD_BUFFER_SIZE

#if 1
#define mutex_t rex_crit_sect_type
#define mutex_init(lock) rex_init_crit_sect(lock)
#define mutex_trylock(lock) rex_try_enter_crit_sect(lock)
#define mutex_lock(lock) rex_enter_crit_sect(lock)
#define mutex_unlock(lock) rex_leave_crit_sect(lock)
#else
#define mutex_t pthread_mutex_t
#define mutex_init(lock) pthread_mutex_init(lock, NULL)
#define mutex_trylock(lock) pthread_mutex_trylock(lock)
#define mutex_lock(lock) pthread_mutex_lock(lock)
#define mutex_unlock(lock) pthread_mutex_unlock(lock)
#endif

typedef struct {
	char *buf;
	int len;
	struct list_head node;
	void *reserved[0];
} record_t;

typedef struct mem_pool {
	void *addr;
	int max_nr;
	int curr_nr;
	int unit;
} mem_pool_t;

typedef struct {
	smdl_handle_type handle;
	rex_tcb_type *tcb;
	mutex_t lock;
	struct list_head list;
	mem_pool_t pool;
	int opened;
	int inited;
	char early_buffer[EARLY_BUFFER_SIZE];
	int early_buffer_offset;
} mlog_t;

static mlog_t g_mlog = {
	.list = LIST_HEAD_INIT(g_mlog.list),
	.inited = 0,
	.early_buffer_offset = 0,
};

static int init_pool(mem_pool_t *pool, int max_nr)
{
	void *addr;
	int i;

	pool->max_nr = max_nr;
	pool->unit = sizeof(record_t) + SMD_BUFFER_SIZE;

	addr = malloc(pool->unit * pool->max_nr);
	if (!addr)
		return -1;

	pool->addr = addr;
	pool->curr_nr = 0;

	for (i = 0; i < pool->max_nr; i++) {
		record_t *tmp = (record_t *)((char*)pool->addr + i * pool->unit);
		INIT_LIST_HEAD(&tmp->node);
	}

	return 0;
}

static record_t *grab_next_record(mem_pool_t *pool)
{
	record_t *new;

	if (!pool->addr)
		return NULL;

	new = (record_t *)((char*)pool->addr + pool->unit * pool->curr_nr);
	pool->curr_nr = (pool->curr_nr + 1) % pool->max_nr;

	list_del(&new->node);
	INIT_LIST_HEAD(&new->node);

	new->buf = (char *)(new->reserved);
	new->len = pool->unit - sizeof(record_t);

	return new;
}

/* for test */
int mlog_test(const char *fmt, ...)
{
	mlog_t *log = &g_mlog;
	char buf[SMD_BUFFER_SIZE];
	va_list args;

	if (!log->opened)
		return -1;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	return smdl_write(log->handle, strlen(buf) + 1, buf, SMDL_WRITE_FLAGS_NONE);
}

int mlog(const char *fmt, ...)
{
	mlog_t *log = &g_mlog;
	record_t *record;
	char *buf;
	int len, ret = -1;
	va_list args;

	if (log->inited) {
		mutex_lock(&log->lock);

		record = grab_next_record(&log->pool);

		va_start(args, fmt);
		ret = vsnprintf(record->buf, record->len, fmt, args);
		va_end(args);

		record->len = strlen(record->buf) + 1;

		list_add_tail(&record->node, &log->list);

		mutex_unlock(&log->lock);

		if (log->opened)
			rex_set_sigs(log->tcb, MLOG_EVENT_WRITE);

	} else {
		len = EARLY_BUFFER_SIZE - log->early_buffer_offset;
		if (len > 0) {
			buf = log->early_buffer + log->early_buffer_offset;
			va_start(args, fmt);
			ret = vsnprintf(buf, len, fmt, args);
			log->early_buffer_offset += strlen(buf);
			va_end(args);
		}
	}

	return ret;
}

static void mlog_event_notify(
		smdl_handle_type handle, smdl_event_type event, void *d)
{
	mlog_t *log = (mlog_t *)d;

	switch(event) {
	case SMDL_EVENT_OPEN:
		log->opened = 1;
		if (!list_empty(&log->list))
			rex_set_sigs(log->tcb, MLOG_EVENT_WRITE);
		break;
	case SMDL_EVENT_READ:
		rex_set_sigs(log->tcb, MLOG_EVENT_READ);
		break;
	case SMDL_EVENT_WRITE:
		if (!list_empty(&log->list))
			rex_set_sigs(log->tcb, MLOG_EVENT_WRITE);
		break;
	case SMDL_EVENT_REMOTE_CLOSE:
	case SMDL_EVENT_CLOSE:
		log->opened = 0;
		break;
	default:
		break;
	}
}

static int mlog_init(mlog_t *log)
{
	if (init_pool(&log->pool, 100) < 0)
		return -1;

	mutex_init(&log->lock);
	log->tcb = rex_self();

	log->handle = smdl_open(
			"mlog",
			SMD_APPS_MODEM,
			SMDL_OPEN_FLAGS_PRIORITY_DEFAULT|SMDL_OPEN_FLAGS_MODE_PACKET,
			SMD_BUFFER_SIZE,
			mlog_event_notify,
			log);
	if (!log->handle)
		return -1;

	log->inited = 1;

	/* add early buffer to list */
	if (log->early_buffer_offset > 0) {
		mutex_lock(&log->lock);
		record_t *record = grab_next_record(&log->pool);
		strncpy(record->buf, log->early_buffer, record->len);
		record->len = strlen(record->buf) + 1;
		list_add(&record->node, &log->list);
		mutex_unlock(&log->lock);
		log->early_buffer_offset = 0;
	}

	return 0;
}

static void mlog_event_read(mlog_t *log)
{
	int avail, ret;
	char *buf;

	while ((avail = smdl_rx_peek(log->handle)) > 0) {
		buf = malloc(avail);
		if (!buf)
			break;

		ret = smdl_read(log->handle, avail, buf, SMDL_READ_FLAGS_NONE);

		/* loopback to AP */
		if (ret > 0)
			mlog("%s", buf);

		free(buf);

		if (ret <= 0)
			break;
	}
}

static void mlog_event_write(mlog_t *log)
{
	record_t *record, *next;
	int ret;


	mutex_lock(&log->lock);

	list_for_each_entry_safe(record, next, &log->list, node) {
		ret = smdl_write(log->handle, record->len, record->buf, SMDL_WRITE_FLAGS_NONE);
		if (ret <= 0)
			break;
		list_del(&record->node);
		INIT_LIST_HEAD(&record->node);
	}

	mutex_unlock(&log->lock);
}

static void *mlog_loop(mlog_t *log)
{
	rex_sigs_type events;

	do {
		events = rex_wait(MLOG_EVENT_READ|MLOG_EVENT_WRITE|TASK_STOP_SIG);

		if (events & MLOG_EVENT_READ) {
			rex_clr_sigs(log->tcb, MLOG_EVENT_READ);
			mlog_event_read(log);
		}

		if (events & MLOG_EVENT_WRITE) {
			rex_clr_sigs(log->tcb, MLOG_EVENT_WRITE);
			mlog_event_write(log);
		}

	} while (1);
}

void mlog_task(dword unused)
{
	mlog_t *log = &g_mlog;

	mlog("mlog task start.\n");

	mlog_init(log);

	rcinit_handshake_startup();

	mlog_loop(log);
}

#else

int mlog(const char *fmt, ...) { return 0; }

#endif
