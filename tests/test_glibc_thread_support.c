#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <pthread.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif

#define NUM_THREADS 3

struct parm {
	int id;
	int ready;
};

pthread_mutex_t msg_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *syscall_setreuid(void *arg)
{
	long int rc;
	uid_t u;

	(void) arg; /* unused */

	rc = syscall(SYS_setreuid, -1, 0);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 0);

	return NULL;
}

static void test_syscall_setreuid(void **state)
{
	pthread_attr_t pthread_custom_attr;
	pthread_t *threads;
	int i;

	(void) state; /* unused */

	threads = (pthread_t*)malloc(NUM_THREADS * sizeof(pthread_t));
	assert_non_null(threads);

	pthread_attr_init(&pthread_custom_attr);

	for (i = 0; i < NUM_THREADS; i++) {
		pthread_create(&threads[i],
			       &pthread_custom_attr,
			       syscall_setreuid,
			       NULL);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}
}

static void *sync_setreuid(void *arg)
{
	struct parm *p = (struct parm *)arg;
	uid_t u;

	syscall_setreuid(arg);

	p->ready = 1;

	pthread_mutex_lock(&msg_mutex);

	u = geteuid();
	assert_int_equal(u, 42);

	pthread_mutex_unlock(&msg_mutex);

	return NULL;
}

static void test_sync_setreuid(void **state)
{
	pthread_attr_t pthread_custom_attr;
	pthread_t *threads;
	struct parm *p;
	int rc;
	int i;

	(void) state; /* unused */

	threads = (pthread_t*)malloc(NUM_THREADS * sizeof(pthread_t));
	assert_non_null(threads);
	pthread_attr_init(&pthread_custom_attr);

	p = malloc(NUM_THREADS * sizeof(struct parm));
	assert_non_null(p);

	pthread_mutex_lock(&msg_mutex);

	for (i = 0; i < NUM_THREADS; i++) {
		p[i].id = i;
		p[i].ready = 0;

		pthread_create(&threads[i],
			       &pthread_custom_attr,
			       sync_setreuid,
			       (void *)&p[i]);
	}

	/* wait for the reads to set euid to 0 */
	for (i = 0; i < NUM_THREADS; i++) {
		while (p[i].ready != 1) {
			sleep(1);
		}
	}

	rc = setreuid(-1, 42);
	assert_int_equal(rc, 0);

	pthread_mutex_unlock(&msg_mutex);

	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_syscall_setreuid),
		unit_test(test_sync_setreuid),
	};

	rc = run_tests(tests);

	return rc;
}
