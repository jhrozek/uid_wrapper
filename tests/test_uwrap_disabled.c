#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct test_opts {
	int root_mode;
	uid_t myuid;
	gid_t mygid;
	uid_t nbuid;
	gid_t nbgid;
};

static void setup(void **state)
{
	struct test_opts *t;
	struct passwd *pwd;

	pwd = getpwnam("nobody");
	assert_non_null(pwd);

	t = malloc(sizeof(struct test_opts));
	assert_non_null(t);

	ZERO_STRUCTP(t);

	t->myuid = getuid();
	t->mygid = getgid();

	t->nbuid = pwd->pw_uid;
	t->nbgid = pwd->pw_gid;

	if (getuid() == (uid_t)0 || geteuid() == (uid_t)0) {
		t->root_mode = 1;
	}

	*state = t;
}

static void teardown(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;

	setuid(t->myuid);
	seteuid(t->myuid);
	setgid(t->mygid);
	setegid(t->mygid);

	free(t);
}

static void test_uwrap_setuid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	int rc;

	if (t->root_mode) {
		return;
	} else {
		rc = setuid(t->nbuid);
		assert_int_equal(rc, -1);
	}
}

static void test_uwrap_seteuid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = seteuid(t->nbuid);
		assert_int_equal(rc, 0);

		u = geteuid();
		assert_int_equal(u, t->nbuid);
	} else {
		rc = seteuid(t->nbuid);
		assert_int_equal(rc, -1);
	}
}

#ifdef HAVE_SETREUID
static void test_uwrap_setreuid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = setreuid(-1, t->nbuid);
		assert_int_equal(rc, 0);

		u = geteuid();
		assert_int_equal(u, t->nbuid);
	} else {
		rc = setreuid(-1, t->nbuid);
		assert_int_equal(rc, -1);
	}
}
#endif

#ifdef HAVE_SETRESUID
static void test_uwrap_setresuid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = setresuid(-1, t->nbuid, -1);
		assert_int_equal(rc, 0);

		u = geteuid();
		assert_int_equal(u, t->nbuid);
	} else {
		rc = setresuid(-1, t->nbuid, -1);
		assert_int_equal(rc, -1);
	}
}
#endif

static void test_uwrap_setgid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	int rc;

	if (t->root_mode) {
		return;
	} else {
		rc = setgid(t->nbgid);
		assert_int_equal(rc, -1);
	}
}

static void test_uwrap_setegid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = setegid(t->nbgid);
		assert_int_equal(rc, 0);

		u = getegid();
		assert_int_equal(u, t->nbgid);
	} else {
		rc = setegid(t->nbgid);
		assert_int_equal(rc, -1);
	}
}

#ifdef HAVE_SETREGID
static void test_uwrap_setregid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = setregid(-1, t->nbgid);
		assert_int_equal(rc, 0);

		u = getegid();
		assert_int_equal(u, t->nbgid);
	} else {
		rc = setregid(-1, t->nbgid);
		assert_int_equal(rc, -1);
	}
}
#endif

#ifdef HAVE_SETRESGID
static void test_uwrap_setresgid(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	uid_t u;
	int rc;

	if (t->root_mode) {
		rc = setresgid(-1, t->nbgid, -1);
		assert_int_equal(rc, 0);

		u = getegid();
		assert_int_equal(u, t->nbgid);
	} else {
		rc = setresgid(-1, t->nbgid, -1);
		assert_int_equal(rc, -1);
	}
}
#endif

static void test_uwrap_setgroups(void **state)
{
	struct test_opts *t = (struct test_opts *)*state;
	gid_t glist[1];
	gid_t rlist[16];
	int rc;

	glist[0] = t->nbgid;

	(void) state; /* unused */

	if (t->root_mode) {
		rc = setgroups(ARRAY_SIZE(glist), glist);
		assert_int_equal(rc, 0);

		rc = getgroups(ARRAY_SIZE(rlist), rlist);
		assert_int_equal(rc, 1);

		assert_memory_equal(glist, rlist, sizeof(glist));
	} else {
		rc = setgroups(ARRAY_SIZE(glist), glist);
		assert_int_equal(rc, -1);

		rc = getgroups(ARRAY_SIZE(rlist), rlist);
		assert_int_not_equal(rc, -1);
	}
}

int main(void)
{
	int rc;

	const UnitTest tests[] = {
		unit_test_setup_teardown(test_uwrap_setuid, setup, teardown),
		unit_test_setup_teardown(test_uwrap_seteuid, setup, teardown),
#ifdef HAVE_SETREUID
		unit_test_setup_teardown(test_uwrap_setreuid, setup, teardown),
#endif
#ifdef HAVE_SETRESUID
		unit_test_setup_teardown(test_uwrap_setresuid, setup, teardown),
#endif
		unit_test_setup_teardown(test_uwrap_setgid, setup, teardown),
		unit_test_setup_teardown(test_uwrap_setegid, setup, teardown),
#ifdef HAVE_SETREGID
		unit_test_setup_teardown(test_uwrap_setregid, setup, teardown),
#endif
#ifdef HAVE_SETRESGID
		unit_test_setup_teardown(test_uwrap_setresgid, setup, teardown),
#endif
		unit_test_setup_teardown(test_uwrap_setgroups, setup, teardown),
	};

	rc = run_tests(tests);

	return rc;
}
