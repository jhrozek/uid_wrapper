#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/types.h>
#include <unistd.h>

static void test_uwrap_seteuid(void **state)
{
	int rc;
	uid_t u;
	(void) state; /* unused */

	rc = seteuid(0);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 0);

	rc = seteuid(42);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 42);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_seteuid),
	};

	rc = run_tests(tests);

	return rc;
}
