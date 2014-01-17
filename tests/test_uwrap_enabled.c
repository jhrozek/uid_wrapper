#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

int uid_wrapper_enabled(void);

static void test_uid_wrapper_enabled(void **state)
{
    int rc;

    (void)state; /* unused */

    rc = uid_wrapper_enabled();
    assert_int_equal(rc, 1);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uid_wrapper_enabled),
	};

	rc = run_tests(tests);

	return rc;
}
