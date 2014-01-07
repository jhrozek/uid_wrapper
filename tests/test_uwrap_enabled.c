#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

int uwrap_enabled(void);

static void test_uwrap_enabled(void **state)
{
    int rc;

    (void)state; /* unused */

    rc = uwrap_enabled();
    assert_int_equal(rc, 1);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_enabled),
	};

	rc = run_tests(tests);

	return rc;
}
