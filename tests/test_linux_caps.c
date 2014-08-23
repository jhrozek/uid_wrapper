#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif

#include <sys/capability.h>

static void test_capget(void **state)
{
	int rc;
	int err;
	struct __user_cap_header_struct chdr;
	struct __user_cap_data_struct caps;

	(void) state; /* unused */

	/* datap may be NULL, in this case, only capability
	 * version is returned
	 */
	memset(&chdr, 0, sizeof(struct __user_cap_header_struct));
	rc = capget(&chdr, NULL);
	printf("version = %d pid = %d\n", chdr.version, chdr.pid);
	assert_int_equal(rc, 0);

	/* Root has all caps */
	rc = capget(&chdr, &caps);
	err = errno;
	printf("errno = %d err = %s\n", err, strerror(err));
	assert_int_equal(rc, 0);
	assert_int_equal(caps.effective, 0xFFFFFFFF);
}

int main(void)
{
	int rc;

	const UnitTest tests[] = {
		unit_test(test_capget),
	};

	rc = run_tests(tests);

	return rc;
}
