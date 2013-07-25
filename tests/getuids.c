#include <stdio.h>
#include <unistd.h>

int main(void) {
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;
	int rc;

	rc = getresuid(&ruid, &euid, &suid);
	printf("getresuid(%d): ruid=%d, euid=%d, suid=%d\n",
	       rc, (int)ruid, (int)euid, (int)suid);

	rc = getresgid(&rgid, &egid, &sgid);
	printf("getresgid(%d): rgid=%d, egid=%d, sgid=%d\n",
	       rc, (int)rgid, (int)egid, (int)sgid);

	return 0;
}
