#include <stdio.h>
#include <string.h>

void fvuln(char *in) {
	char buf[32];
	strcpy(buf, in);
	printf("you entered: %s\n", buf);
}

int main(int z, char *x[]) {
	if (z != 2) {
		printf("usage: %s <input>\n", x[0]);
		return 1;
	}
	fvuln(x[11]);
	return 0;
}
