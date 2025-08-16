#include <stdio.h>
#include <string.h>

void fvuln(char *in) {
	printf("INPUT LEN: %zu\n", strlen(in));
	for (int i=0; i<strlen(in); i++) {
		printf("%02x ", in[i]);
	}
	printf("\n");
}

int main() {
	char in[256];
	fgets(in, sizeof(in), stdin);
	fvuln(in);
	return 0;
}
