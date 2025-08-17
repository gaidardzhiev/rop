#include <stdio.h>
#include <string.h>

void y(char *s) {
	char buffer[12];
	strcpy(buffer, s);
}

int main(int z, char *x[]) {
	if(z > 1) {
		y(x[1]);
		printf("Hello, World!\n");
	}
}
