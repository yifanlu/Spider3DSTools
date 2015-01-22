#include <stdio.h>

int main(int argc, const char *argv[])
{
	FILE *file;
	unsigned int state;
	unsigned short data;

	if ((file = fopen(argv[1], "rb")) == NULL)
	{
		perror("fopen");
		return 1;
	}

	while (fread(&data, 2, 1, file) == 1)
	{
		fprintf(stdout, "\\u%04x", data);
	}
	fclose(file);
	return 0;
}
