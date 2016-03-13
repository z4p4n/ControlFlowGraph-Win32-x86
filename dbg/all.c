#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {

	int i;

	if (argc < 2) {

		fprintf (stdout, "Give number please\n");
		exit (EXIT_FAILURE);
	}
	char cmd[BUFSIZ];

	for (i = 0 ; i < strtol (argv[1], NULL, 10) ; i++) {

		snprintf (cmd, BUFSIZ, "dot dbg%d -Tpng -o dbg%d.png", i, i);
		system (cmd);
	}

	exit (EXIT_SUCCESS);

	return;
}
