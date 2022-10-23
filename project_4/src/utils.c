#include "utils.h"

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

/*
 * Reads text from a file
 *
 * arg0: path to input file
 */
char *
readFromFile(char * filename)
{
	char ch;
	FILE *rp;
	int ind = 0;

	unsigned int len_max = 128;
    unsigned int current_size = 0;

	rp = fopen(filename, "r");
	if (!rp) {handleErrors("File not Found!");}

	char * buffer = (char *)malloc(sizeof(char)*len_max);
    current_size = len_max;

	while((ch=fgetc(rp)) != EOF) {
		buffer[ind++] = ch;

		if (ind == current_size) {
			current_size = ind + len_max;
			buffer = realloc(buffer, current_size);
		}
	}
	buffer[ind] = '\0';
    fclose(rp);

	return buffer;
}

/*
 * Reads binary text from a file
 *
 * arg0: path to input file
 */
size_t *
readBinFromFile(char * filename)
{
	size_t byte;
	FILE *rp;
	int ind = 0;

	unsigned int len_max = 128;
    unsigned int current_size = 0;

	rp = fopen(filename, "rb");
	if (!rp) handleErrors("File not Found!");

	size_t * buffer = (size_t *)malloc(sizeof(size_t)*len_max);
    current_size = len_max;

	while(fread(&byte, sizeof(size_t), 1, rp) == 1) {
		buffer[ind++] = byte;

		if (ind == current_size) {
			current_size = ind + len_max;
			buffer = realloc(buffer, current_size);
		}
	}
	buffer[ind] = '\0';
    fclose(rp);

	return buffer;
}

/*
 * Writes text to a file
 *
 * arg0: path to output file
 * arg1: text to write
 * arg2: length of text to write
 */
 void
 writeToFile(char * buffer, char * filename, size_t length)
 {
	FILE *wp;

	wp = fopen(filename, "w");
	for (int i = 0 ; i < length ; i++) {
		fprintf(wp, "%c", buffer[i]);
	}

	fclose(wp);
 }

/*
 * Writes text to a file in hexadecimal form
 *
 * arg0: path to output file
 * arg1: text to write
 * arg2: length of text to write
 */
 void
 writeHexToFile(char * buffer, char * filename, size_t length)
 {
	FILE *wp;

	wp = fopen(filename, "w");
	for (int i = 0 ; i < length ; i++) {
		fprintf(wp, "%02X", buffer[i]);
	}

	fclose(wp);
 }

 /* 
 *	Handles possible errors
 *
 *	arg0: message to show 
 */
void 
handleErrors(char * msg)
{
	fprintf(stderr, "%s\n", msg);
    abort();
}
