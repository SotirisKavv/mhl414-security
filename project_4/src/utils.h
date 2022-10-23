#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>


/*
 * Prints the hex value of the input, 16 values per line
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *, size_t);


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *, size_t);


/*
 * Prints the usage message
 */
void
usage(void);


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *, char *, char *, int);

/*
 * Reads text from a file
 *
 * arg0: path to input file
 */
char * readFromFile(char *);

/*
 * Reads binary text from a file
 *
 * arg0: path to input file
 */
size_t *
readBinFromFile(char *);

/*
 * Writes text to a file
 *
 * arg0: path to output file
 * arg1: text to write
 * arg2: length of text to write
 */
void writeHexToFile(char *, char *, size_t);

/*
 * Writes text to a file in hexadecimal form
 *
 * arg0: path to output file
 * arg1: text to write
 * arg2: length of text to write
 */
void writeHexToFile(char *, char *, size_t);

/* 
 *	Handles possible errors 
 *
 *  arg0: message to show
 */
void 
handleErrors(char * );

#endif /* _UTILS_H */
