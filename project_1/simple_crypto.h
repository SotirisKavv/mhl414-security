#ifndef SIMPLE_CRYPTO_h
#define SIMPLE_CRYPTO_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//Useful constants
#define NUMBERS 10
#define UPPERCASE 26
#define LOWERCASE 26

#define TOTAL_LET 62

static char * otpKey;

/*HELPER FUNCTIONS*/
char * scan(char * input );
void safePrint( char * input );
void otpKeyGenerate( char * input );
char * clearInputUppercase( char * input );
char * vigenereKeySpread( char * input, int length );

//One Time Pad
char * otpEncryption( char * input );
char * otpDecryption( char * input );

//Caesar's Cipher
char * caesarEncryption( char * input, int key );
char * caesarDecryption( char * input, int key );

// Vigenere Cipher
char * vigenereEncryption( char * input, char * key );
char * vigenereDecryption( char * input, char * key );

#endif