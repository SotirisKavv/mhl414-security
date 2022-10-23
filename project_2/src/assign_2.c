#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define BUFFSIZE 1024

/* function prototypes */
void print_hex(unsigned char *, size_t);
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
int gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
void uconcat(unsigned char *, unsigned char *, int, unsigned char *, int);

/*
 * Prints the hex value of the input
 * 16 values per line
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
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{

	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;

	cipher = (bit_mode==256)? EVP_get_cipherbyname("aes-256-ecb") : EVP_get_cipherbyname("aes-128-ecb");
	if (!cipher) {
		fprintf(stderr, "No such cipher!\n");
		return;
	}

	dgst = EVP_get_digestbyname("sha1");
	if (!dgst) {
		fprintf(stderr, "No such digest!\n");
		return;
	}

	if (!EVP_BytesToKey(cipher, dgst, NULL, password, strlen((const char*)password), 1, key, iv)) {
		fprintf(stderr, "EVP_BytesToKey failed!\n");
		return;
	}

	return;
}


/*
 * Encrypts the data
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	int len, ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "Context uninitialized!\n");
		return -1;
	}
	
	cipher = (bit_mode == 128) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
	if (!cipher) {
		fprintf(stderr, "No such cipher!\n");
		return -1;
	}

	if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
		fprintf(stderr, "Error in Encryption Init!\n");
		return -1;
	}

	if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		fprintf(stderr, "Error in Encryption Update!\n");
		return -1;
	}
	ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		fprintf(stderr, "Error in Encryption Finalization!\n");
		return -1;
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher;
	int len, plaintext_len;

	plaintext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "Context uninitialized!\n");
		return -1;
	}
	
	cipher = (bit_mode == 128) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
	if (!cipher) {
		fprintf(stderr, "No such cipher!\n");
		return -1;
	}

	if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
		fprintf(stderr, "Error in Decryption Init!\n");
		return -1;
	}

	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		fprintf(stderr, "Error in Decryption Update!\n");
		return -1;
	}
	plaintext_len = len;

	if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		fprintf(stderr, "Error in Decryption Finalization!\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
int
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
	CMAC_CTX * ctx;
	const EVP_CIPHER * cipher;
	size_t cmac_len;

	if (!(ctx = CMAC_CTX_new())) {
		fprintf(stderr, "CMAC Context uninitialized!\n");
		return -1;
	}
	
	cipher = (bit_mode == 128) ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
	if (!cipher) {
		fprintf(stderr, "No such cipher!\n");
		return -1;
	}

	if (!CMAC_Init(ctx, key, EVP_CIPHER_key_length(cipher), cipher, NULL)) {
		fprintf(stderr, "Error in CMAC Init!\n");
		return -1;
	}

	if (!CMAC_Update(ctx, data, data_len)) {
		fprintf(stderr, "Error in CMAC Update!\n");
		return -1;
	}

	if (!CMAC_Final(ctx, cmac, &cmac_len)) {
		fprintf(stderr, "Error in CMAC Finalization!\n");
		return -1;
	}
	
	CMAC_CTX_free(ctx);

	return (int) cmac_len;
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 1;

	for (int i = 0; i < 16; i++) {
		if (cmac1[i] != cmac2[i]) {
			verify = 0;
		}
	}
	return verify;
}

/*
 *	Concatenates two bytestreams
 */
void
uconcat(unsigned char * out, unsigned char * stream_1, int strlen_1, unsigned char * stream_2, int strlen_2) {
	
	memcpy(out, stream_1, strlen_1);
	memcpy(out+strlen_1, stream_2, strlen_2);

	return;
}


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	FILE * infile, * outfile;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned char cmac[16], cmac_ver[16];
	int in_len, out_len, cmac_len;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	in_len = 0;
	out_len = 0;
	cmac_len = 0;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);


	int cipher_block_sz = EVP_CIPHER_block_size(bit_mode == 128 ? EVP_aes_128_ecb() : EVP_aes_256_ecb());
	unsigned char in[BUFFSIZE], out[BUFFSIZE+ cipher_block_sz];

	infile = fopen(input_file, "rb");
	in_len = fread(in, sizeof(unsigned char), BUFFSIZE, infile);

	/* Initialize the library */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	/* Keygen from password */
	keygen(password, key, iv, bit_mode);

	/* Operate on the data according to the mode */
	switch (op_mode) {
		case 0:	/* encrypt */
			out_len = encrypt(in, in_len, key, iv, out, bit_mode);
			outfile = fopen(output_file, "wb");
			fwrite(out, sizeof(unsigned char), out_len, outfile);
			break;

		case 1: /* decrypt */
			out_len = decrypt(in, in_len, key, iv, out, bit_mode);
			outfile = fopen(output_file, "wb");
			fwrite(out, sizeof(unsigned char), out_len, outfile);
			break;

		case 2: /* sign */
			out_len = encrypt(in, in_len, key, iv, out, bit_mode);
			cmac_len = gen_cmac(in, in_len, key, cmac, bit_mode);

			unsigned char * buff = (unsigned char *)malloc((sizeof(unsigned char)*(out_len+cmac_len)));
			uconcat(buff, out, out_len, cmac, cmac_len);

			outfile = fopen(output_file, "wb");
			fwrite(buff, sizeof(unsigned char), out_len+cmac_len, outfile);
			break;

		case 3: /* verify */
			memcpy(cmac, in+in_len-16, 16);
			out_len = decrypt(in, in_len-16, key, iv, out, bit_mode);
			cmac_len = gen_cmac(out, out_len, key, cmac_ver, bit_mode);

			if (verify_cmac(cmac, cmac_ver)){
				outfile = fopen(output_file, "wb");
				fwrite(out, sizeof(unsigned char), out_len, outfile);
			}
			break;
		default:
			break;
	}

	/* Clean up */
	fclose(infile); fclose(outfile);
	free(input_file); free(output_file);
	free(password);

	/* END */
	return 0;
}
