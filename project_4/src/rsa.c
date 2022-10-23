#include "rsa.h"
#include "utils.h"
#include "math.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes;
	int arr[limit-1][2];
	int val = 2;

	for (int i = 0; i <= limit-1; i++) {
		arr[i][0]=val; arr[i][1]=1;
		val++;
	}

    for (int i = 2; i <= sqrt((double)limit)+2; i++) {
        if (arr[i-2][1]==1){
            for (int j = i*i; j <= limit; j+=i) {
                arr[j-2][1]=0;
            }
        }
    }

    primes = (size_t*)malloc(sizeof(size_t)*limit);
    int ind = 0;

    for (int i = 0; i < limit-1; i++) {
        if(arr[i][1]==1) {
            primes[ind]=arr[i][0];
            ind++;
        }
    }
    
    int size = 0;
    size_t *p = primes;

    while (*p!=0) {
        size++;
        p++;
    }

    *primes_sz = size;

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	while (b!=0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e = 0;
	int primes_sz;
	
	size_t * primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

	for (int i = 0; i < primes_sz; i++) {
		if ((primes[i] % fi_n != 0) && (gcd(primes[i], fi_n) == 1)) {
			e = primes[i];
			break;
		}
	}

	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
	size_t x;
    a = a % b; 
    for (x = 1; x < b; x++) {
		if ((a * x) % b == 1) 
            return x;
	}
	return 0;
}

/*
 *	Computation of large powers of a number
 *	
 *	arg0: base
 *	arg1: exponent
 *
 *	ret: base ^ exponent
 */
int
pow_mod(int base, int exp, int mod) 
{
	long long x = 1, y = base;

	while (exp > 0) {
		if (exp % 2 == 1)
			x = (x * y) % mod;
		y = (y * y) % mod;
		exp /= 2;
	}

	return x % mod;
}

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	int sieves_length;

	size_t *prime_pool = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &sieves_length);

	srand(time(NULL));
	p = prime_pool[rand()%sieves_length];
	q = prime_pool[rand()%sieves_length];

	n = p * q;
	fi_n = (p - 1) * (q - 1);
	e = choose_e(fi_n);
	d = mod_inverse(e, fi_n);

	size_t public[2] = { n, e };
	size_t private[2] = { n, d };

	FILE *wp;

	wp = fopen("../public.key", "wb");
	fwrite(public, sizeof(size_t), 2, wp);
	fclose(wp);

	wp = fopen("../private.key", "wb");
	fwrite(private, sizeof(size_t), 2, wp);
	fclose(wp);
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	FILE *rp, *wp;
	char * plaintext = NULL;
	size_t * ciphertext;
	size_t * keys = (size_t *)malloc(sizeof(size_t)*2);
    
	/* reading public key (n, e) */
	rp = fopen(key_file, "rb");
    if (!rp) handleErrors("Error opening file _key");

    fread(keys, sizeof(size_t), 2, rp);
	fclose(rp);

	/* reading plaintext to be encrypted */
	plaintext = readFromFile(input_file);

	/* encrypting the message */
	int ptxt_sz = strlen(plaintext);
	ciphertext = (size_t *)malloc(sizeof(size_t)*ptxt_sz);

	for ( int i = 0; i < ptxt_sz; i++) 
	{
		/* encryption function: c(m) = m^e mod n */
		ciphertext[i] = (size_t) pow_mod((int)plaintext[i], keys[1], keys[0]);
	}

	/* binary writing the encrypted text to the output file */
	wp = fopen(output_file, "wb");
    if (!wp) handleErrors("Error opening file _write");

    fwrite(ciphertext, sizeof(size_t), ptxt_sz, wp);
	fclose(wp);

}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	FILE *rp, *wp;
	size_t * ciphertext = NULL;
	char * plaintext;
	size_t * keys = (size_t *)malloc(sizeof(size_t)*2);
    
	/* reading private key (n, d) */
	rp = fopen(key_file, "rb");
    if (!rp) handleErrors("Error opening file _key");

    fread(keys, sizeof(size_t), 2, rp);
	fclose(rp);

	/* reading binary ciphertext to be decrypted */
	ciphertext = readBinFromFile(input_file);

	/* encrypting the message */
	int ctxt_sz = 0;
	size_t *p = ciphertext;

    while (*p!=0) {
        ctxt_sz++;
        p++;
    }
	plaintext = (char *)malloc(sizeof(char)*ctxt_sz);

	for ( int i = 0; i < ctxt_sz; i++) 
	{
		/* decryption function: m(c) = c^d mod n */
		plaintext[i] = (char) pow_mod((int)ciphertext[i], keys[1], keys[0]);
	}

	/* binary writing the decrypted text to the output file */
	wp = fopen(output_file, "w");
    if (!wp) handleErrors("Error opening file _write");

    fwrite(plaintext, sizeof(char), ctxt_sz, wp);
	fclose(wp);

}
