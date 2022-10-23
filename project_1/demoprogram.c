#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simple_crypto.h"

int main() {
    int caesarKey;
    char * vigenereKey;
    char * otpInput, * caesarInput, * vigenereInput;
    char * otpEncrypted, * caesarEncrypted, * vigenereEncrypted;
    char * otpDecrypted, * caesarDecrypted, * vigenereDecrypted; 

    printf("[OTP] input: ");
    otpInput = scan("");

    otpEncrypted = otpEncryption(otpInput);
    printf("[OTP] encrypted: ");
    safePrint(otpEncrypted);
    printf("\n");

    otpDecrypted = otpDecryption(otpEncrypted);
    printf("[OTP] decrypted: ");
    safePrint(otpDecrypted);
    printf("\n");

    printf("[Caesars] input: ");
    caesarInput = scan("");
    printf("[Caesars] key: ");
    scanf("%d", &caesarKey);
    getchar();

    caesarEncrypted = caesarEncryption(caesarInput, caesarKey);
    printf("[Caesars] encrypted: ");
    safePrint(caesarEncrypted);
    printf("\n");

    caesarDecrypted = caesarDecryption(caesarEncrypted, caesarKey);
    printf("[Caesars] decrypted: ");
    safePrint(caesarDecrypted);
    printf("\n");

    printf("[Vigenere] input: ");
    vigenereInput = scan("");
    printf("[Vigenere] key: ");
    vigenereKey = scan("");

    vigenereEncrypted = vigenereEncryption(vigenereInput, vigenereKey);
    printf("[Vigenere] encrypted: %s\n", vigenereEncrypted);

    vigenereDecrypted = vigenereDecryption(vigenereEncrypted, vigenereKey);
    printf("[Vigenere] decrypted: %s\n", vigenereDecrypted);

    return 0;
}