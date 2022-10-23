#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include "simple_crypto.h"

//Helper Functions
char * scan( char * input ) {

    unsigned int len_max = 128;
    unsigned int current_size = 0;
    
    char * dest = malloc(len_max);
    current_size = len_max;

    printf("%s", input);

    if(dest != NULL) {
        int c = EOF;
        unsigned int i =0;

        while (( c = getchar() ) != '\n' && c != EOF) {
            dest[i++] = (char) c;

            if(i == current_size) {
                current_size = i+len_max;
                dest = realloc(dest, current_size);
            }
        }

        dest[i] = '\0';
    }

    return dest;
}

void safePrint( char * input ) {
    while(*input) {
        // if ((*input >= '0' && *input <= '9') || (*input >= 'a' && *input <= 'z') || (*input >= 'A' && *input <= 'Z'))
        if (isprint(*input))
            printf("%c", (char) *input);
        else
            printf("(x%02x)", (unsigned int) (unsigned char) *input);
        
        input++;
    }

}

char * filterInput( char * input ) {
    for (int i = 0, j; input[i] != '\0'; i++) {

      while (!(input[i] >= 'A' && input[i] <= 'Z') &&
             !(input[i] >= 'a' && input[i] <= 'z') &&
             !(input[i] >= '0' && input[i] <= '9') && !(input[i] == '\0')) {
         for (j = i; input[j] != '\0'; j++) {

            input[j] = input[j + 1];
         }
         input[j] = '\0';
      }
   }

   return input;
}

char * filterInputUppercase( char * input ) {
    for (int i = 0, j; input[i] != '\0'; i++) {

      while (!(input[i] >= 'A' && input[i] <= 'Z') && !(input[i] == '\0')) {
         for (j = i; input[j] != '\0'; j++) {

            input[j] = input[j + 1];
         }
         input[j] = '\0';
      }
   }

   return input;
}

void otpKeyGenerate( char * input ) {
    int fp;

    otpKey = (char *)malloc(sizeof(char)*strlen(input));

    fp = open("/dev/urandom", O_RDONLY);
    read(fp, otpKey, strlen(input));
}

char * vigenereKeySpread( char * key, int length ) {
    char * ret;

    if (length <= strlen(key)) {

        ret = malloc(sizeof(char) * length);
        memcpy(ret, key, length);

    } else {

        char * temp = malloc(sizeof(char) * length);
        ret = malloc(sizeof(char) * length);

        while (strlen(temp)<length) {
            strcat(temp, key);
        }
        memcpy(ret, temp, length);
    }

    return ret;
}

// One Time Pad
char * otpEncryption( char * input ) {
    otpKeyGenerate(input);
    char * kp = otpKey, * p = filterInput(input);

    while (*p!='\0'||*kp!='\0') {
        *p = (char)*p^*kp;
        
        p++; kp++;
    }

    return input;
}

char * otpDecryption( char * input ) {
    char * p = input;
    char * kp = otpKey;

    while(*p!='\0'||*kp!='\0') {
        *p ^= *kp;
        
        p++; kp++;
    }

    return input;
}

// Caesar Encryption
char * caesarEncryption( char * input, int key ) {
    char * p = filterInput(input);

    int shift = key % TOTAL_LET;
    int gap_1 = 'A' - '9' - 1;
    int gap_2 = 'a' - 'Z' - 1;

    while (*p!='\0') {
        if (*p >= '0' && *p <= '9') {
            if (*p+shift <= '9') {
                *p += shift;
            } else if (*p + (shift+gap_1) >= 'A' && *p + (shift+gap_1) <= 'Z') {
                *p += shift + gap_1;
            } else if (*p + (shift+gap_1+gap_2) >= 'a' && *p + (shift+gap_1+gap_2) <= 'z') {
                *p += shift + gap_1 + gap_2;
            } else if (*p + (shift+gap_1+gap_2) > 'z') {
                *p += (shift+gap_1+gap_2) - 'z' + '0' -1;
            }

        } else if (*p >= 'A' && *p <= 'Z') {
            if (*p+shift <= 'Z') {
                *p += shift;
            } else if (*p + (shift+gap_2) >= 'a' && *p + (shift+gap_2) <= 'z') {
                *p += shift + gap_2; 
            } else if (*p + (shift+gap_2) > 'z'){
                int reshift = *p + (shift+gap_2) - 'z' - 1;
                if ('0' + reshift <= '9' ) {
                    *p = '0' + reshift;
                } else if ('0' + (reshift+gap_1) >= 'A' && '0' + (reshift+gap_1) <= 'Z') {
                    *p = '0' + reshift + gap_1;
                }
            }

        } else if (*p >= 'a' && *p <= 'z') {
            if (*p+shift <= 'z') {
                 *p += shift;
            } else if (*p + shift > 'z'){
                int reshift = *p + shift - 'z' - 1;
                if ('0' + reshift <= '9' ) {
                    *p = '0' + reshift;
                } else if ('0' + (reshift+gap_1) >= 'A' && '0' + (reshift+gap_1) <= 'Z') {
                    *p = '0' + reshift + gap_1;
                } else if ('0' + (reshift+gap_1+gap_2) >= 'a' && '0' + (reshift+gap_1+gap_2) <= 'z' ) {
                    *p = '0' + reshift + (gap_1+gap_2);
                }
            }
        }
        p++;
    }

    return input;
}

char * caesarDecryption( char * input, int key ) {
    char * p = input;

    int shift = key % TOTAL_LET;
    int gap_1 = 'A' - '9' - 1;
    int gap_2 = 'a' - 'Z' - 1;

    while(*p!='\0') {
        if (*p >= '0' && *p <= '9') {
            if (*p-shift >= '0') {
                *p -= shift;
            } else if (*p-shift < '0') {
                int reshift = '0' - *p + shift - 1;
                if ('z' - reshift >= 'a') {
                    *p = 'z' - reshift;
                } else if ('z' - (reshift+gap_2) >= 'A' && 'z' - (reshift+gap_2) <= 'Z') {
                    *p = 'z' - (reshift+gap_2);
                } else if ('z' - (reshift+gap_1+gap_2) >= '0' && 'z' - (reshift+gap_1+gap_2) <= '9') {
                    *p = 'z' - (reshift+gap_2+gap_1);
                }
            }             
        } else if (*p >= 'A' && *p <= 'Z') {
            if (*p - shift >= 'A') {
                *p -= shift;
            } else if (*p - (shift+gap_1) >= '0' && *p - (shift+gap_1) <= '9') {
                *p -= shift + gap_1; 
            } else if (*p - (shift+gap_1) < '0'){
                int reshift = '0' - *p + (shift+gap_1) - 1;
                if ('z' - reshift >= 'a' ) {
                    *p = 'z' - reshift;
                } else if ('z' - (reshift+gap_2) >= 'A' && 'z' - (reshift+gap_2) <= 'Z') {
                    *p = 'z' - (reshift + gap_2);
                }
            }
        } else if (*p >= 'a' && *p <= 'z') {
            if (*p-shift >= 'a') {
                *p -= shift;
            } else if (*p - (shift+gap_2) >= 'A' && *p - (shift+gap_2) <= 'Z'){
                *p -= shift + gap_2;
            } else if (*p - (shift+gap_2+gap_1) >= '0' && *p - (shift+gap_2+gap_1) <= '9') {
                *p -= shift + gap_2 + gap_1;
            } else if (*p - (shift+gap_2+gap_1) < '0') {
                *p -= '0' + (shift+gap_2+gap_1) -'z' -1;
            }
        }
        p++;
    }

    return input;
}


// Vigenere Cipher
char * vigenereEncryption( char * input, char * key ) {
    char * p = filterInputUppercase(input);
    char * kp = filterInputUppercase(key);

    char * kps = vigenereKeySpread(kp, strlen(p));

    while (*p!='\0' || *kps!='\0') {
        int offset = *kps - 'A';
        if (*p + offset <= 'Z') {
            *p += offset;
        } else {
            *p = *p + offset - 'Z' + 'A' -1;
        }
        kps++; p++;
    }

    return input;
}

char * vigenereDecryption( char * input, char * key ) {
    char * p = input;
    char * kp = filterInputUppercase(key);
    

    char * kps = vigenereKeySpread(kp, strlen(p));

    while (*p!='\0' || *kps!='\0') {
        int offset = *kps - 'A';
        if (*p - offset >= 'A') {
            *p -= offset;
        } else {
            *p -= 'A' + offset - 'Z' -1;
        }
        kps++; p++;
    }

    return input;
}