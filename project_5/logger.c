#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <openssl/md5.h>
 
int w_flag = 0;

char *
str2md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = calloc(33,sizeof(char));

	/* MD5 file hash value */
    MD5_Init(&c);

    while (length > 0) {
        if (length > 128) {
            MD5_Update(&c, str, 128);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 128;
        str += 128;
    }

    MD5_Final(digest, &c);

	/* Turn bits into Hex-Form */
    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}


FILE *
fopen(const char *path, const char *mode) 
{
	//access type - 0 if created, 1 if exists;
	int access_type;
	if (mode[0]==(char)'r'){
		access_type = 1;
	} else {
		access_type = (!access(realpath(path, NULL), F_OK))?1:0;
	}

	int ret;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* Get Sys info */
	//date & time
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char date[36];
	char timestamp[14];
	sprintf(date, "%02d/%02d/%04u", tm->tm_mday, tm->tm_mon+1, tm->tm_year+1900);
	sprintf(timestamp, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);

	//is action denied
	int isActionDenied = (access(realpath(path, NULL), R_OK | W_OK)==0)?0:1;

	//fingerprint
	/* Read from file */
	char * file_cnt, * fingerprint;

	if (isActionDenied) {
		fingerprint = "0";
	} else {
		if (mode[1]=='+' || mode[0]=='r') {
			file_cnt = calloc(256, sizeof(char));

			fseek(original_fopen_ret, 0, SEEK_SET);
			while ((ret = fread(file_cnt, sizeof(char), 128, original_fopen_ret))>0)	//read
				file_cnt[ret] = 0x00;

			fingerprint = str2md5(file_cnt, strlen(file_cnt));
		} else {
			fingerprint = "0";
		}
	}

	/* Gather infos into string */
	char * log = malloc(256);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", 
		getuid(), realpath(path, NULL), date, timestamp, access_type, isActionDenied, fingerprint);

	/* Write them to logging file using File Descriptors */
	int fd = open("file_logging.log", O_RDWR | O_CREAT | O_APPEND, 0666);	//open so that you can create and append
	write(fd, log, strlen(log));	//write
	close(fd);	//close file

	if (mode[0]=='w' && mode[1]!='+') w_flag = 1;
	else w_flag = 0;

	return original_fopen_ret;
}

FILE *
fopen64(const char *path, const char *mode) 
{	
	return fopen(path, mode);
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);



	/* call the original fwrite function */
	int ret;
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* log in logging file */
	//find filename
	int fdw = fileno(stream);
	char fd_path[PATH_MAX], *filename; 
	sprintf(fd_path, "/proc/self/fd/%d", fdw);
	filename = malloc(PATH_MAX);
	int n = readlink(fd_path, filename, PATH_MAX);
	if (n < 0)
		abort();
	filename[n] = '\0';

	//is action denied
	int isActionDenied = (access(filename, W_OK)==0)?0:1;

	//get sate & time
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char date[36];
	char timestamp[14];
	sprintf(date, "%02d/%02d/%04d", tm->tm_mday, tm->tm_mon+1, tm->tm_year+1900);
	sprintf(timestamp, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);

	//access type - 2 if write;
	int access_type = 2;

	//fingerprint
	char * fingerprint, * file_cnt;
		
	file_cnt = calloc(256, sizeof(char));

	fseek(stream, 0, SEEK_SET);
	while ((ret = fread(file_cnt, sizeof(char), 128, stream))>0)	//read
		file_cnt[ret] = 0x00;

	if (w_flag) {
		strcat(file_cnt, ptr);
	}

	fingerprint = str2md5(file_cnt, strlen(file_cnt));


	char * log = malloc(256);
	sprintf(log, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n", 
		getuid(), filename, date, timestamp, access_type, isActionDenied, fingerprint);
	free(fingerprint);

	int fd = open("file_logging.log", O_RDWR | O_CREAT | O_APPEND, 0666);
	write(fd, log, strlen(log));
	close(fd);

	return original_fwrite_ret;
}


