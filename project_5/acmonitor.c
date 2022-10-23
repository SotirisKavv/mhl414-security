#define _XOPEN_SOURCE 600

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
 
#define LINE_SZ 2048

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char* date; /* file access date */
	char* time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

};

struct entry **
unmarshal_users(FILE *log)
{
	struct entry **logs;
	char buffer[LINE_SZ], *fcnt, *ptr;
	int i = 0, curr_logs, max_logs = 2048;


	if (!log) return NULL;

	logs = (struct entry **)malloc(sizeof(struct entry *)*max_logs);
	curr_logs = max_logs;

	while ((fcnt = fgets(buffer, sizeof(buffer), log)) != NULL)
	{
		logs[i] = (struct entry *)malloc(sizeof(struct entry));

		ptr = strtok(buffer, "\t");
		logs[i]->uid = atoi(ptr);

		ptr = strtok(NULL, "\t");
		logs[i]->file = (char *)malloc(sizeof(char)*strlen(ptr));
		strcpy(logs[i]->file, ptr);

		ptr = strtok(NULL, "\t");
		logs[i]->date = (char *)malloc(sizeof(char)*strlen(ptr));
		strcpy(logs[i]->date, ptr);

		ptr = strtok(NULL, "\t");
		logs[i]->time = (char *)malloc(sizeof(char)*strlen(ptr));
		strcpy(logs[i]->time, ptr);

		ptr = strtok(NULL, "\t");
		logs[i]->access_type = atoi(ptr);

		ptr = strtok(NULL, "\t");
		logs[i]->action_denied = atoi(ptr);

		ptr = strtok(NULL, "\n");
		logs[i]->fingerprint = (char *)malloc(sizeof(char)*strlen(ptr));
		strcpy(logs[i]->fingerprint, ptr);

		i++;

		if (i==curr_logs) {
			curr_logs += max_logs;
			logs = realloc(logs, curr_logs);
		}
			
	}
	logs[i] = NULL;

	return logs;

}

int
searchInt(int *arr, int val, int length)
{
	if (!arr)
		return 0;
	
	for (int i = 0; i < length; i++) {
		if (arr[i] == val)
			return 1;
	}

	return 0;
}

int
searchFile(char **arr, char* val, int length)
{
	if (!arr)
		return 0;
	
	for (int i = 0; i < length; i++) {
		if (strcmp(arr[i], val) == 0)
			return 1;
	}

	return 0;
}


int *
uniqueUIDs(struct entry **logs, int *length)
{
	int *uids = NULL;

	*length = 0;

	while (*logs != NULL)
	{
		if (!searchInt(uids, (*logs)->uid, *length)) {
			uids = realloc(uids, ++(*length));
			uids[*length-1] = (*logs)->uid;
		}

		logs++;
	}

	return uids;
}

char * 
findFisrtFingerprint(struct entry **logs, int uid, char * filename)
{
	while (*logs) 
	{
		if ((*logs)->uid == uid && strcmp((*logs)->file, realpath(filename, NULL)) == 0 && !((*logs)->action_denied))
			return (*logs)->fingerprint;

		logs++;
	}

	return NULL;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-v <num of files>, Prints the total number of files"
		   "created in the last 20 minutes\n"
		   "-e, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	struct entry **logs = unmarshal_users(log), **p;
	int * uids, uids_l, files_l;
	char **files = NULL;
	
	uids = uniqueUIDs(logs, &uids_l);

	for (int i = 0; i < uids_l; i++)
	{
		files_l = 0; files = (char **)calloc(sizeof(char *), 7);
		p = logs;

		while (*p)
		{
			if ((*p)->uid == uids[i] && (*p)->action_denied) 
			{
				if (!searchFile(files, (*p)->file, files_l)) {
					files_l++;
					files[files_l-1] = (char*)malloc(sizeof(char)*strlen((*p)->file));
					strcpy(files[files_l-1], (*p)->file);
				}
			}

			if (files_l >= 7) 
			{
				printf("%d\n", uids[i]);
				break;
			}

			p++;
		}
	}

	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	struct entry **logs = unmarshal_users(log), **p;
	int *uids, length, mods;
	char *last_fngp;

	if (access(realpath(file_to_scan, NULL), F_OK)) {
		printf("./acmonitor: file \"%s\" does not exist\n", file_to_scan);
		usage();
	}

	uids = uniqueUIDs(logs, &length);

	for (int i = 0; i < length; i++) 
	{	
		mods = 0;
		last_fngp = findFisrtFingerprint(logs, uids[i], file_to_scan);
		p = logs;

		while (*p)
		{
			if ((*p)->uid == uids[i] && strcmp((*p)->file, realpath(file_to_scan, NULL)) == 0) {
				if (strcmp((*p)->fingerprint, last_fngp) != 0 && (*p)->access_type == 2) {
					mods++;
					last_fngp = (*p)->fingerprint;
				}
			}
			p++;
		}

		if (mods>0) printf("%d\t%d\n", uids[i], mods);
	}

	return;
}

void
list_file_creations(FILE* log, int num){

	struct entry **logs = unmarshal_users(log), **p;
	int files_l = 0;

	time_t t, today = time(NULL);
	struct tm *tm = localtime(&today);
	char time[36];

	p=logs;

	while (*p)
	{	
		sprintf(time, "%s %s", (*p)->date, (*p)->time);
		strptime(time, "%d/%m/%Y %H:%M:%S", tm);
		t = mktime(tm);

		if (difftime(today, t)/60 < 20.0 && (*p)->access_type==0)
		{
			files_l++;
		}
		p++;
	}

	if (files_l>num)
		printf("%d\n", files_l);	

	return;
}

void
list_encrypted_files(FILE* log)
{
	struct entry **logs = unmarshal_users(log), **p;
	int files_l = 0;
	regex_t rx;
	char ** files = NULL;

	files = (char **)calloc(1024, sizeof(char *));
	p = logs;

	if (regcomp(&rx, "^.*\\.(encrypt)$", REG_EXTENDED) != 0) {
        fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }

	while (*p)
	{	
		if (!regexec(&rx, (*p)->file, 0, NULL, 0) && !searchFile(files, (*p)->file, files_l)) {
			files_l++;
			files[files_l-1] = (char*)malloc(sizeof(char)*strlen((*p)->file));
			strcpy(files[files_l-1], (*p)->file);
		}			

		p++;
	}
	for (int i = 0; i < files_l; i++) {
		printf("%s\n",files[i]);
	}

	regfree(&rx);
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:v:me")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'v':
			list_file_creations(log, atoi(optarg));
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'e':
			list_encrypted_files(log);
			break;
		default:
			usage();
		}

	}


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
