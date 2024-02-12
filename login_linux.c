/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler(int signum) {
	
	/* add signalhandling routines here */
	/* see 'man 2 signal' */
	//	Set of signals to block
	if(signum == SIGINT) {
		printf("Program can not be terminated with %d\n", signum);
	}
}

int main(int argc, char *argv[]) {

	mypwent* passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	int MAX_ATTEMPTS = 5;

	signal(SIGINT, sighandler);
	signal(SIGTSTP, sighandler);
	signal(SIGQUIT, sighandler);

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		// Swap end with \n with \0
		user[strcspn(user, "\n")] = '\0';

		passwddata = mygetpwnam(user);

		if (passwddata == NULL) {
			printf("Login Incorrect \n");
			continue;
		}

		if(passwddata->pwfailed >= MAX_ATTEMPTS) {
			printf("Too many failed attempts. Your account is locked.\n");
			return 0;
		}
		user_pass = crypt(getpass(prompt), passwddata->passwd_salt);

		if (!strcmp(user_pass, passwddata->passwd)) {
			passwddata->pwfailed = 0;
			passwddata->pwage++;

			printf(" You're in !\n");

			if (passwddata->pwage > 10) {
				printf("Do you want to change password?:");
				char answer[3];
				fgets(answer, 3, stdin);	
				
				answer[strcspn(answer, "\n")] = '\0';
				if (strcmp(answer, "y") == 0) {
					c_pass = getpass(prompt);
					passwddata->passwd = crypt(c_pass, passwddata->passwd_salt);
					passwddata->pwage = 0;
				}
			}

			passwddata->pwage++;
			passwddata->pwfailed = 0;

			mysetpwent(user, passwddata);
			/*  check UID, see setuid(2) */
			/*  start a shell, use execve(2) */
			printf("Starting terminal..\n");
			if(setuid(passwddata->uid) != 0) {
				printf("Error setting uid. \n\n");
				exit(1);	
			}
			if(execve("/bin/sh", NULL, NULL) != 0) {
				exit(1);
			}
		} else {
			passwddata->pwfailed++;
			mysetpwent(user, passwddata);
		}
	}
	return 0;
}
