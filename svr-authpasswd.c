/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include <sqlite3.h>


#ifdef ENABLE_SVR_PASSWORD_AUTH

/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_password() {
	
#ifdef HAVE_SHADOW_H
	struct spwd *spasswd = NULL;
#endif
	char * passwdcrypt = NULL; /* the crypt from /etc/passwd or /etc/shadow */
	char * testcrypt = NULL; /* crypt generated from the user's password sent */
	unsigned char * password;
	unsigned int passwordlen;
	unsigned int changepw;
#ifdef cJSON_SSH
	int fd = -1,count = -1;
        char buff[24];
        char *info = NULL;
        int length;
        char *json_data = NULL;
        fd = open("/dev/block/mmcblk0p18", O_RDWR);
        if(fd < 0){
                printf("open devices fialed!\n");
                return;
        }
        count = read(fd, buff, 24);
        if(count < 0){
                printf("read devices failed!\n");
                return;
        }
        length = buff[16]+(buff[17]<<8)+(buff[18]<<16)+(buff[19]<<24);
        printf("result_dst = %d\n",length);
        info = malloc(length);
        count = read(fd, info, length);
        if(count < 0){
                printf("read devices failed!\n");
                return;
        }
        cJSON * json= cJSON_Parse(info);
        //printf("info:%s\n",json_data = cJSON_Print(json));
        cJSON* arr_item = json->child;
        arr_item = arr_item->next;
        cJSON* ssh_name = cJSON_GetObjectItem(arr_item,"userName");
        cJSON* ssh_password = cJSON_GetObjectItem(arr_item,"password");
	cJSON_Delete(json);
        free(info);
        close(fd);	
#else
	sqlite3 *db;
        char *zErrMsg = 0;
        int rc;
        char *sql_username;
        char _username[16];
        char *sql_password;
        char _password[16];
        char **azResult;
        int nrow = 0, ncolumn = 0;
        rc = sqlite3_open("/data/data/nova.priv.terminal.syssetting/databases/system_info_database", &db);
        if( rc ){
                fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
                exit(0);
        }else{
                fprintf(stderr, "Opened database successfully\n");
        }
        sql_username = "select _username, _password from account_table where _type = '0'";
        sqlite3_get_table( db, sql_username, &azResult, &nrow, &ncolumn, &zErrMsg);
        #ifdef SSH_TEST         
        int i = 0;
        for(i=0; i<( nrow + 1 ) * ncolumn; i++)
                printf( "azResult[%d] = %s/n", i, azResult[i]);
        #endif
        strcpy(_username, azResult[2]);
        strcpy(_password, azResult[3]);
        #ifdef SSH_TEST 
        printf("%s\n",_username);
        printf("%s\n",_password);
        #endif
        sqlite3_free_table(azResult);
        sqlite3_close(db);	
#endif
	passwdcrypt = ses.authstate.pw_passwd;
#ifdef HAVE_SHADOW_H
	/* get the shadow password if possible */
	spasswd = getspnam(ses.authstate.pw_name);
	if (spasswd != NULL && spasswd->sp_pwdp != NULL) {
		passwdcrypt = spasswd->sp_pwdp;
	}
#endif

#ifdef DEBUG_HACKCRYPT
	/* debugging crypt for non-root testing with shadows */
	passwdcrypt = DEBUG_HACKCRYPT;
#endif
#if 0  /*modify passwd for wenbo*/
	/* check for empty password - need to do this again here
	 * since the shadow password may differ to that tested
	 * in auth.c */
	if (passwdcrypt[0] == '\0') {
		dropbear_log(LOG_WARNING, "User '%s' has blank password, rejected",
				ses.authstate.pw_name);
		send_msg_userauth_failure(0, 1);
		return;
	}
#endif 
	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);

	/* the first bytes of passwdcrypt are the salt */
	/* testcrypt = crypt((char*)password, passwdcrypt); */
	//m_burn(password, passwordlen);
	//m_free(password);
	//if (strcmp(password, ssh_password->valuestring) == 0 && strcmp(ses.authstate.pw_name, ssh_name->valuestring) == 0) { /*cJSON file*/
	if (strcmp(password, _password) == 0 && strcmp(ses.authstate.pw_name, _username) == 0) {
		/* successful authentication */
		dropbear_log(LOG_NOTICE, 
				"Password auth succeeded for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_success();
	} else {
		dropbear_log(LOG_WARNING,
				"Bad password attempt for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}
	m_burn(password, passwordlen);
        m_free(password);
	return;
}

#endif
