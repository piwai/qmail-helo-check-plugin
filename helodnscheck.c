/*
* Copyright (C) 2007 Jason Frisvold <friz@godshell.com>
* Original Copyright (C) 2003-2004 Perolo Silantico <per.sil@gmx.it>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
***
* 1/16 Modified original version to check helo/ehlo instead of mail from
***
*
* $Id$
*
*/

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#define LOGFILE "/var/log/qmail/qmail-plugin/helodnscheck.log"

void block_permanent(const char* message) {
  printf("E553 sorry, %s (#5.7.1)\n", message);
  fprintf(stderr, "helo-dns-check: blocked with: %s\n", message);  
}


void block_temporary(const char* message) {
  printf("E451 %s (#4.3.0)\n", message);
  fprintf(stderr, "helo-dns-check: temporary failure: %s\n", message);  
}

int main(void) {
 unsigned char dns_answer[1023];
 char *helo_domain = getenv("SMTPHELOHOST");
 char *remote_ip = getenv("TCPREMOTEIP");
 char *no_helo_check = getenv("NOHELODNSCHECK");
 FILE *F=NULL;
 time_t t;
 struct tm *tmp;
 char timestr[30];

 F = fopen (LOGFILE, "a");
 if (F == NULL) {
   return 0;    // do nothing if we can't log to file
 }
 t = time(NULL);
 tmp = localtime(&t);
 strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmp);

  if (no_helo_check) {
    fprintf(F, "%s:ip=%s:helo=%s:allow (NOHELODNSCHECK is defined)\n", 
	    timestr, remote_ip, helo_domain); 
    goto _end;
  }

  if (!helo_domain) {
    fprintf(F, "%s:ip=%s:helo=%s:block (no HELO/EHLO hostname has been sent)\n",
	    timestr, remote_ip, helo_domain); 
    //block_permanent("no HELO/EHLO hostname has been sent.");
    goto _end;
  }

  /* init DNS library */
  res_init();

  /* check A record of host */ 
  if (res_query(helo_domain, C_IN, T_A, dns_answer, sizeof(dns_answer)) <= 0) {
    if ((errno == ECONNREFUSED) || (errno == TRY_AGAIN)) {
      fprintf(F, "%s:ip=%s:helo=%s:allow (DNS temporary failure)\n",
	      timestr, remote_ip, helo_domain); 
      //block_temporary("DNS temporary failure.");
    } else {
      fprintf(F, "%s:ip=%s:helo=%s:block (invalid host name in EHLO command)\n",
	      timestr, remote_ip, helo_domain); 
      //block_permanent("invalid host name in HELO/EHLO command.");
    }
  } else {
    fprintf(F, "%s:ip=%s:helo=%s:allow\n", 
	    timestr, remote_ip, helo_domain); 
  }

_end:
    fclose(F);
    return 0;
}

