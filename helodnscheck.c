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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <syslog.h>

void block_permanent(const char* message) {
  printf("E553 sorry, %s (#5.7.1)\n", message);
  fprintf(stderr, "helo-dns-check: blocked with: %s\n", message);  
}

void block_temporary(const char* message) {
  printf("E451 %s (#4.3.0)\n", message);
  fprintf(stderr, "helo-dns-check: temporary failure: %s\n", message);  
}

int check_domain_against_ip(const char *domain, const char *remote_ip) {
  struct addrinfo hints, *res, *result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  void *addr;
  char ipstr[16];
  int err = 0;

  err = getaddrinfo(domain, NULL, &hints, &result);
  if (err) {
    syslog(LOG_DEBUG, "getaddrinfo() failed\n");
    return 1;
  }
  for (res = result; res != NULL; res = res->ai_next) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
      addr = &(ipv4->sin_addr);
      inet_ntop(res->ai_family, addr, ipstr, sizeof(ipstr));
      if (!strncmp(ipstr, remote_ip, 16)) {
	syslog(LOG_DEBUG, "match found for '%s' -> %s \n", domain, remote_ip);
	return 0;
      }
    }
  syslog(LOG_DEBUG, "no IP matching '%s'", domain);
  return 1;
}

int main(void) {
 char *helo_domain = getenv("SMTPHELOHOST");
 char *remote_ip = getenv("TCPREMOTEIP");
 char *no_helo_check = getenv("NOHELODNSCHECK");

 openlog("qmail-helo", LOG_PID, LOG_LOCAL0);

  if (no_helo_check) {
    syslog(LOG_DEBUG, "ip=%s:helo=%s:allow (NOHELODNSCHECK is defined)\n", 
	    remote_ip, helo_domain); 
    goto _end;
  }

  if (!helo_domain) {
    syslog(LOG_DEBUG, "ip=%s:helo=%s:block (no HELO/EHLO hostname has been sent)\n",
	    remote_ip, helo_domain); 
    //block_permanent("no HELO/EHLO hostname has been sent.");
    goto _end;
  }

  if (check_domain_against_ip(helo_domain, remote_ip) == 0) {
      syslog(LOG_DEBUG, "ip=%s:helo=%s:allow\n", remote_ip, helo_domain); 
      //block_temporary("DNS temporary failure.");
  } else {
      syslog(LOG_DEBUG, "ip=%s:helo=%s:block (invalid host name in EHLO command)\n",
	      remote_ip, helo_domain); 
      //block_permanent("invalid host name in HELO/EHLO command.");
  }

_end:
    closelog();
    return 0;
}

