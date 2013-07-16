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
#include <fnmatch.h>

#ifndef TEST
# define LOG(...) syslog(LOG_DEBUG, __VA_ARGS__)
#else
# define LOG(...) fprintf(stderr, __VA_ARGS__)
#endif

void block(const char *ip, const char *domain, const char *message) {
  printf("R553 sorry, %s (#5.7.1)\n", message);
  LOG("ip=%s:helo=%s:block (%s)\n", ip, domain, message);
}

void add_header(const char *ip, const char *domain, const char *message) {
  printf("HX-Spam-Flag: YES\n");
  LOG("ip=%s:helo=%s:allow,add_header (%s)\n", ip, domain, message);
}

void allow(const char *ip, const char *domain, const char *message) {
  LOG("ip=%s:helo=%s:allow (%s)\n", ip, domain, message);
}


int check_whitelisted(const char *helo_domain) {
  char *wlist_path = getenv("HELOWHITELIST");
  char wl_entry[64];
  FILE *whitelist = NULL;

  if (!wlist_path) {
    return 0;
  }
  whitelist = fopen(wlist_path, "r");
  if (!whitelist) {
    return 0;
  }
  while (fscanf(whitelist, "%s\n", wl_entry) == 1) {
    if (!strncmp(wl_entry, helo_domain, 64)) {
      return 1;
    }
  }
  return 0;
}

int main(void) {
  char *helo_domain = getenv("SMTPHELOHOST");
  char *remote_ip = getenv("TCPREMOTEIP");
  struct addrinfo hints, *res, *result;
  char ipstr[16];
  int ret = 0;

  openlog("qmail-helo", LOG_PID, LOG_LOCAL0);

  if (!helo_domain) {
    block(remote_ip, helo_domain, "no HELO/EHLO hostname has been sent"); 
    goto _end;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; // Handle Ipv4 only
  hints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(helo_domain, NULL, &hints, &result);
  if (ret) {
    if (ret == EAI_AGAIN) {
      allow(remote_ip, helo_domain, "temporary DNS failure");
    } else {
      block(remote_ip, helo_domain, gai_strerror(ret));
    }
    goto _end;
  } 

  for (res = result; res != NULL; res = res->ai_next) {
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    void * addr = &(ipv4->sin_addr);
    inet_ntop(res->ai_family, addr, ipstr, sizeof(ipstr));
    if (!strncmp(ipstr, remote_ip, 16)) {
      allow(remote_ip, helo_domain, "DNS record match");
      goto _end;
    }
  }
  if (check_whitelisted(helo_domain)) {
    allow(remote_ip, helo_domain, "Whitelisted");
  } else {
    add_header(remote_ip, helo_domain, "DNS mismatch");
  }

_end:
  closelog();
  return 0;
}

