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
 char *no_helo_check = getenv("NOHELODNSCHECK");

  if (no_helo_check) {
     return 0;
  }

  if (!helo_domain) {
    block_permanent("no HELO/EHLO hostname has been sent.");
    return 0;
  }

  /* init DNS library */
  res_init();

  /* check A record of host */ 
  if (res_query(helo_domain, C_IN, T_A, dns_answer, sizeof(dns_answer)) <= 0)
  {
    if ((errno == ECONNREFUSED) || (errno == TRY_AGAIN))
      block_temporary("DNS temporary failure.");
    else
      block_permanent("invalid host name in HELO/EHLO command.");
  }

  return 0;
}

