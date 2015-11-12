/*
 * Copyright 2015, Cumulus Networks Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * Author: olson@cumulusnetworks.com>
 */

#include <stdint.h>
#include <time.h>
#include <pwd.h>
#include <utmp.h>

#define MAP_TACPLUS_FILE "/var/run/tacacs_client_map"

#define MAP_FILE_VERSION 1 /* in case tacacs_mapping struct changes */

/*
 * Structure to maintain mapping between login name and mapped tacacs name.
 * Only live while session is active.  Like utmp, designed to re-use slots
 * after session is gone.
 * Designed so that it should have the same layout in 32 and 64 bit,
 * although currently only in use on 64 bit systems.
 * Unlike utmp we do not maintain a login pid, because the PID we could
 * record will not be the PID we want check.
 */
struct tacacs_mapping {
    struct timeval tac_tv;  /* only used for debug for now */
# if __WORDSIZE == 32
    uint32_t __fill__[2]; /* to keep alignment the same for 32 and 64 bit */
#endif
    uint32_t tac_mapversion; /* mapping version that wrote this file */
    uint32_t tac_session; /* session ID */
    uid_t tac_mapuid; /* for faster lookup, the login auid */
    char tac_logname[UT_NAMESIZE+1]; /* login name.  from utmp.h, + 1 for \0 */
    char tac_mappedname[UT_NAMESIZE+1]; /* mapped name, for uid we are using */
    char tac_rhost[UT_HOSTSIZE+1]; /* ssh, etc. originating host, for logging */
};

/* update the mapped user database */
int update_mapuser(char *user, unsigned priv_level,
    char *host); /* returns true/false */
char *get_user_to_auth(char *pamuser); /* returns NULL or strdup'ed memory */
unsigned map_get_sessionid(void); /* return the sessionid for this session */

/*
 * Lookup the given name to see if we mapped it, via our mapping file.
 * and return the mapped login name, if so.  Otherwise returns the 
 * pamuser name passed as first argument.  Passing pamuser as NULL
 * requests match on auid and session only.
 *
 * If the returned pointer != first arg and non-NULL, caller should free it.
 *
 * This only works while a mapped user is logged in, and since the auid and
 * session are lookup keys, only for processes that are descendents
 * of the mapped login.
 *
 * if host is non-NULL, *host is set to the originating rhost, if any
 * It is a malloc'ed entry, and should be freed by the caller
 */
char *lookup_logname(char *pamuser, uid_t auid, unsigned session, char **host);

/*
 * Similar to lookup_logname(), but by uid.
 * The same caveat applies; only works for descendent processes.
 * Returns the original login username, and the mapped name
 * in the copied to the buffered pointed to by mapped
 * Returns NULL if not found.  If non-NULL, the returned
 * pointer should be freed by the caller.
 */
char *lookup_mapuid(uid_t uid, uid_t auid, unsigned session,
                    char *mappedname, size_t maplen);

/* This is not a public entry point, it's a helper routine for pam_tacplus */
void __update_loguid(char *, char *, char *);
