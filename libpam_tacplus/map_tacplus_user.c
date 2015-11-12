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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <libaudit.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "map_tacplus_user.h"

static const char *libname = "libtacplus_map";

static const char *mapfile = MAP_TACPLUS_FILE;

static int debug; /* for developer debug */

#define MATCH_MAPPED 1 /* match mapped name in mapfile */
#define MATCH_LOGIN 2 /* match login name in mapfile */
/*
 * see if a mapping file entry matches; the pid needs to be valid and
 * the process still alive, to be consider a match.
 * name can be NULL, if we are looking for a UID match
 * rather than a name match.
 * If auid and/or session are -1, they are wildcards, only match
 * on other data.
 * "which" controls which name we match on.
 */
static int is_mapmatch(struct tacacs_mapping *map, int which, char *name,
                       uid_t auid, unsigned session)
{
    if (map->tac_mapversion != MAP_FILE_VERSION)
        syslog (LOG_WARNING, "%s version of tacacs client_map_file %d"
            " != expected %d proceeding anyway", libname, map->tac_mapversion,
            MAP_FILE_VERSION);
    if ((session == -1 || map->tac_session == session) && 
        (auid == -1 || map->tac_mapuid == auid)) {
        if (!name)
            return 1; /* usually cleanup, just auid and session match */
        switch(which) {
        case MATCH_MAPPED:
            if (!strcmp(name, map->tac_mappedname))
                return 1;
            break;
        case MATCH_LOGIN:
            if (!strcmp(name, map->tac_logname))
                return 1;
            break;
        default:
            syslog (LOG_WARNING, "%s invalid lookup type %d", libname, which);
            break;
        }
    }
    return 0;
}


/*
 * Lookup the given name to see if we mapped it, via our mapping file.
 * and return the mapped login name, if so.  Otherwise return the 
 * username passed in.
 *
 * This only works while a mapped user is logged in, and since the auid and
 * session are lookup keys, only for processes that are descendents
 * of the mapped login.
 *
 * we need to look up the auid locally only, to avoid recursing into the
 * tacacs code.   This could cause problems if somebody is using local
 * users, ldap, and tacacs, but we just require that the mapped user always
 * be a local user.  Since the local user password isn't supposed to be
 * used, that should be OK.
 *
 * We take a shared lock to prevent looking at the file while it's being
 * updated.
 *
 * If returned pointer != first arg, caller should free it.
 * There isn't a really good way to validate that an entry is still
 * live, without searching through all the /proc/PID/sessionid files.
 *
 * If pamuser is NULL, only match on auid & session.  Used for audit records
 * and cleanup.
 *
 * We don't record the PID because we can't get it right under all
 * circumstances.  If we could, it would help sanity checks.
 *
 * If somebody kills, e.g., the session parent login or sshd, nothing is
 * left around to do the cleanup, and the entry could remain forever.
 * __update_loguid() does this on every add and delete.
 */
char *lookup_logname(char *pamuser, uid_t auid, unsigned session, char **host)
{
    struct tacacs_mapping map;
    char *origuser = pamuser; /* if no match, return original */
    int fd, cnt;

    fd = open(mapfile, O_RDONLY, 0600);
    if (fd == -1) {
        return pamuser; /* likely not using tacacs, but may be earlier error */
    }

    if (flock(fd, LOCK_SH)) {
        syslog (LOG_WARNING, "%s lock of tacacs client_map_file %s failed: %m, "
            "proceeding anyway", libname, mapfile);
    }

    while ((cnt=read(fd, &map, sizeof map)) == sizeof map) {
        if (is_mapmatch(&map, MATCH_MAPPED, pamuser, auid, session)) {
            origuser = strndup(map.tac_logname, sizeof map.tac_logname);
            if (!origuser) {
                syslog(LOG_WARNING,
                       "%s failed to allocate memory, user %.*s: %m",
                       libname, (int)sizeof map.tac_logname,
                       map.tac_logname);
                origuser = pamuser;
            }
            if (host)
                *host = strndup(map.tac_rhost, sizeof map.tac_rhost);
            break;
        }
    }
    if (cnt > 0 && cnt != sizeof map)
        syslog (LOG_WARNING,
                "%s corrupted tacacs client_map_file %s: read wrong size %d",
                libname, mapfile, cnt);
    (void)flock(fd, LOCK_UN);
    close(fd);
    return origuser;
}

/*
 * Similar to lookup_logname(), but by uid.
 * Returns the original login username, and the mapped name
 * in the copied to the buffered pointed to by mapped
 * If auid and/or session are -1, they are wildcards, take
 * the first matching uid from the mapfile 
 * Returns NULL if not found.
 */
char *lookup_mapuid(uid_t uid, uid_t auid, unsigned session,
                    char *mappedname, size_t maplen)
{
    struct tacacs_mapping map;
    int fd, cnt;
    char *loginname = NULL;

    fd = open(mapfile, O_RDONLY, 0600);
    if (fd == -1) {
        return NULL; /* likely not using tacacs, but may be earlier error */
    }

    if (flock(fd, LOCK_SH)) {
        syslog (LOG_WARNING, "%s lock of tacacs client_map_file %s failed: %m, "
            "proceeding anyway", libname, mapfile);
    }

    while ((cnt=read(fd, &map, sizeof map)) == sizeof map) {
        if (map.tac_mapuid == uid &&
            is_mapmatch(&map, MATCH_LOGIN, NULL, auid, session)) {
            loginname = strdup(map.tac_logname); /* this may leak */
            snprintf(mappedname, maplen, "%s", map.tac_mappedname);
            break;
        }
    }
    if (cnt > 0 && cnt != sizeof map)
        syslog (LOG_WARNING,
                "%s corrupted tacacs client_map_file %s: read wrong size %d",
                libname, mapfile, cnt);
    (void)flock(fd, LOCK_UN);
    close(fd);
    return loginname;
}

/*
 * there isn't an API to get the audit sessionid, so this will
 * do.   Returns sessionid if we can read it, else 0.
 * 0 is not a valid sessionid; default if no auditing is -1U
 * Don't cache the value, since it can change.
 * We export it for users of this library.
 */
unsigned
map_get_sessionid(void)
{
    int fd = -1, cnt;
    unsigned id = 0U;
    static char buf[12];

    fd = open("/proc/self/sessionid", O_RDONLY);
    if (fd != -1) {
        cnt = read(fd, buf, sizeof(buf));
        close(fd);
    }
    if (fd != -1 && cnt > 0) {
        id = strtoul(buf, NULL, 0);
    }
    return id;
}

/*
 * open the map file, creating if necessary, and verifying permissions
 */
static int
open_map()
{
    int fd;
    struct stat st;

    /*
     * create exclusive, for first time use; if that fails (regardless
     * of errno), try a normal open.
     */
    fd = open(mapfile, O_CREAT|O_RDWR|O_EXCL, 0600);
    if (fd == -1)
        fd = open(mapfile, O_RDWR, 0600);
    if (fd == -1) { /* directory missing? What else? */
        syslog (LOG_ERR, "%s unable to open tacacs client_map_file %s: %m",
                         libname, mapfile);
    }
    else {
        if (fstat(fd, &st) == 0 && !(st.st_mode & S_IROTH)) {
            if (fchmod(fd, st.st_mode | S_IROTH))
                syslog (LOG_ERR, "%s unable to chmod tacacs "
                    "client_map_file %s: %m", libname, mapfile);
        }
    }
    return fd;
}

/*
 * Lookup a sessionid for all /proc/PID/sessionid
 * If a match is found, or there are lookup errors, return 0, else return 1.
 */
static int
invalid_session(int mapsess)
{
    DIR *dp;
    struct dirent *dptr;
    int ret = 0;

    dp = opendir("/proc");
    if (!dp)
        return 0;
    while ((dptr = readdir(dp))) {
        char *eptr;
        if (strtoul(dptr->d_name, &eptr, 10) && !*eptr) {
            /* all numeric, it's a PID */
            char nmbuf[128]; /* always short path */
            char sess_str[16];
            int fd, cnt, sess=0;
            snprintf(nmbuf, sizeof nmbuf, "/proc/%s/sessionid", dptr->d_name);
            fd = open(nmbuf, O_RDONLY);
            if (fd == -1)
                syslog(LOG_DEBUG, "%s: %s open fails: %m", libname, nmbuf);
            else {
                cnt = read(fd, sess_str, sizeof sess_str - 1);
                close(fd);
                if (cnt > 0) {
                    sess_str[cnt] = '\0';
                    sess = strtoul(sess_str, &eptr, 0);
                    if (sess == mapsess) {
                        goto done;
                    }
                }
            }
        }
    }
    ret = 1;
done:
    closedir(dp);
    return ret;
}

/*
 * check for stale (invalid) entries, and clean them up if found.
 * Called with the flock() held.
 *
 * Since we only have one version now, if the version doesn't match,
 * the entry is corrupt, so clear it.
 */
static void
chk_cleanup_map(int fd)
{
    struct tacacs_mapping map, tmap;
    int cnt;

    if (lseek(fd, 0, SEEK_SET))
        return;

    memset(&map, 0, sizeof(map)); /* make sure it's sane */
    map.tac_mapversion = MAP_FILE_VERSION;
    (void)gettimeofday((struct timeval *)&map.tac_tv, NULL);

    while ((cnt=read(fd, &tmap, sizeof tmap)) == sizeof tmap) {
        if (tmap.tac_mapversion != MAP_FILE_VERSION ||
            ((tmap.tac_mapuid || tmap.tac_mappedname) &&
            tmap.tac_session && invalid_session(tmap.tac_session))) {
            off_t off = (off_t)-cnt;
            syslog(LOG_WARNING, "%s: Cleaning up stale entry in %s uid=%d, "
                "sess=%d, mapuser=%s", libname, mapfile, tmap.tac_mapuid,
                tmap.tac_session, tmap.tac_mappedname);
            if (lseek(fd, off, SEEK_CUR) == -1) {
                syslog (LOG_ERR,
                    "%s: rewrite seek failed on tacacs client_map_file %s: %m",
                    libname, mapfile);
                break; /* we can't do anything else */
            }
            else if (write(fd, &map, sizeof map) != sizeof map) {
                /* future lookups will fail... */
                syslog (LOG_ERR, "%s unable to write tacacs client_map_file "
                    "%s: %m", libname, mapfile);
            }
        }
    }

    /*
     * could lead to missing other entries if this was the add call and it
     * fails, but there isn't much we can do about it.
     */
    (void)lseek(fd, 0, SEEK_SET);
}


/*
 * Create an entry for the mapped user in our lookup file, with the info
 * that will be needed by the audit and nss plugins.
 *
 * if olduser is NULL, then we are doing cleanup after logout, etc.
 * If olduser is non-null we are writing the mapping entry to the map file
 * If adding a mapping entry, walk the file to see if there is an unused
 * entry that we can re-use.  We take an exclusive flock here, shared in
 * the lookup code, to avoid corrupting the file.
 *
 * Because there is a possibility of stale entries, validate and cleanup
 * whenever we are doing the update.
 * Stale entries can occur when somebody kills, e.g., the session parent
 * login or sshd, nothing is left around to do the cleanup, and the entry could
 * remain forever.  __update_loguid() does this on every add and delete.
 *
 * This would be static, but it needs to be exported to pam_tacplus.
 * It is not a public entry point.
*/

void
__update_loguid(char *newuser, char *olduser, char *rhost)
{
    struct tacacs_mapping map, tmap;
    int fd, cnt, foundmatch = 0;
    uid_t auid;
    unsigned session;

    fd = open_map();
    if (fd == -1)
        return;

    if (flock(fd, LOCK_EX))
        syslog (LOG_WARNING, "%s unable to lock tacacs client_map_file %s: %m,"
                             " proceeding anyway", libname, mapfile);

    if(olduser) /* check and cleanup before adding */
        chk_cleanup_map(fd);

    memset(&map, 0, sizeof(map)); /* make sure it's sane */
    auid = audit_getloginuid();
    session = map_get_sessionid();

    if (olduser) {
        /* so we can map back for later accounting and for nss_tacplus; newuser
         * *should* always be non-null.  olduser will be NULL at logout */
        snprintf(map.tac_logname, sizeof map.tac_logname, "%s",
                 newuser ? newuser : "");
        snprintf(map.tac_mappedname, sizeof map.tac_mappedname, "%s",
                 olduser ? olduser : "");
        snprintf(map.tac_rhost, sizeof map.tac_rhost, "%s",
                 rhost ? rhost : "");
        map.tac_mapuid = auid;
        map.tac_session = session;
    }

    (void)gettimeofday((struct timeval *)&map.tac_tv, NULL);
    map.tac_mapversion = MAP_FILE_VERSION;

    while (!foundmatch && (cnt=read(fd, &tmap, sizeof tmap)) == sizeof tmap) {
        if (olduser && !tmap.tac_mapuid && !tmap.tac_session) {
            foundmatch = 1; /* found an empty slot to use. */
        }
        if (!olduser && is_mapmatch(&tmap, MATCH_LOGIN, newuser, auid,
            session)) {
            foundmatch = 1;
        }
    }
    if (cnt > 0 && cnt != sizeof map)
        syslog (LOG_WARNING,
            "%s: corrupted tacacs client_map_file %s: incorrect size %d read",
            libname, mapfile, cnt);

    if (!olduser && !foundmatch) {
        goto done;
    }

    if (foundmatch) { /* found entry to overwrite, either to NULL or re-use */
        off_t off = (off_t)-cnt;
        if (lseek(fd, off, SEEK_CUR) == -1) {
            syslog (LOG_ERR,
                "%s: rewrite seek failed on tacacs client_map_file %s: %m",
                libname, mapfile);
            goto done;
        }
    }
    else if (!newuser) {
        /*
         * if we didn't find entry to clear, something went wrong,
         * so don't write an empty entry at the end.
         */
        goto done;
    }

    /* either overwrite an existing entry, or write new at end */
    if (write(fd, &map, sizeof map) != sizeof map) {
        /* future lookups will fail... */
        syslog (LOG_ERR, "%s unable to write tacacs client_map_file %s: %m",
            libname, mapfile);
    }
done:
    if(!olduser) /* check and cleanup after deleting */
        chk_cleanup_map(fd);
    (void)flock(fd, LOCK_UN);
    (void)fsync(fd);
    close(fd);
}


/*
 * Check to see if login name found in /etc/passwd.  If so, use it.  If not
 * try to map to a localuser tacacsN where N <= to the TACACS+ privilege level.
 * The NSS lookup code needs to match this same algorithm.
 *
 * Returns 1 if user was mapped (!islocal), 0 if not mapped
 */
int
update_mapuser(char *user, unsigned priv_level, char *rhost)
{
    FILE *pwfile;
    struct passwd *ent;
    char tacuser[9]; /* "tacacs" + up to two digits plus 0 */
    int islocal, foundtac;
    unsigned priv = priv_level;
    uid_t luid=0, tuid=0;

    pwfile = fopen("/etc/passwd", "r");
    if (!pwfile) {
        syslog(LOG_WARNING, "%s: failed to open /etc/passwd: %m", libname);
        return 0;
    }

recheck:
    snprintf(tacuser, sizeof tacuser, "tacacs%u", priv);
    for (islocal = foundtac = 0; (!islocal || !foundtac) &&
        (ent = fgetpwent(pwfile)); ) {
        if(!ent->pw_name)
            continue; /* shouldn't happen */
        if(!strcmp(ent->pw_name, user)) {
            islocal++;
            luid = ent->pw_uid;
        }
        else if(!strcmp(ent->pw_name, tacuser)) {
            foundtac++;
            tuid = ent->pw_uid;
        }
    }
    if(islocal || foundtac) {
        fclose(pwfile);
        pwfile = NULL;
        /*
         * If priv-level==N, and tacacsN isnt local, but tacacsM (0<=M<N)
         * is present, we fallback to that lower level (with a warning logged).
         * This sets the session ID (/proc/PID/sessionid) as a side effect, and
         * that sessionid will remain the same for all child processes (unless
         * something "incorrectly", calls audit_setloginuid() again.
         *
         * We call it here, instead of requiring pam_loginuid in pam.d/sshd,
         * login, etc. because we need the info earlier than it is really
         * possible via the normal pam auth/session sequencing.
         */
        audit_setloginuid(islocal?luid:tuid); /* set auid */
        __update_loguid(user, islocal?user:tacuser, rhost);
        if(debug && !islocal && priv != priv_level)
            syslog(LOG_DEBUG, "%s: Did not find local tacacs%u , using %s",
                libname, priv_level, tacuser);
    }
    else if(priv > 0) {
        priv--;
        rewind(pwfile);
        goto recheck;
    }
    if (pwfile)
        fclose(pwfile);
    return !islocal;
}


/*
 * lookup a uid only in the local password file (to avoid tacacs recursion).
 * This is supposed to be the mapped user, which should always be a local
 * user, so we don't need to care about ldap or other remote mechanisms.
 * Returns a pointer to strdup'ed memory, if found.  Caller must free,
 * or it will leak.
 */
static char *lookup_local_uid(uid_t auid)
{
    FILE *pwfile;
    struct passwd *ent;
    char *pwname = NULL; /* will be strdup'ed on success */

    pwfile = fopen("/etc/passwd", "r");
    if (!pwfile) {
        syslog(LOG_WARNING, "%s: failed to open /etc/passwd: %m", libname);
        return NULL;
    }
    while ((ent = fgetpwent(pwfile)) && ent->pw_uid != auid)
            ;
    if(ent)
        pwname = strdup(ent->pw_name);
    fclose(pwfile);
    return pwname;
}

/*
 * If a mapped user entry already exists, we are probably being
 * used for su or sudo, so we need to get the original user password,
 * rather than the mapped user (the generic NSS lookup doesn't need
 * the password).
 * Never lookup for uid == 0 (login process, or root doing sudo), to avoid
 * causing any issues (and because it's pointless).
 *
 * If auid != uid, and audit session ID already set, then do the lookup.
 *
 * We return strndup'ed memory on success, which will be leaked if not freed.
 * That's OK, given that this is typically called only once per program, and
 * that usernames are short.
 */
char *get_user_to_auth(char *pamuser)
{
    char *mapuser, *origuser;
    unsigned session;
    uid_t auid;

    if (pamuser == NULL)
        return NULL;

    auid = audit_getloginuid();
    if(auid == (uid_t)-1 || !auid)
        return pamuser;
    session = map_get_sessionid();
    if (session == ~0U) /* sessionid not set or not enabled */
        return pamuser;

    mapuser = lookup_local_uid(auid);
    if (!mapuser)
        return pamuser;

    if(strcmp(pamuser, mapuser)) {
        free(mapuser);
        return pamuser;
    }
    free(mapuser); /* done now */

    /* returns malloced string of original user, if found, which will
     * be a memory leak, but that shouldn't matter
     */
    origuser = lookup_logname(pamuser, auid, session, NULL);
    return origuser ? origuser : pamuser;
}
