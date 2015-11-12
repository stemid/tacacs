/*
 * Copyright (C) 2015 Cumulus Networks, Inc
 * Author: Dave Olson <olson@cumulusnetworks.com>
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
 */

/*
 * This is mostly boilerplate, for programs that want to send
 * very simple (char * buffer) tacacs accounting stop and start
 * records.   
 *
 * It is intended that the calling program use dlopen and dlsym to
 * invoke the only external entry point send_tacacs_acct().
 * 
 * On first call, send_tacacs_acct() does all the initialization of
 * reading the config file, constructing the basic arguments needed
 * for sending an account record, etc.
 *
 * The sequence for use (ignoring error checking) is:
    #define SENDTAC_START 1
    #define SENDTAC_STOP 0
    void *dl_handle;
    void *(*acctfunc)(int, const char *);
    dl_handle = dlopen("libsimple_tacacct.so.1", RTLD_NOW);
    acctfunc = dlsym("send_tacacs_acct", acctfn);
    acctfunc(SENDTAC_START, "account command to send");
    acctfunc(SENDTAC_STOP, "account command to send");
 */


#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <libaudit.h>

#include <tacplus/libtac.h>
#include <tacplus/map_tacplus_user.h>

static const char *lib_name = "simple_tacacct";
static const char *config_file = "/etc/tacplus_servers";

typedef struct {
    struct addrinfo *addr;
    const char *key;
} tacplus_server_t;

/* set from configuration file parsing */
static tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
static int tac_srv_no;

/* with this simple interface, no way for caller to specify */
static char tac_service[] = "shell";
static char tac_protocol[] = "ssh";
static int debug;

static int tacplus_config(const char *cfile)
{
    FILE *conf;
    int tac_key_no = 0;
    char lbuf[256];

    conf = fopen(cfile, "r");
    if(conf == NULL) {
        syslog(LOG_WARNING, "%s: can't open config file %s: %m",
            lib_name, cfile); 
        goto err;
    }

    while (fgets(lbuf, sizeof lbuf, conf)) {
        if(*lbuf == '#' || isspace(*lbuf))
            continue; /* skip comments, white space lines, etc. */
        strtok(lbuf, " \t\n\r\f"); /* terminate buffer at first whitespace */
        if(!strncmp (lbuf, "include=", 8)) {
            /*
             * allow include files, useful for centralizing tacacs
             * server IP address and secret.
             */
            if(lbuf[8]) /* else treat as empty config, ignoring errors */
                (void)tacplus_config(&lbuf[8]);
        }
        else if(!strncmp (lbuf, "debug=", 6)) 
            debug = strtoul(lbuf+6, NULL, 0);
        /*
         * This next group is here to prevent a warning in the
         * final "else" case.  We don't need them, but if there
         * is a common included file, we might see them.
         */
        else if(!strncmp (lbuf, "service=", 8) ||
            !strncmp (lbuf, "protocol=", 9) ||
            !strncmp (lbuf, "login=", 6))
            ;
        else if(!strncmp (lbuf, "secret=", 7)) {
            /* no need to complain if too many on this one */
            if(tac_key_no < TAC_PLUS_MAXSERVERS) {
                if((tac_srv[tac_key_no].key = strdup(lbuf+7)))
                    tac_key_no++;
                else
                    syslog(LOG_ERR, "%s: unabled to copy server secret %s",
                        lib_name, lbuf+7);
            }
        }
        else if(!strncmp (lbuf, "server=", 7)) {
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) {
                struct addrinfo hints, *servers, *server;
                int rv;
                char *port, server_buf[sizeof lbuf];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                strcpy(server_buf, lbuf + 7);

                port = strchr(server_buf, ':');
                if(port != NULL) {
                    *port = '\0';
					port++;
                }
                if((rv = getaddrinfo(server_buf, (port == NULL) ?
                            "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL &&
                        tac_srv_no < TAC_PLUS_MAXSERVERS;
                        server = server->ai_next) {
                        tac_srv[tac_srv_no].addr = server;
                        if(tac_key_no && tac_srv_no != (tac_key_no-1))
                            /* use current key if set, and not the same index */
                            tac_srv[tac_srv_no].key = tac_srv[tac_key_no-1].key;
                        tac_srv_no++;
                    }
                }
                else {
                    syslog(LOG_ERR,
                        "%s: skip invalid server: %s (getaddrinfo: %s)",
                        lib_name, server_buf, gai_strerror(rv));
                }
            }
            else {
                syslog(LOG_ERR, "%s: maximum number of servers (%d) exceeded,"
                    " skipping", lib_name, TAC_PLUS_MAXSERVERS);
            }
        }
        else if(debug) /* ignore unrecognized lines, unless debug on */
            syslog(LOG_WARNING, "%s: unrecognized parameter: %s",
                lib_name, lbuf);
    }
    fclose(conf);

    if(debug) {
        int n;
        if(!*tac_service || tac_srv_no == 0)
            syslog(LOG_DEBUG, "%s:%s: no TACACS %s in config, giving up",
                lib_name, __FUNCTION__, tac_srv_no ? "service" :
                (*tac_service ? "server" : "service and no server"));

        for(n = 0; n < tac_srv_no; n++)
            syslog(LOG_DEBUG, "%s: server[%d] { addr=%s, key='%s' }",
                lib_name, n, tac_ntop(tac_srv[n].addr->ai_addr),
                tac_srv[n].key);
    }

    return 0;

err:
    if(conf)
            fclose(conf);
    return 1;
}

int static
send_acct_msg(int tac_fd, int type, char *user, char *tty, char *host,
    char *cmd, uint16_t taskid)
{
    char buf[64];
    struct tac_attrib *attr;
    int retval;
    struct areply re;

    attr=(struct tac_attrib *)tac_xcalloc(1, sizeof(struct tac_attrib));

    snprintf(buf, sizeof buf, "%lu", (unsigned long)time(NULL));
    tac_add_attrib(&attr, "start_time", buf);

    snprintf(buf, sizeof buf, "%hu", taskid);
    tac_add_attrib(&attr, "task_id", buf);

    tac_add_attrib(&attr, "service", tac_service);
    if(tac_protocol[0])
      tac_add_attrib(&attr, "protocol", tac_protocol);
    tac_add_attrib(&attr, "cmd", (char*)cmd);

    re.msg = NULL;
    retval = tac_acct_send(tac_fd, type, user, tty, host, attr);

    if(retval < 0)
        syslog(LOG_WARNING, "send of accounting msg failed: %m");
    else if(tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS ) {
        syslog(LOG_WARNING, "accounting msg response failed: %m");
        retval = -1;
    }

    tac_free_attrib(&attr);
    if(re.msg != NULL)
        free(re.msg);

    return retval >= 0 ? 0 : 1;
}

static char *tty, *user, hname[256];

static void init_fields(void)
{
    char *logname, mappedname[256];
    int session;
    uid_t auid;

    auid = audit_getloginuid(); /* audit_setloginuid not called */
    session = map_get_sessionid();
    mappedname[0] = '\0';

    /*
     * we do the name lookup with auid as first arg, not uid, since
     * the calling program may be invoked via sudo.
     */
    if (auid == 0 || auid == (uid_t)-1 || !session || session == -1 ||
        !(logname = lookup_mapuid(auid, auid, session, mappedname,
                sizeof mappedname))) {
        return; /* without reading config for server */
    }

    if(tacplus_config(config_file))
        fprintf(stderr, "Config file had errors, continuing\n");

    user = strdup(logname);
    if (!user)
        user = "unk_user";
    tty = ttyname(2);
    if (!tty)
        tty = "unk_tty";
    hname[0] = 0;
    gethostname(hname, sizeof hname);
    if (!*hname)
        snprintf(hname, sizeof hname, "unk_host");
}

/* 
 * Send the accounting record to the TACACS+ server.
 * This is the only global symbol in the library.
 *
 * taskid must be zero for start of command, and the
 * value returned should be passed to the end of command
 * call, so the tacacs task_id will match.
 *
 * We have to make a new connection each time, because libtac is
 * single threaded (doesn't support multiple connects at the same
 * time due to use of globals)), and doesn't have support for
 * persistent connections.
 *
 * This routine silently does nothing if no tacacs servers were
 * configured (either literally, or because the auid or session
 * aren't set and from a tacacs authenticated login).
 *
 * If a server is configured, but can't be reached, it will try
 * again on each call, resulting in about 5 second delay for
 * each call.  This shouldn't normally be a problem, unless the
 * tacacs server crashes or becomes unreachable after the tacacs
 * user logs in.
 *
 */
int
send_tacacs_acct(int taskid, char *cmdmsg)
{
    int retval, srv_i, srv_fd, type;
    uint16_t task_id;
    static int need_init = 1;

    if (need_init) {
        init_fields();
        need_init = 0;
    }

    type = taskid ?  TAC_PLUS_ACCT_FLAG_STOP : TAC_PLUS_ACCT_FLAG_START;
    task_id = taskid ? (uint16_t)taskid : tac_magic();
    if (!task_id)
        task_id++;  /* random number returned, but must not be 0 for us */

    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        srv_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
            NULL);
        if (srv_fd == -1) {
            syslog(LOG_WARNING, "error connecting to %s send acct record: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr));
            continue;
        }
        retval = send_acct_msg(srv_fd, type, user, tty, hname, cmdmsg, task_id);
        if(retval)
            syslog(LOG_WARNING, "error sending accounting record to %s: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr));
        close(srv_fd);
        if(!retval)
            break; /* only send to first responding server */
    }
    return (int)task_id; /* for cmd stop */
}
