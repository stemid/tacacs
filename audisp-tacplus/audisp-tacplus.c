/*
 * Copyright 2014, 2015 Cumulus Networks, inc
 *   Based on audisp-example.c by Steve Grubb <sgrubb@redhat.com>
 *     Copyright 2009 Red Hat Inc., Durham, North Carolina.
 *     All Rights Reserved.
 *
 *   TACACS+ work based on pam_tacplus.c
 *     Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 *     Jeroen Nijhof <jeroen@jeroennijhof.nl>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: olson@cumulusnetworks.com>
 *
 * This audisp plugin is used for TACACS+ accounting of commands
 * being run by users known to the TACACS+ servers
 * It uses libtac to communicate with the TACACS+ servers
 * It uses the same configuration file format as the libnss_tacplus
 * plugin (but uses the file /etc/audisp/audisp-tacplus.conf to
 * follow the audisp conventions).
 *
 * You can test it by running commands similar to:
 *   ausearch --start today --raw > test.log
 *   ./audisp-tacplus < test.log
 *
 * Excluding some init/destroy items you might need to add to main, the 
 * event_handler function is the main place that you would modify to do
 * things specific to your plugin.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <libaudit.h>
#include <auparse.h>


#include <tacplus/libtac.h>
#include <tacplus/map_tacplus_user.h>

#define _VMAJ 1
#define _VMIN 0
#define _VPATCH 0

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;

char *configfile = "/etc/audisp/audisp-tac_plus.conf";

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

/*
 * SIGTERM handler
 */
static void
term_handler(int sig __attribute__ ((unused)))
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void
hup_handler(int sig __attribute__ ((unused)))
{
        hup = 1;
}

typedef struct {
    struct addrinfo *addr;
    const char *key;
} tacplus_server_t;

/* set from configuration file parsing */
static tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
static unsigned tac_srv_no;
static char tac_service[64];
static char tac_protocol[64];
static int debug = 0;
static int acct_all; /* send accounting to all servers, not just 1st */

static const char *progname = "audisp-tacplus"; /* for syslogs and errors */

static void
audisp_tacplus_config(char *cfile)
{
    FILE *conf;
    int tac_key_no = 0;
    char lbuf[256];

    conf = fopen(cfile, "r");
    if(conf == NULL) {
        syslog(LOG_WARNING, "%s: can't open config file %s: %m",
            progname, cfile); 
        return;
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
            if(lbuf[8]) /* else treat as empty config */
                audisp_tacplus_config(&lbuf[8]);
        }
        else if(!strncmp (lbuf, "debug=", 6)) 
            debug = strtoul(lbuf+6, NULL, 0);
        else if(!strncmp (lbuf, "acct_all=", 9))
            acct_all = strtoul(lbuf+9, NULL, 0);
        else if(!strncmp (lbuf, "service=", 8))
            tac_xstrcpy (tac_service, lbuf + 8, sizeof(tac_service));
        else if(!strncmp (lbuf, "protocol=", 9))
            tac_xstrcpy (tac_protocol, lbuf + 9, sizeof(tac_protocol));
        else if(!strncmp (lbuf, "login=", 6))
            tac_xstrcpy (tac_login, lbuf + 6, sizeof(tac_login));
            
        else if(!strncmp (lbuf, "secret=", 7)) {
            /* no need to complain if too many on this one */
            if(tac_key_no < TAC_PLUS_MAXSERVERS) {
                if((tac_srv[tac_key_no].key = strdup(lbuf+7)))
                    tac_key_no++;
                else
                    syslog(LOG_ERR, "%s: unabled to copy server secret %s",
                        __FUNCTION__, lbuf+7);
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
                        "skip invalid server: %s (getaddrinfo: %s)",
                        server_buf, gai_strerror(rv));
                }
            }
            else {
                syslog(LOG_ERR, "maximum number of servers (%d) exceeded, "
                    "skipping", TAC_PLUS_MAXSERVERS);
            }
        }
        else if(debug) /* ignore unrecognized lines, unless debug on */
            syslog(LOG_WARNING, "%s: unrecognized parameter: %s",
                progname, lbuf);
    }

    if(!tac_service[0] || tac_srv_no == 0)
        syslog(LOG_ERR, "%s version %d.%d.%d: missing tacacs fields in file %s",
            progname, _VMAJ, _VMIN, _VPATCH, configfile);

    if(debug) {
        int n;
        syslog(LOG_NOTICE, "%s version %d.%d.%d", progname,
            _VMAJ, _VMIN, _VPATCH);

        for(n = 0; n < tac_srv_no; n++)
            syslog(LOG_DEBUG, "%s: server[%d] { addr=%s, key='%s' }",
                progname, n, tac_ntop(tac_srv[n].addr->ai_addr),
                tac_srv[n].key);
    }

    fclose(conf);
}


static void
reload_config(void)
{
	hup = 0;
    audisp_tacplus_config(configfile);
}

int
main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;

    /* if there is an argument, it is an alternate configuration file */
    if(argc > 1)
        configfile = argv[1];
    reload_config();

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	/* Initialize the auparse library */
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		syslog(LOG_ERR, "exitting due to auparse init errors");
		return -1;
	}
	auparse_add_callback(au, handle_event, NULL, NULL);
	do {
		/* Load configuration */
		if (hup) {
			reload_config();
		}

		/* Now the event loop */
		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0) {
			auparse_feed(au, tmp, strnlen(tmp,
						MAX_AUDIT_MESSAGE_LENGTH));
		}
		if (feof(stdin))
			break;
	} while (stop == 0);

    syslog(LOG_DEBUG, "finishing");
	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);
	auparse_destroy(au);

	return 0;
}

int
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

/* 
 * Send the accounting record to the TACACS+ server.
 *
 * We have to make a new connection each time, because libtac is single threaded
 * (doesn't support multiple connects at the same time due to use of globals)),
 * and doesn't have support for persistent connections.
 */
static void
send_tacacs_acct(char *user, char *tty, char *host, char *cmdmsg, int type,
    uint16_t task_id)
{
    int retval, srv_i, srv_fd;

    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        srv_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
            NULL);
        if (srv_fd == -1) {
            syslog(LOG_WARNING, "error connecting to %s send acct record: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr));
            continue;
        }
        retval = send_acct_msg(srv_fd, type, user, tty, host, cmdmsg, task_id);
        if(retval)
            syslog(LOG_WARNING, "error sending accounting record to %s: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr));
        close(srv_fd);
        if(!retval && !acct_all)
            break; /* only send to first responding server */
    }
}

/*
 * encapsulate the field lookup, and rewind if needed,
 * rather than repeating at each call.
 */
static const char *get_field(auparse_state_t *au, const char *field)
{
    const char *str;
    if(!(str=auparse_find_field(au, field))) {
        auparse_first_field(au);
        if(!(str=auparse_find_field(au, field))) {
            /* sometimes auparse_first_field() isn't enough, depending
             * on earlier lookup order. */
            auparse_first_record(au);
            if(!(str=auparse_find_field(au, field)))
                return NULL;
        }
    }
    return str;
}

/* find an audit field, and return the value for numeric fields.
 * return 1 if OK (field found and is numeric), otherwise 0.
 * It is somewhat smart, in that it will try from current position in case code
 * is written "knowing" field order; if not found will rewind and try again.
 */
static unsigned long
get_auval(auparse_state_t *au, const char *field, int *val)
{
    int rv;

    if(!get_field(au, field))
        return 0;
    rv = auparse_get_field_int(au);
    if (rv == -1 && errno)
        return 0;
    *val = rv;
    return 1;
}


/* 
 * Get the audit record for exec system calls, and send it off to the
 * tacacs+ server.   Lookup the original tacacs username first.
 * This just gets us the starts of commands, not the stop, which would
 * require matching up the exit system call.   For now, don't bother.
 * Maybe add some caching of usernames at some point.
 * Both auid and sessionid have to be valid for us to do accounting.
 * We don't bother with really long cmd names or really long arg lists,
 * we stop at 240 characters, because the longest field tacacs+ can handle
 * is 255 characters, and some of the accounting doesn't seem to work
 * if right at full length.
 */
static void get_acct_record(auparse_state_t *au)
{
    int val, i, llen, tlen, freeloguser=0;
    int acct_type;
    pid_t pid;
    uint16_t taskno;
    unsigned argc=0, session=0, auid;
    char *auser = NULL, *loguser, *tty = NULL, *host = NULL;
    char *cmd = NULL, *ausyscall = NULL;
    char logbuf[240], *logptr, *logbase;

    if(get_field(au, "syscall"))
        ausyscall = (char *)auparse_interpret_field(au);

    /* exec calls are START of commands, exit (including exit_group) are STOP */
    if (ausyscall && !strncmp(ausyscall, "exec", 4)) {
        acct_type = TAC_PLUS_ACCT_FLAG_START;
    }
    else if (ausyscall && !strncmp(ausyscall, "exit", 4)) {
        acct_type = TAC_PLUS_ACCT_FLAG_STOP;
    }
    else /* not a system call we care about */
        return;

    auid = session = val = 0;
    if (get_auval(au, "auid", &val))
        auid = (unsigned)val;
    if (auid == 0 || auid == (unsigned)-1) {
        /* we have to have auid for tacplus mapping */
        return;
    }
    if (get_auval(au, "ses", &val))
        session = (unsigned)val;
    if (session == 0 || session == (unsigned)-1) {
        /* we have to have session for tacplus mapping */
        return;
    }
    if (get_auval(au, "pid", &val)) {
        /*
         * Use pid so start and stop have matching taskno.  If pids wrap
         * in 16 bit space, we might have a collsion, but that's unlikely,
         * and with 16 bits, it could happen no matter what we do.
         */
        pid = (pid_t)val;
        taskno = (uint16_t) pid;
    }
    else /* should never happen, if it does, records won't match */
        taskno = tac_magic();

    if(get_field(au, "auid")) {
        auser = (char *)auparse_interpret_field(au);
    }
    if (!auser) {
        auser="unknown";
    }
    if(get_field(au, "tty"))
        tty = (char *)auparse_interpret_field(au);

    auparse_first_field(au);

    /*
     * pass NULL as the name lookup because we must have an auid and session
     * match in order to qualify as a tacacs session accounting record.  With
     * the NSS library, the username in auser will likely already be the login
     * name.
     */
    loguser = lookup_logname(NULL, auid, session, &host);
    if (!loguser) {
        char *user;

        if (auser) {
            user = auser;
        }
        else {
            auparse_first_field(au);
            if(auparse_find_field(au, "uid")) {
                user = (char *)auparse_interpret_field(au);
            }
        }
        if (!user)
            return; /* must be an invalid record */
        loguser = user;
    }
    else {
        freeloguser = 1;
    }
        

    if(get_field(au, "exe"))
        cmd = (char *)auparse_interpret_field(au);
    if (get_auval(au, "argc", &val))
        argc = (int)val;

    /*
     * could also grab "exe", since it can in theory
     * be different, and besides gives full path, so not ambiguous,
     * but not for now.
     */
    logbase = logptr = logbuf;
    tlen =  0;
    if (cmd) {
        i = 1; /* don't need argv[0], show full executable */
        llen = snprintf(logbuf, sizeof logbuf, "%s", cmd);
        if (llen >= sizeof logbuf) {
            llen = sizeof logbuf - 1;
        }
        logptr += llen;
        tlen = llen;
    }
    else
        i = 0; /* show argv[0] */
    char anum[13];
    for(; i<argc && tlen < sizeof logbuf; i++) {
        snprintf(anum, sizeof anum, "a%u", i);
        if(get_field(au, anum)) { /* should always be true */
            llen = snprintf(logptr, sizeof logbuf - tlen,
                "%s%s", i?" ":"", auparse_interpret_field(au));
            if (llen >= (sizeof logbuf - tlen)) {
                llen = sizeof logbuf - tlen;
                break;
            }
            logptr += llen;
            tlen += llen;
        }
    }

    send_tacacs_acct(loguser, tty, host?host:"UNK", logbase, acct_type, taskno);

    if (host)
        free(host);

    if(freeloguser)
        free(loguser);
}

/* This function receives a single complete event at a time from the auparse
 * library. This is where the main analysis code would be added. */
static void
handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type,
        void *user_data __attribute__ ((unused)))
{
	int type, num=0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY) {
		return;
    }

	/* Loop through the records in the event looking for one to process.
	   We use physical record number because we may search around and
	   move the cursor accidentally skipping a record. */
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
        /* we are only writing TACACS account records for syslog exec
         * records.  login, etc. are handled through pam_tacplus
         */
		switch (type) {
			case AUDIT_SYSCALL:
                get_acct_record(au);
				// for doublechecking dump_whole_record(au); 
				break;
			default:
				break;
		}
		num++;
	}
}
