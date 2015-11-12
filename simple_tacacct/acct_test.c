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
 * Test program for the simple_tacct library
 * Calls the accounting library entry point with 0 for start
 * of a command.  The entry point returns that taskid used, and
 * that must be passed as the first argument when the command
 * is done, so the tacacs task_id field matches in the stop and
 * start commands.
 *
 * Accounting records are only written if run from a descendent
 * of a tacacs login (auid and sessionid are set, and the user
 * lookup from libtacplus_map succeeds.
 */


#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

int main(int cnt, char **args)
{
    void *dl_handle;
    int (*acctfunc)(int, const char *);
    static const char acctlib[] = "libsimple_tacacct.so.1";
    static const char acctfn[] = "send_tacacs_acct";
    char acctline[256];
    int id;

    dl_handle = dlopen(acctlib, RTLD_NOW);

    if (!dl_handle) {
        char *err = dlerror();
        fprintf(stderr, "Unable to open tacacs accounting library %s: %s\n",
            acctlib, err);
        return 1;
    }

    acctfunc = dlsym(dl_handle, acctfn);
    if (!acctfunc) {
        char *err = dlerror();
        fprintf(stderr, "Unable to find symbol %s in %s: %s\n", acctfn,
            acctlib, err);
        return 1;
    }


    printf("enter a line of text to send as acct record\n");

    if (!fgets(acctline, sizeof acctline, stdin) || !acctline[0]) {
        fprintf(stderr, "failed to read input line\n");
        return 1;
    }

    id = acctfunc(0, acctline);
    acctfunc(id, acctline);
    return 0;
}
