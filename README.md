# Introduction
This document describes how to install and configure ssh authentication using a TACACS+ server.
It is assumed that the GNU/Linux system is Centos 7.

# Prerequisites

First make sure that the C developer tools and the development libraries for PAM and audit are installed on the system.


```
$ sudo yum install gcc
$ sudo yum install libtool
$ sudo yum install autoconf
$ sudo yum install automake

$ sudo yum install pam-devel
$ sudo yum install audit-libs-devel
```


# Installation

Begin with building and installing the libpm_tacplus library. 
The reason we have to start with lib_tacplus is because the other libraries are dependent on it.

The build and installation procedure is that same for all four libraries, after *cd* into respective
directory run the following commands:

```
$ autoreconf -i
$ ./configure
$ make
$ make install
```


# Configuration

## Dynamic loader

Create the file /etc/ld.so.conf.d/tacacs.conf with the following content:

```
/usr/local/lib
/usr/local/lib/security
```

## nsswitch.conf

Make sure the passwd section of /etc/nsswitch.conf contains the tacplus definition.
Example:

```
passwd:  tacplus files
```

## Local tacacsX users

Create 16 local users whose names are on the form tacacsX, where X is a number between 0 - 15.
Also, create a home directory for the users, but there is no need for a password.

## Define the tacacs servers

Copy the file /usr/local/etc/tacplus_servers to /etc/tacplus_servers and make sure it contains
the shared tacacs secret and the ip-address of your tacacs servers.

Example Content:
```
secret=MySuperSecretPassword1
server=192.71.124.10
secret=MySuperSecretPassword2
server=192.71.124.11
```

## Configure tacplus_nss.conf

Copy the file /usr/local/etc/tacplus_nss.conf to /etc/tacplus_nss.conf
and make sure it has the following content:
```
debug=0
service=shell
include=/etc/tacplus_servers
```

## Configure audit

Copy the file  /usr/local/etc/audisp/audisp-tac_plus.conf to /etc/audisp/audisp-tac_plus.conf
and add the following content:

```
acct_all=1
include=/etc/tacplus_servers
service=shell
```

Copy the file /usr/local/etc/audisp/plugins.d/audisp-tacplus.conf to
/etc/audisp/plugins.d/audisp-tacplus.conf and make sure it contains the following:
```
active = yes # if no, accounting is disabled
direction = out
path = /usr/local/sbin/audisp-tacplus
type = always
format = string
```


## SSH PAM Modules

Create the file /etc/pam.d/tacacs with the following content:

```
auth    sufficient /usr/local/lib/security/pam_tacplus.so include=/etc/tacplus_servers 
account sufficient /usr/local/lib/security/pam_tacplus.so include=/etc/tacplus_servers login=login protocol=ssh service=shell
session sufficient /usr/local/lib/security/pam_tacplus.so include=/etc/tacplus_servers login=login protocol=ssh service=shell
```

Then, edit /etc/pam.d/ssh and add the following line to the **top** of the file.
```
auth       include      tacacs
```
