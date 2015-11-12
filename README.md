# Introduction
This document describes how to install and configure ssh authentication using a TACACS+ server.
It is assumed that the GNU/Linux system is Centos 7.

# Prerequisites

First make sure that the audit development libraries are installed on the system.


```
$ sudo yum install audit-libs-devel

```




# Installation

Begin with building and installing the libpm_tacplus library. 
The reason we have to start with lib_tacplus is because the other libraries are dependent on it.

The build and installation procedure is that same for all four libraries, after /cd/ into each respective
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

Add the following line to /etc/nsswitch.conf

```
passwd:  tacplus files
```

## Local tacascsX users

Create 16 local users whose names are on the form tacacsX, where X is a number between 0 - 15.
Also, create a home directory for the users, but there is no need for a password.

## Define the tacacs servers

Copy the file /usr/local/etc/tacplus_servers to /etc/tacplus_servers and make sure it contains
the shared tacacs secret and the ip-address of the tacacs servers.

Example Content:
```
secret=MySuperSecretPassword1
server=192.71.124.10
secret=MySuperSecretPassword2
server=192.71.124.11
```



## SSH PAM

Create the file /etc/pam.d/tacacs.conf