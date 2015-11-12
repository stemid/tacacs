# Introduction
This document describes how to install and configure ssh authentication using a TACACS+ server.
It is assumed that the GNU/Linux system is Centos 7.

# Prerequisites


# Installation

Begin with building and installing the libpm_tacplus library. 
The reason we have to start with lib_tacplus is because the other libraries are dependent on it.


# Configuration

## /etc/ld.so.conf.d/tacacs.conf

Create tacacs.conf and add the following content:

```
/usr/local/lib
/usr/local/lib/security
```
