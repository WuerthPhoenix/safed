# Safed Agent

## Description

Safed is the acronym of **S**ecurity **A**uditing **F**orward**E**r **D**eamon. It is an open source agent suite, based on the SNARE agent provided by Intersect Allinace. 
The existing open source basis was enhanced as follows:
- Reliability of the communication between agent and syslog server
- Resend not received logs
- Encrypted communications
- Filter events of interest
- Remote configuration API


## Repository Structure

- safed-agent: the safed agent for Linux, Sun Solaris, IBM AIX, HP-UX platforms
- safed-audit-linux: the safed component that allows safed to interoperate with the linux auditd daemon
- safed-audit-aix: the safed component that allows safed to interoperate with the IBM AIX audit component
- audit-agent-win: the safed agent for Win2003
- audit-agent-winx64: the safed agent for Win2003 for 64 processors (changes only the Visual C++ project)
- audit-agent-win8: the safed agent for Win2008/2012
- audit-agent-win8x64: the safed agent for Win2008/2012 for 64 bit processors
- audit-agent-allmsi: msi build scripts 
- includes: the header files for gnutls and regexp 
- win/x32: the gnutls and regexp library compiled for windows (32 bit processors)
- win/x64: the gnutls and regexp library compiled for windows (64 bit processors)
- win/gnutls: the gnutls 3.6 
- win/regexp: the regexp 2.7



## Installation And Configuration

The installation and configuration guide can be downloaded [here](http://www.neteye-blog.com/wp-content/uploads/2014/07/Safed_installation.pdf).


## News

News and updates can be found on this [blog](http://www.neteye-blog.com/?s=Safed&x=0&y=0&lang=en).


## Building From Source

Notes for Visual C++ projects can be found [here](http://www.neteye-blog.com/wp-content/uploads/2011/09/projectnotes.pdf).

Starting from version 1.9.0 for secure communications GnuTLS 3.6 is requested - supporting TLS 1.3 (https://gnutls.org/)

## License

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```



