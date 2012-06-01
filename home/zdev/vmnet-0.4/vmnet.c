/*
 * VMnet -- generic Virtual Network facility
 * Copyright (c) 2000 Willem Konynenberg.  All rights reserved.
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
 * Willem Konynenberg <wfk@xos.nl>
 * May 31, 2000
 *
 * This little program was written for use with the Hercules S/390
 * simulator, but might be of more general use for various virtual
 * machine programs such as VMware, User Mode Linux, or dosemu.
 *
 * It uses a SLIP connection on one side, and stdin/stdout on the other
 * to pass IP packets between the "real" network and the network device
 * of some virtual machine.
 *
 *
 * This program must be installed with setuid root permissions, so
 * it can be started by ordinary users for their virtual machines.
 * The intention is to keep this program simple enough that it can
 * be thoroughly audited for security.  Note that the script facility
 * is an inherent security risk: it is up to the administrator to
 * ensure the scripts are secure.  Better not rely on the PATH...
 *
 *
 * A configuration file is used to determine who may use what addresses.
 * Additional actions when the interface is brought up/down, like routing,
 * proxy-arp, etc, can be implemented using the script facility.
 *
 *
 * There is no facility to dymanically manage a pool of addresses (yet).
 * Every virtual machine of every user needs a separate IP address.
 *
 *
 * Having diald source code available was a big help.  It showed how
 * to set up the SLIP connection and parse/generated SLIP packets.
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>

#include "config.h"

struct buf {
	int len;
	char *ptr;
	char data[16*1024];
};

typedef struct slipconnection {
	int masterfd;
	int slavefd;
	int unit;
	int oldldisc;
	char username[128];
	char remoteip[64];
	char localip[64];
	char script[256];
} slipconn;

typedef struct {
	char username[128];
	char remoteip[64];
	char localip[64];
	char script[256];
} cfgentry;

int go = 1;

void sig_catch(int sig)
{
	/* just die gently on any signal... */
	go = 0;
}

void sig_setup()
{
	struct sigaction sa;
	sigset_t mask;

	sigemptyset(&mask);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_catch;
	sa.sa_mask = mask;
	sa.sa_flags = 0;

	sigaction(SIGHUP, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGQUIT, &sa, 0);
}

/* Read one line of data, no buffering */
int readline(int fd, char *buf, int len)
{
	int r, n = 0;

	if (len == 0) return 0;
	do {
		r = read(fd, &buf[n], 1);
		if (r <= 0) {
			return n; /* don't know what else to do */
		}
	} while (buf[n++] != '\n' && n < len);
	return n;
}

cfgentry *getcfgentry(cfgentry *cfg)
{
	static FILE *fp = NULL;
	char linebuffer[1024];
	int r;

	if (fp == NULL) {
		fp = fopen(CONFIG_FILE, "r");
		if (fp == NULL) {
			perror("Cannot open configuration file:");
			exit(1);
		}
	}

	while (1) {
		if (fgets(linebuffer, sizeof(linebuffer), fp) == NULL) {
			fclose(fp);
			fp = NULL;
			return NULL;
		}
		cfg->script[0] = '\0';
		r = sscanf(linebuffer, "%127s %63s %63s %255s\n", cfg->username,
			cfg->remoteip, cfg->localip, cfg->script);
		if (r >= 3 && cfg->username[0] != '#') {
			return cfg;
		}
	}
}

cfgentry *getcfgbyid(cfgentry *cfg, char *username, char *remoteip)
{
	while (getcfgentry(cfg) != NULL) {
		if (!strcmp(username, cfg->username)
		 && !strcmp(remoteip, cfg->remoteip)) {
			return cfg;
		}
	}
	return NULL;
}

void login(slipconn *sc)
{
	int n;
	struct passwd *pw;
	cfgentry cfg;

	pw = getpwuid(getuid());
	strncpy(sc->username, pw->pw_name, sizeof(sc->username)-1);

	n = readline(0, sc->remoteip, sizeof(sc->remoteip));
	sc->remoteip[n-1] = '\0';	/* strip newline */

	if (getcfgbyid(&cfg, sc->username, sc->remoteip) == NULL) {
		fprintf(stderr,
			"Remote IP address '%s' not found for user '%s'\n",
			sc->remoteip, sc->username);
		exit(1);
	}
	strncpy(sc->localip, cfg.localip, sizeof(sc->localip));
	strncpy(sc->script, cfg.script, sizeof(sc->script));
}

int open_pty_pair(int *masterp, int *slavep)
{
	int master, slave;
	char name[1024];

	master = getpt();
	if (master < 0) {
		return 0;
	}

	if (grantpt(master) < 0 || unlockpt(master) < 0) {
		close(master);
		return 0;
	}

	if (ptsname_r(master, name, sizeof(name)) < 0) {
		close(master);
		return 0;
	}

	slave = open(name, O_RDWR);
	if (slave < 0) {
		close(master);
		return 0;
	}

	*masterp = master;
	*slavep = slave;
	return 1;
}

void tty_setup(slipconn *sc)
{
	int speed, i;
	struct termios tios;

	if (tcgetattr(sc->slavefd, &tios) < 0) {
		perror("tcgetattr");
	}

	tios.c_cflag = CS8 | CREAD | HUPCL | CLOCAL;
	tios.c_iflag = IGNBRK | IGNPAR;
	tios.c_oflag = 0;
	tios.c_lflag = 0;
	for (i = 0; i <NCCS; i++) {
		tios.c_cc[i] = 0;
	}
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;
	
	speed = B9600;
	if (speed) {
		cfsetospeed(&tios, speed);
		cfsetispeed(&tios, speed);
	}

	if (tcsetattr(sc->slavefd, TCSANOW, &tios) < 0) {
		perror("tcsetattr");
		exit(1);
	}
}

int slip_setup(slipconn *sc)
{
	int disc, sencap = 0;

	if (ioctl(sc->slavefd, TIOCGETD, &sc->oldldisc) < 0) {
		perror("TIOCGETD");
		exit(1);
	}

	disc = N_SLIP;
	if ((sc->unit = ioctl(sc->slavefd, TIOCSETD, &disc)) < 0) {
		perror("TIOCSETD");
		exit(1);
	}

	if (ioctl(sc->slavefd, SIOCSIFENCAP, &sencap) < 0) {
		perror("SIOCSIFENCAP");
		exit(1);
	}

	if (ioctl(sc->slavefd, TIOCGETD, &disc) < 0) {
		perror("TIOCGETD");
		exit(1);
	}

	if (ioctl(sc->slavefd, SIOCGIFENCAP, &sencap) < 0) {
		perror("SIOCGIFENCAP");
		exit(1);
	}

	if (disc != N_SLIP || sencap != 0) {
		fprintf(stderr, "setup of SLIP failed\n");
		exit(1);
	}
}

void interface_start(slipconn *sc)
{
	char buf[1024];

	sprintf(buf, "%s sl%d %s pointopoint %s netmask 255.255.255.255 mtu 1500",
		IFCONFIG, sc->unit, sc->localip, sc->remoteip);
	if (*sc->script) {
		sprintf(buf+strlen(buf), " && %s up '%s' '%s'",
			sc->script, sc->remoteip, sc->localip);
	}
	system(buf);
}

void slip_start(slipconn *sc)
{
	int mfd, sfd, disc, sencap = 0;

	if (!open_pty_pair(&sc->masterfd, &sc->slavefd)) {
		perror("open_pty_pair");
		exit(1);
	}

	tty_setup(sc);
	slip_setup(sc);
	interface_start(sc);
}

void interface_stop(slipconn *sc)
{
	char buf[1024];
	int uid;

	sprintf(buf, "%s sl%d down", IFCONFIG, sc->unit);
	if (*sc->script) {
		sprintf(buf+strlen(buf), " && %s down '%s' '%s'",
			sc->script, sc->remoteip, sc->localip);
	}
	system(buf);
}

void slip_release(slipconn *sc)
{
	if (ioctl(sc->slavefd, TIOCSETD, &sc->oldldisc) < 0) {
		perror("TIOCSETD");
	}

	close(sc->masterfd);
	close(sc->slavefd);
}

void slip_stop(slipconn *sc)
{
	interface_stop(sc);
	slip_release(sc);
}

void bufread(slipconn *sc, int fd, struct buf *buf)
{
	buf->len = read(fd, buf->data, sizeof(buf->data));
	if (buf->len < 0) {
		perror("read");
		slip_stop(sc);
		exit(1);
	}
	buf->ptr = buf->data;
}

void bufwrite(slipconn *sc, int fd, struct buf *buf)
{
	int r;

	r = write(fd, buf->ptr, buf->len);
	if (r <= 0) {
		perror("write");
		slip_stop(sc);
		exit(1);
	}
	buf->len -= r;
	buf->ptr += r;
}

int main()
{
	fd_set rfds, wfds, readfds, writefds;
	int n;
	struct buf stdinbuf, stdoutbuf;
	slipconn sc;

	sig_setup();
	login(&sc);
	setuid(0);	/* set real uid to 0 for some ifconfig's */
	slip_start(&sc);

	FD_ZERO(&rfds);
	FD_SET(sc.masterfd, &rfds);
	FD_SET(0, &rfds);
	FD_ZERO(&wfds);

	while (go) {
		readfds = rfds;
		writefds = wfds;

		n = select(sc.masterfd+1, &readfds, &writefds, 0, 0);

		if (n > 0) {
			if (FD_ISSET(0, &readfds)) {
				bufread(&sc, 0, &stdinbuf);
				if (stdinbuf.len == 0) {
					/* eof on stdin */
					slip_stop(&sc);
					exit(0);
				}
				if (stdinbuf.len) {
					FD_SET(sc.masterfd, &wfds);
					FD_CLR(0, &rfds);
				}
			}
			if (FD_ISSET(sc.masterfd, &readfds)) {
				bufread(&sc, sc.masterfd, &stdoutbuf);
				if (stdoutbuf.len) {
					FD_SET(1, &wfds);
					FD_CLR(sc.masterfd, &rfds);
				}
			}
			if (FD_ISSET(sc.masterfd, &writefds)) {
				bufwrite(&sc, sc.masterfd, &stdinbuf);
				if (stdinbuf.len == 0) {
					FD_SET(0, &rfds);
					FD_CLR(sc.masterfd, &wfds);
				}
			}
			if (FD_ISSET(1, &writefds)) {
				bufwrite(&sc, 1, &stdoutbuf);
				if (stdoutbuf.len == 0) {
					FD_SET(sc.masterfd, &rfds);
					FD_CLR(1, &wfds);
				}
			}
		}
	}
	slip_stop(&sc);
	return 0;
}
