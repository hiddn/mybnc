// Copyright 2005, Hidden (hidden@undernet.org) - All rights reserved

#define bncversion "4.3"

//#include <sys/select.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>


/* BNC states
	0: not authed
	1: connected. not registered
	2: fully connected to server
*/

#define NICKLEN  15
#define USERLEN  15
#define RNAMELEN 64
#define CHANLEN  300
#define HOSTLEN  63

#define MAXCHAN 50
#define IDENTLEN 32
//#define MAXCLIENTS 10
#define NUMSLOTS 15
#define TIMEOUT 15 /* TIME, in seconds, user has to auth to the bnc */
#define PASSLEN 32

#define MAXWORDS 500
#define BUFSZ 1024
#define BUFSZS 8129
#define SENDQSIZE 1048576
//#define INITSENDQSIZE 1048576


struct IPSALLOWED {
	char mask[64];
	struct IPSALLOWED *next;
} *ipsallowed;

struct CHANLIST {
	char c[CHANLEN+1];
	int qlog;
	char topic[257];
	char topicby[64];
	int topictime;
	struct CHANLIST *prev;
	struct CHANLIST *next;
} *chanlist;

struct SLOTS {
	int fd;
	int t;
	char nick[NICKLEN+1];
	char user[USERLEN+1];
	char realname[RNAMELEN+1];
	char ip[16];
	int sendinfos;
} *slots;

struct CLIENTS {
	int fd;
	struct IDENTS *ident;
	int signon;
	int rindc;
	char *bufc;
	char *obufc;

	char ip[16];
	//char *sendq;
	char *c_sendqbuf;
	int c_sendqsize;
	int DISCONNECT_CLIENT_WHEN_SENDQ_SENT;
	int SENDING_QLOG_BEFORE_DISCONNECTING;
	int lastping;
	int pingtime;
	int clientidle;
	int reattach;
	struct CLIENTS *prev;
	struct CLIENTS *next;
} *clients;

struct IDENTS {
	char ident[IDENTLEN+1];
	char ip[16];
	int fd;
	int qlog;
	int firstseen;
	int lastseen;
	struct IDENTS *prev;
	struct IDENTS *next;
} *idents;

struct {
	struct sockaddr_in vhost;
	struct sockaddr_in server;
	char servername[HOSTLEN+1]; /* As per 001 numeric */
	char serverPASSWORD[PASSLEN+1];
	char n001[256];
	char network[32];
	char nick[NICKLEN+1];
	char user[USERLEN+1];
	char realname[RNAMELEN+1];
	char ip[16];
	char listenip[16];
	char detachmsg[257];
	int recv001;
	int listenport;
	int sockfd;
	int state;
	int sendinfos;
} servinfos = {
	/* Sane Defaults(tm) */
	.vhost  = {
		.sin_family = AF_INET, .sin_port = 0,
		.sin_addr = { .s_addr = INADDR_ANY }
	},
	/*                                   htons(6667) == 2842 */
	.server = { .sin_family = AF_INET, .sin_port = 2842,
		    .sin_addr = { .s_addr = INADDR_ANY }
	},
	.servername = { '\0', }, .serverPASSWORD   = { '\0', }, .n001 = { '\0', },
	.network = { '\0', },
	.nick     = { '\0', }, .user     = { '\0', }, .realname = { '\0', },
	.ip  = { '\0', }, .listenip  = { '\0', }, .detachmsg  = { '\0', },
	.recv001 = 0,
	.listenport = 0,
	.sockfd = -1,
	.state = 0,
	.sendinfos = 1
};



static int get_addr(struct in_addr *addr, char *host)
{
	struct hostent *hent;
	hent = gethostbyname(host);
	if (!hent) {
		return -1;
	}
	memcpy(addr, hent->h_addr_list[0], sizeof(*addr));
	return 0;
}

int debug = 0;
int debugtofile = 0;

static int parse_opts(int argc, char **argv)
{
	int err = 0;
	int opt;

	while (!err && (opt = getopt(argc, argv, "df")) != -1) {
		switch (opt) {
		/*case 'h':
			err = get_addr(&servinfos.vhost.sin_addr, optarg);
			if (err == -1) {
				fprintf(stderr, "Invalid vhost: %s\n", optarg);
			}
			break;
		case 's':
			err = get_addr(&servinfos.server.sin_addr, optarg);
			if (err == -1) {
				fprintf(stderr, "Invalid server: %s\n", optarg);
			}
			break;
		case 'p':
			if (!(err = atoi(optarg))) {
				fprintf(stderr, "Invalid port: %s\n", optarg);
				err = -1;
			} else {
				servinfos.server.sin_port = htons(err);
				err = 0;
			}
			break;*/
		case 'd':
			debug = 1;
			printf("debug enabled\n");
			break;
		case 'f':
			debugtofile = 1;
			printf("debug to file enabled\n");
			break;
		case '?':
			fprintf(stderr, "Invalid option: %c\n", optopt);
			err = -1;
			break;
		case ':':
			fprintf(stderr, "Option %c requires a parameter\n", optopt);
			err = -1;
			break;
		default:
			fprintf(stderr, "I AM BUGGY!\n");
			err = -1;
		}
	}

	/*if (err == 0 && servinfos.server.sin_addr.s_addr == INADDR_ANY) {
		fprintf(stderr, "Server not specified (-s)\n");
		err = -1;
	}*/
	return err;
}



int Accept (int fd, struct sockaddr_in *sin);
int readsock (int sockfd, int tofd, char *buf, char *obuf, int bufsize, int *rind);
int readline (char *line, char **words, int maxwords, int sockfd);
int evalcom (int sockfd, char *line, char **words, int wcount);
int sendt (int sockfd, char const *format, ...) __attribute__ ((format (printf, 2, 3)));
int snotice (char const *format, ...) __attribute__ ((format (printf, 1, 2)));
int gnotice (char const *format, ...) __attribute__ ((format (printf, 1, 2)));
int iswm (char *wc, char *str);
int loadipsallowed ();
int isipallowed(char *address);
int dout (char const *format, ...) __attribute__ ((format (printf, 1, 2)));
char *fulltimestamp (time_t ltime);
int alog (char *format, ...) __attribute__ ((format (printf, 1, 2)));
int Conn();
int closeclient();
int closeserver();
//void sighup();
//void sigpipe();
int getctime();
int findlastfd();
int remchan (char *chan);
int addchan (char *chan);
int cleanchan ();
int readconf();
int addqlog (char *line);
struct CHANLIST* onchan (char *chan);
int setqlogchan (char *chan);
int clearqueue (char who);
int addqueue (int fd, char *text, int n);
int sendqueue (int fd);
int mywrite (int tofd, char *buf, int n);
int isvhostok();
char* timestamp();
char* shortts();
int qlogts(char* buf);
int sendlog (int fd, int type, int size, char *chan);
int addclient (int fd, char *ip);
int remclient_free (struct CLIENTS *c);
int remclient (int fd);
int cleanclients ();
struct CLIENTS* getclient (int fd);
int clientcount ();
int addident (char *ident);
int remident (char *ident);
int cleanidents ();
struct IDENTS* getident (char *ident);




int WAIT_TIME = 0;
int maxclients = 1;
struct CLIENTS *active_c = 0;
int rinds = 0;
//int rindc = 0;
int rinda = 0;
char *s_sendqbuf;
//char *c_sendqbuf;
//int c_sendqsize;
int s_sendqsize;
fd_set ufd;
fd_set wfd;
//fd_set efd;
char PASSWORD[PASSLEN+1];
//char **PASSWORD;
char *qlogbuf;
char *logtbuf;
char *logbuf;
int qloglen = 0;
int KEEPALIVE;
int SHORTTS = 0;
int THROTTLE = 60;
int throttle_t = 0;
//int reattach=0;
int lastfd;
int listenfd;
int connectedclient=0;
int connectedserver=0;
int incomplete = 0;
int TIMEZONE = 0;
int CMD_VHOST = 1;
int CMD_JUMP = 1;
//int DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 0;
//int SENDING_QLOG_BEFORE_DISCONNECTING = 0;
int lastping = 0;
int pingtime = 0;
int clientidle = 0;
int connecttime = 0;
int PINGFREQUENCY = 120;
int PINGTIMEOUT = 60;
int QLOGBUFSIZE = 131072;
int LOGBUFSIZE = 131072;
sig_atomic_t sig_received;
sig_atomic_t sigpipe_received;


void sighup() {
	sig_received = 1;
}
void sigpipe() {
	sigpipe_received = 1;
}
void sighupfunc() {

	signal(SIGHUP,sighup);
	dout("Received SIGHUP, reloading conf\n");
	alog("Received SIGHUP, reloading conf");

	if (readconf() == -1) {
		dout("Error reading conf\n");
		alog("Error reloading conf");
	}
	loadipsallowed();
}
void sigpipefunc() {

	signal(SIGPIPE,sigpipe);
	dout("Received SIGPIPE\n");
	alog("Received SIGPIPE");
}

int main (int argc, char **argv)
{
	int rval=0;
	struct timeval tv;
	int rc;
	struct sockaddr_in sin;
	struct sockaddr_in sin_newfd;
	const int on=1;
	int i;
	int PID;
	char *bufs;
	char *obufs;
	//char *bufc;
	//char *obufc;
	char *bufa;
	char *obufa;
	//int sendqsend=0;
	struct CLIENTS *c;
	struct CLIENTS *next;
	int go_break = 0;
	FILE *f;

	qlogbuf = 0;
	logbuf = 0;
	logtbuf = 0;
	s_sendqbuf = 0;
	//c_sendqbuf = 0;
	s_sendqsize = 0;
	//c_sendqsize = 0;
	slots = 0;

	chanlist = 0;
	clients = 0;
	idents = 0;
	sig_received = 0;
	sigpipe_received = 0;

	//memset(&servinfos, 0, sizeof(servinfos));

	if (parse_opts(argc, argv) == -1) {
		fprintf(stderr, "Usage: %s -s server [-p port] [-h vhost] [-d] [-f]\n",
			argv[0]);
			return EXIT_FAILURE;
	}

	if (readconf() == -1)
		return -1;


	//printf("listening on port %d\n", servinfos.listenport);


	if ((qlogbuf = malloc(QLOGBUFSIZE+1)) == 0) {
		dout("in function addqlog(): malloc() error\n");
		alog("in function addqlog(): malloc() error");
		return -1;
	}
	*qlogbuf = '\0';

	if ((logbuf = malloc(LOGBUFSIZE+1)) == 0) {
		dout("in function addqlog(): malloc() error\n");
		alog("in function addqlog(): malloc() error");
		return -1;
	}
	*logbuf = '\0';
	if ((logtbuf = malloc(LOGBUFSIZE+1)) == 0) {
		dout("in function addqlog(): malloc() error\n");
		alog("in function addqlog(): malloc() error");
		return -1;
	}
	*logtbuf = '\0';

	bufs = malloc(BUFSZS+1);
	if (bufs == 0) {
		alog("malloc() error");
		return -1;
	}

	obufs = malloc(BUFSZS+1);
	if (obufs == 0) {
		alog("malloc() error");
		return -1;
	}

	/*bufc = malloc(BUFSZ+1);
	if (bufc == 0) {
		alog("malloc() error");
		return -1;
	}

	obufc = malloc(BUFSZ+1);
	if (obufc == 0) {
		alog("malloc() error");
		return -1;
	}*/

	bufa = malloc(BUFSZ+1);
	if (bufa == 0) {
		alog("malloc() error");
		return -1;
	}

	obufa = malloc(BUFSZ+1);
	if (obufa == 0) {
		alog("malloc() error");
		return -1;
	}

	if (s_sendqbuf == 0) {
		if ((s_sendqbuf = malloc(SENDQSIZE+1)) == 0) {
			alog("sendqueue: malloc() failed");
			dout("sendqueue: malloc() failed\n");
			return -1;
		}
		*s_sendqbuf = '\0';
	}

	/*if (c_sendqbuf == 0) {
		if ((c_sendqbuf = malloc(SENDQSIZE+1)) == 0) {
			alog("sendqueue: malloc() failed");
			dout("sendqueue: malloc() failed\n");
			return -1;
		}
		*c_sendqbuf = '\0';
	}*/

	if (slots == 0) {
		if ((slots = malloc(sizeof(struct SLOTS)*NUMSLOTS)) == 0) {
			alog("slots: malloc() failed");
			dout("slots: malloc() failed\n");
			return -1;
		}
	}



	if (loadipsallowed() == -1) {
		fprintf(stderr, "file mybnc.allow does not exist. Add IPs allowed (no hosts) to the file, one per line. Wildcards are allowed\nexample: 192.168.0.*\n");
		return -1;
	}



	memset(slots,0,sizeof(struct SLOTS)*NUMSLOTS);
	for (i=0; i<NUMSLOTS; i++) {
			slots[i].fd = -1;
		}
	//memset(clients,0,sizeof(struct CLIENTS)*MAXCLIENTS);
	memset(&sin,0,sizeof(sin));
	memset(&sin_newfd,0,sizeof(sin_newfd));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;


	if (*servinfos.listenip != '\0') {
		if (get_addr(&sin.sin_addr, servinfos.listenip) == -1) {
			alog("error: get_addr() for listenip");
			exit(1);
		}
	}
	sin.sin_port = htons(servinfos.listenport);
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    	perror("setsockopt");
    	exit(1);
	}
	if (bind(listenfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(listenfd,NUMSLOTS) == -1) {
		perror("listen");
		exit(1);
	}

	lastfd = listenfd;
	printf("listening on port %d\n", servinfos.listenport);

	if (debug == 0) {
		if ((PID = fork())) {
			printf("going to backgound, PID=%d\n", PID+1);
			//alog("going to backgound, PID=%d", PID+1);
			return 0;
		}
		if (fork()) {
			umask(0);
			close(fileno(stdin));
			close(fileno(stdout));
			close(fileno(stderr));
			return 0;
		}
	}

	alog("going to backgound, PID=%d", getpid());

	if ((f = fopen("mybnc.pid", "w")) == NULL) {
		alog("error: fopen() for mybnc.pid\n");
		printf("error: fopen() for mybnc.pid\n");
		exit(1);
	}
	fprintf(f, "%d\n", (int) getpid());
	fclose(f);


	if (debugtofile) {
		dout("\n\n\n\n\n");
		dout("----- Program started ! -----\n\n");
	}

	signal(SIGHUP,sighup);
	signal(SIGPIPE,sigpipe);
	findlastfd();


	do {
		//sendqsend=0;
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		if (sig_received == 1) {
			sig_received = 0;
			sighupfunc();
		}
		if (sigpipe_received == 1) {
			sigpipe_received = 0;
			sigpipefunc();
		}

		FD_ZERO(&ufd);
		FD_ZERO(&wfd);
		FD_SET(listenfd,&ufd);

		c = clients;
		while (c != 0) {
			active_c = c;
			next = c->next;

			if ((active_c != 0) && (c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT > 1)) {
				if ((getctime() - c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT) > 7) {
					closeclient();
				}
			}

			if ((active_c != 0) && (KEEPALIVE)) {
				if (connectedserver) {
					if ((c->pingtime > 0) && ((getctime() - c->pingtime) > 0)) {
						//ping timeout
						snotice("PING TIMEOUT (after %d seconds)", PINGTIMEOUT);
						sendt(c->fd, "ERROR :Ping timeout");
						if (KEEPALIVE == 1) {
							if (clientcount() < 2) {
								sendt(servinfos.sockfd, "away :%s", servinfos.detachmsg);
								dout("sending detach msg ...\n");
							}
						}
						else {
							sendt(servinfos.sockfd, "quit :Ping timeout");
							closeserver();
						}
						closeclient();
					}
					if ((active_c != 0) && (c->clientidle > 0) && ((getctime() - c->lastping) > PINGFREQUENCY) && ((getctime() - c->clientidle) > PINGFREQUENCY)) {
						//sendt(servinfos.clientfd,"PING :mybnc");
						sendt(c->fd,"PING :mybnc");
						c->pingtime = getctime() + PINGTIMEOUT;
						c->lastping = getctime();
					}
				}
			}

			if ((connectedclient == 1) && (active_c != 0)) {
				FD_SET(c->fd,&ufd);
				if (*c->c_sendqbuf != '\0') {
					FD_SET(c->fd,&wfd);
					//sendqsend=1;
				}
			}
			c = next;
			if (clientcount() == 0)
				c = 0;
		}
		active_c = 0;

		if (connectedserver == 1) {
			FD_SET(servinfos.sockfd,&ufd);
			if (*s_sendqbuf != '\0') {
				FD_SET(servinfos.sockfd,&wfd);
				//sendqsend=1;
			}
		}

		for (i=0; i < NUMSLOTS; i++) {
			if (slots[i].fd > -1) {
				if ((getctime() - slots[i].t) > TIMEOUT) {
					sendt(slots[i].fd, "NOTICE auth :Timeout");
					close(slots[i].fd);
					//FD_CLR(slots[a].fd, &ufd);
					slots[i].fd = -1;
				}
				else {
					FD_SET(slots[i].fd,&ufd);
				}
			}
		}


		findlastfd();

		//if (sendqsend)
			rc = select(lastfd+1,&ufd,&wfd,NULL,&tv);
		//else
		//	rc = select(lastfd+1,&ufd,NULL,NULL,&tv);

		if (rc < 0) {
			if (errno == EINTR) {
				dout("select(): Interrupted system call\n");
				errno=0;
				continue;
			}
			alog("select() error %d: %s", errno, strerror(errno));
			perror("select");
			break;
		}

		if (rc == 0)
			continue;


		/*if (*c_sendqbuf != '\0')
			sendqueue(servinfos.clientfd);
		if (*s_sendqbuf != '\0')
			sendqueue(servinfos.sockfd);
		*/



		if (connectedserver == 1) {
			if (FD_ISSET(servinfos.sockfd,&wfd)) {
				//dout("Oh oh! Server socket ready to write!\n");
				sendqueue(servinfos.sockfd);
			}
			if (FD_ISSET(servinfos.sockfd,&ufd)) {
				if ((rval = readsock(servinfos.sockfd,-100, bufs, obufs, BUFSZS, &rinds)) == -1) {
					alog("Lost connection to server");
					dout("Lost connection to server\n");
					if (connectedclient == 1)
						gnotice("Lost connection to server");
					closeserver();
					//closeclient();
					cleanclients();
					findlastfd();
					rval=0;
				}
				if (rval == -3)
					rval=0;
			}
		}
		c = clients;
		while (c != 0) {
			active_c = c;
			next = c->next;


			if (connectedclient == 1) {
				if (FD_ISSET(c->fd,&wfd)) {
					//dout("Oh oh! Client socket ready to write!\n");
					sendqueue(c->fd);
				}
				if (FD_ISSET(c->fd,&ufd)) {
					if ((rval = readsock(c->fd,servinfos.sockfd, c->bufc, c->obufc, BUFSZ, &c->rindc)) == -1) {
						alog("Lost connection from client");
						dout("Lost connection from client\n");
                                                if (KEEPALIVE != 1) {
							if (connectedserver == 1)
								sendt(servinfos.sockfd, "quit :Lost connection from client");
							closeserver();
						}
						if (KEEPALIVE == 1) {
							if (clientcount() < 2) {
								sendt(servinfos.sockfd, "away :%s", servinfos.detachmsg);
								dout("sending detach msg ...\n");
							}
						}
						closeclient();
						findlastfd();
						rval=0;
					}
					if (rval == -3)
						rval=0;
					if (rval == -2) {
						go_break = 1;
						break;
					}
				}
			}
			c = next;
			if (clientcount() == 0)
				c = 0;
		}
		active_c = 0;
		if (go_break == 1)
			break;

		for (i=0; i < NUMSLOTS; i++) {
			if (slots[i].fd > -1) {
				if (FD_ISSET(slots[i].fd,&ufd)) {
					if ((rval = readsock(slots[i].fd,0, bufa, obufa, BUFSZ, &rinda)) <= -1) {
						close(slots[i].fd);
						slots[i].fd = -1;
						findlastfd();
						rval=0;
						if (rval < -1) {
							alog("umm, error: rval=%d", rval);
							rval=0;
						}
					}
				}
			}
		}

		if (FD_ISSET(listenfd,&ufd)) {
			Accept(listenfd, &sin_newfd);
			findlastfd();
		}

		if (rval < 0) {
			alog("looking for the bug ? rval = %d ...", rval);
		}
	} while (rval >= 0);

	alog("Bnc dies now!");
	closeserver();
	//closeclient();
	cleanclients();
	close(listenfd);

	for (i=0; i < NUMSLOTS; i++) {
		if (slots[i].fd > -1) {
			close(slots[i].fd);
		}
	}

	free(bufs);
	free(obufs);
	//free(bufc);
	//free(obufc);
	free(bufa);
	free(obufa);
	dout("Success!\n");
	return EXIT_SUCCESS;
}

int isvhostok()
{
	int sockfd;

	if ((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1) {
		alog("socket error");
		dout("socket error\n");
		perror("socket");
		return EXIT_FAILURE;
	}


	if (bind(sockfd,(struct sockaddr *)&servinfos.vhost, sizeof(servinfos.vhost)) == -1) {
	     //perror("bind");
		 alog("bind() error");
		 dout("bind() error");
		 close(sockfd);
	     return -1;
	}
	close(sockfd);
	return 1;

}

int Conn()
{
	int sockfd;
	int flags;
	int select_ret;
	socklen_t len = sizeof(int);
	int error = 0;
	struct timeval tv;
	struct CLIENTS *c = active_c;
	fd_set s_wfd;

	cleanchan();


	if ((throttle_t) && ((getctime() - throttle_t) < THROTTLE)) {
		gnotice("Throttled. %d seconds left", (THROTTLE - (getctime() - throttle_t)));
		return -1;
	}

	if ((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1) {

		alog("socket error");
		dout("socket error\n");
		perror("socket");
		return EXIT_FAILURE;
	}


	if (bind(sockfd,(struct sockaddr *)&servinfos.vhost, sizeof(servinfos.vhost)) == -1) {
	     //perror("bind");
		 alog("bind() error");
		 dout("bind() error");
		 if (connectedclient)
			 gnotice("Could not bind to vhost");
		 close(sockfd);
	     return EXIT_FAILURE;
	}

	alog("Connecting to %s:%d ...\n", inet_ntoa(servinfos.server.sin_addr), ntohs(servinfos.server.sin_port));
	gnotice("Connecting to %s:%d ...", inet_ntoa(servinfos.server.sin_addr), ntohs(servinfos.server.sin_port));

	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	if (connect(sockfd, (struct sockaddr *)&servinfos.server, sizeof(struct sockaddr)) == -1) {
		if(errno != EINPROGRESS) {
			//perror("connect");
			gnotice("Connection to server failed");
			dout("error connecting\n");
			//closeserver();
			//return EXIT_FAILURE;
			close(sockfd);
			return -1;
		}
	}


	FD_ZERO(&s_wfd);
	FD_SET(sockfd, &s_wfd);

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	select_ret = select(sockfd + 1, NULL, &s_wfd, NULL, &tv);

	if ((select_ret == -1) || (select_ret == 0)) {
		dout("error connecting\n");
		if (select_ret == -1)
			gnotice("Connection to server failed");
		if (select_ret == 0)
			gnotice("Connection to server timed out");
		close(sockfd);
		return -1;
	}

	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
		dout("error connecting\n");
		close(sockfd);
		return -1;
	}
	if ((error == EINPROGRESS) || (error == ECONNREFUSED)) {
		dout("error connecting\n");
		if (error == ECONNREFUSED)
			gnotice("Connection refused");
		else
			gnotice("Connection error - EINPROGRESS");
		close(sockfd);
		errno = error;
		return -1;
	}

	//servinfos.sockfd = sockfd;

	dout("Connected (select_ret=%d)\n", select_ret);
	gnotice("Connected to server");
	servinfos.state = 1;

	connectedserver = 1;
	connecttime = getctime();
	lastping = connecttime;
	pingtime = 0;

	if (*servinfos.serverPASSWORD != 0) {
		sendt(sockfd, "PASS %s", servinfos.serverPASSWORD);
		dout("Password sent: %s\n", servinfos.serverPASSWORD);
	}

	if ((servinfos.sendinfos == 1) && (strlen(servinfos.nick) > 0) && (c->reattach == 0)) {
		//dout("bug spotter 1 (hope to see 2 soon)\n");
		sendt(sockfd,"NICK %s", servinfos.nick);
		sendt(sockfd,"USER %s 0 0 :%s", servinfos.user, servinfos.realname);
		//dout("bug spotter 2\n");
	}
	c->reattach=0;
	fcntl(sockfd, F_SETFL, O_NONBLOCK);
	findlastfd();
	return sockfd;
}

int closeclient()
{
	struct CLIENTS *c = active_c;

	//c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 0;
	//c->SENDING_QLOG_BEFORE_DISCONNECTING = 0;
	if (c->fd > -1) {
		//FD_CLR(servinfos.clientfd,&ufd);
		close(c->fd);
	}

	*c->c_sendqbuf = '\0';
	c->c_sendqsize = 0;
	if (clientcount() == 1)
		servinfos.state = 0;
	//servinfos.clientfd = -1;
	connectedclient = 0;
	/*c->pingtime=0;
	c->lastping=0;
	c->clientidle=0;
	c->rindc = 0;*/
	findlastfd();
	clearqueue('c');

	remclient(c->fd);
	if (clients != 0)
		connectedclient = 1;
	active_c = 0;
	return 0;
}

int closeserver()
{
	if (servinfos.sockfd > -1) {
		//FD_CLR(servinfos.sockfd,&ufd);
		close(servinfos.sockfd);
	}
	*s_sendqbuf = '\0';
	s_sendqsize = 0;
	connectedserver = 0;
	connecttime = 0;
	servinfos.state = 0;
	servinfos.sockfd = -1;
	//*(servinfos.nick) = '\0';
	//closeclient();
	rinds = 0;
	findlastfd();
	clearqueue('s');
	return 0;
}

int Accept (int fd, struct sockaddr_in *sin)
{
	int newfd;
	socklen_t sinsize;
	int i=0;

	dout("Accept() called!\n");

	sinsize = sizeof(struct sockaddr_in);
	memset(sin,0,sinsize);
	newfd = accept(fd, (struct sockaddr *)sin, &sinsize);
	dout("newfd=%d\n", newfd);
	if (newfd == -1) {
		perror("accept");
		alog("accept() error: (%d) %s", errno, strerror(errno));
		return -1;
	}
	fcntl(newfd, F_SETFL, O_NONBLOCK);

	while (i < NUMSLOTS) {
		if (slots[i].fd == -1)
			break;
		i++;
	}

	if (i == NUMSLOTS) {
		//All connections in use
		sendt(newfd, "ERROR :All bnc connections in use");
		close(newfd);
		findlastfd();
		return -1;
	}


	dout("accept() successful for %s\n", inet_ntoa(sin->sin_addr));
	if (isipallowed(inet_ntoa(sin->sin_addr)) == 0) {
		dout("... Declined. IP not allowed\n");
		//sendt(servinfos.clientfd, ":mybnc!mybnc@127.0.0.1 NOTICE %s :Connection attempt from %s refused", servinfos.nick, inet_ntoa(sin->sin_addr));
		gnotice("Connection attempt from %s refused", inet_ntoa(sin->sin_addr));
		close(newfd);
		findlastfd();
		return -1;
	}
	if ((connectedclient) && (WAIT_TIME <= (getctime() - connecttime)))
		//sendt(servinfos.clientfd, ":mybnc!mybnc@127.0.0.1 NOTICE %s :Connection attempt from %s accepted, ip authorised", servinfos.nick, inet_ntoa(sin->sin_addr));
		gnotice("Connection attempt from %s accepted, ip authorized", inet_ntoa(sin->sin_addr));

	slots[i].sendinfos = 0;
	slots[i].fd = newfd;
	slots[i].t = getctime();
	*(slots[i].nick) = '\0';
	*(slots[i].user) = '\0';
	*(slots[i].realname) = '\0';
	strcpy(slots[i].ip,inet_ntoa(sin->sin_addr));
	return newfd;
}

static char *next_eol(char *start, char *end) {
	do {
		if (*start == '\n') {
			return (start - 1);
		}
	} while (++start < end);
	return NULL;
}


int readsock (int sockfd, int tofd, char *buf, char *obuf, int bufsize, int *rind)
{
	static char** words=0;
	char *eol;
	int last_eol;
	int n;
	int a;
	int i;
	struct CLIENTS *c = getclient(sockfd);


		int wcount;

		if (words == 0) {
			words = malloc(sizeof(char *) * (MAXWORDS+1));
			if (words == 0) {
				alog("malloc() error");
				return -1;
			}

		}

		n = read(sockfd, buf+*rind, bufsize - *rind - 1);
		if (n == -1) {
			dout("read error %d: %s\n", errno, strerror(errno));
			if ((errno == EINTR) || (errno == EAGAIN)) {
				errno = 0;
				return -3;
			}
			return -1;
		}

		if ((errno == EINTR) || (errno == EAGAIN)) {
			dout("ummmm, read error %d ?: %s\n", errno, strerror(errno));
			errno=0;
		}
		if (n == 0) {
			return -1;
		}
		memcpy(obuf+*rind,buf+*rind,n);
		*(buf+*rind+n) = '\0';
		*(obuf+*rind+n) = '\0';

			/*dout("line1 (len=%d) (n=%d): %s\n", strlen(buf+*rind), n, buf+*rind);
			for (i=0; i<n; i++) {
				dout("%d> %d\t", i, *(buf+*rind+i));
			}
			dout("\n");*/


		if (n > strlen(buf+*rind)) {
			if ((n - strlen(buf+*rind)) > 1)
				alog("data received contained a NULL char. Ignoring the %zu chars after", (n - strlen(buf+*rind)));
			for (i=0; i<(n-1); i++) {
				if (*(buf+*rind+i) == '\0') {
					if (*(buf+*rind+i-1) != '\n') {
						*(buf+*rind+i) = '\n';
						*(obuf+*rind+i) = '\n';
						*(buf+*rind+i+1) = '\0';
						*(obuf+*rind+i+1) = '\0';
					}
					i = n;
				}
			}
			n = strlen(buf+*rind);
		}

		*rind += n;


                /* Moved the following to the readline() function 
		if (servinfos.state > 0) {
			//if (tofd == servinfos.clientfd) {
			if (servinfos.sockfd == sockfd) {
				c = clients;
				while (c != 0) {
					active_c = c;
					bytessent = mywrite(c->fd,buf+*rind-n,n);
					c = c->next;
				}
				active_c = 0;
			}
		}
                */

                //errno=0;

		last_eol = -2;
		/* Handle all lines in the buffer */
		while ((eol = next_eol(buf + last_eol+2, &buf[*rind]))) {
			if (*(eol + 1) == '\n') {
				if ((*eol == '\r')) {
					i=0;
				}
				else {
					i=1;
				}
				while ((*(eol + i) == '\n') || (*(eol + i) == '\r')) {
					*(eol + i) = '\0';
					*(obuf + (eol - buf) + i) = '\0';
					i++;
				}

			}
			/* Handle the just-terminated line */
			//memcpy(obuf + last_eol+2,buf + last_eol+2,strlen(buf + last_eol+2)+1);

			/*dout("line2 (len=%d): %s\n", strlen(buf+last_eol+2), buf+last_eol+2);
			for (i=0; i<strlen(buf + last_eol+2); i++) {
				dout("%d> %d\t", i, *(buf+last_eol+2+i));
			}
			dout("\n");*/

			wcount = readline(buf + last_eol+2, words, MAXWORDS, sockfd);
			if (wcount >= 0) {
				if ((a = evalcom(sockfd, obuf + last_eol+2, words, wcount)) == -2) {
					return -2;
				}
				if (a == 100)
					if (connectedserver == 1)
						sendt(servinfos.sockfd, "%s\r\n", obuf + last_eol+2);
			}
			last_eol = (eol - buf);

			if ((getclient(sockfd) == 0) && (c != 0)) {
				//dout("readsock(): probably a /conn was issued\n");
				return 0;
			}
		}


		/* No more EOL's in the buffer */

		/* If there were any lines in the buffer, we may flip the
		 * buffer around so that we get more room into it. We'll also
		 * have to adjust the destination index for the next read to
		 * handle leftover bytes
		 */
		if (last_eol >= 0) {
			int shift = last_eol + 2;
			memmove(buf, buf + shift, bufsize - shift + 1);
			memmove(obuf, obuf + shift, bufsize - shift + 1);
			*rind -= shift;
		}


		return 0;
}


int readline (char *line, char **words, int maxwords, int sockfd)
{
	int wind = -1;
	char *tokstart;
	struct CLIENTS *c = getclient(sockfd);
        static char *buf = 0;
	int buflen = 0;

        if (buf == 0) {
		buf = malloc(sizeof(char) * 2048);
		if (buf == 0) {
			alog("malloc() error");
			exit(1);
		}
        }
	if (c != 0) {		
		dout("[Client] %s\n", line);
	}
	else if (sockfd == servinfos.sockfd) {
		//dout("[Server] %s\n", line);
	}
	else if (sockfd == -10) {
	}
	else {
		dout("[not-authed] %s\n", line);
	}

	if (servinfos.state > 0) {
		//if (tofd == servinfos.clientfd) {
		if (servinfos.sockfd == sockfd) {
			if ((buflen = strlen(line)) > 2045) {
				alog("readline(): line too long (>2045). Line is: %s", line);
				strncpy(buf, line, 2045);
				buf[2045] = '\r';
				buf[2046] = '\n';
				buf[2047] = '\0';				
			}
			else {
				strncpy(buf, line, 2045);
				buf[buflen++] = '\r';
				buf[buflen++] = '\n';
				buf[buflen] = '\0';
			}
			c = clients;
			while (c != 0) {
				active_c = c;
				mywrite(c->fd,buf,buflen);
				c = c->next;
			}
			active_c = 0;
		}
	}
        
	tokstart = line;
	while (*tokstart) {
		words[++wind] = tokstart++;
		if (wind == maxwords) {
			return wind;
		}
		while (*tokstart && *tokstart != ' ') tokstart++;
		if (*tokstart) {
			*tokstart++ = '\0';
		}
		while (*tokstart == ' ') tokstart++;
	}

	return wind;
}


#define MAX_OUT_PAYLOAD 1024
#define MAX_OUT_PAYLOAD2 512

int sendt (int sockfd, char const *format, ...)
{
	va_list vl;
	int nchars, sent;
	//char outbuf[MAX_OUT_PAYLOAD+3];
	int i;
	static char *outbuf = 0;
	struct CLIENTS *c = getclient(sockfd);

	if (outbuf == 0) {
		i = MAX_OUT_PAYLOAD+3;
		if ((outbuf = malloc(i)) <= 0) {
			dout("iswm(): malloc() error\n");
			alog("iswm(): malloc() error");
			exit(0);
		}
		memset(outbuf,0,i);
		i=0;
	}

	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_OUT_PAYLOAD, format, vl);
	va_end(vl);

	if (nchars >= MAX_OUT_PAYLOAD) {
		dout("Output got truncated!\n");
		nchars = MAX_OUT_PAYLOAD;
	}
	outbuf[nchars++] = '\r';
	outbuf[nchars++] = '\n';
	outbuf[nchars] = '\0'; /* Since we print it */
	//dout("sendt(): nchars=%d and strlen(outbuf)=%d\n", nchars, strlen(outbuf));
	nchars = strlen(outbuf);

	if (c != 0)
		dout("BNC-to-Client: %s", outbuf);
	sent = mywrite(sockfd, outbuf, nchars);
	if (sent != nchars) {
		//alog("Write error: sentbytes=%d (err=%d) %s", sent, errno, strerror(errno));
		//dout("Write error: sentbytes=%d (err=%d) %s\n", sent, errno, strerror(errno));
		/*if ((sockfd == servinfos.sockfd) || (sockfd == servinfos.clientfd)) {
			if (sent <= 0) {
				addqueue(sockfd,outbuf,nchars);
			}
			else {
				addqueue(sockfd,outbuf+sent,nchars-sent);
			}
		}*/
		//else {
		if ((sockfd != servinfos.sockfd) && (c == 0)) {
			for (i=0; i < NUMSLOTS; i++) {
				if (slots[i].fd == sockfd) {
					close(slots[i].fd);
					slots[i].fd = -1;
					findlastfd();
					break;
				}
			}
		}
	}
	return sent;
}

int snotice (char const *format, ...)
{
	va_list vl;
	int nchars;
	int i;
	static char *outbuf = 0;
	struct CLIENTS *c = active_c;


	if (outbuf == 0) {
		i = MAX_OUT_PAYLOAD+3;
		if ((outbuf = malloc(i)) <= 0) {
			dout("iswm(): malloc() error\n");
			alog("iswm(): malloc() error");
			exit(0);
		}
		memset(outbuf,0,i);
		i=0;
	}

	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_OUT_PAYLOAD, format, vl);
	va_end(vl);

	if (nchars >= MAX_OUT_PAYLOAD) {
		dout("Output got truncated!");
		nchars = MAX_OUT_PAYLOAD;
		outbuf[MAX_OUT_PAYLOAD] = '\0';
	}

	if (c == 0) {
		alog("Error: bad use in snotice() function: %s", outbuf);
		exit(1);
	}

	return sendt(c->fd, ":my.bnc NOTICE %s :%s", servinfos.nick, outbuf);
}

int gnotice (char const *format, ...)
{
	va_list vl;
	int nchars;
	int i;
	static char *outbuf = 0;
	struct CLIENTS *c = clients;


	if (outbuf == 0) {
		i = MAX_OUT_PAYLOAD+3;
		if ((outbuf = malloc(i)) <= 0) {
			dout("iswm(): malloc() error\n");
			alog("iswm(): malloc() error");
			exit(0);
		}
		memset(outbuf,0,i);
		i=0;
	}

	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_OUT_PAYLOAD, format, vl);
	va_end(vl);

	if (nchars >= MAX_OUT_PAYLOAD) {
		dout("Output got truncated!");
		nchars = MAX_OUT_PAYLOAD;
		outbuf[MAX_OUT_PAYLOAD] = '\0';
	}

	while (c != 0) {
		if (c->fd)
			i = sendt(c->fd, ":my.bnc NOTICE %s :%s", servinfos.nick, outbuf);
		c = c->next;
	}

	return i;
}

int evalcom (int sockfd, char *line, char **w, int wcount)
{
	char rname[RNAMELEN+1];
	int i=0;
	int a=0;
	int sent=0;
	struct CHANLIST *cptr;
	char str[64];
	int passok = 0;
	int nogo = 0;
	int iscprivmsg = 0;
	char *ptr;
	static char *buf = 0;
	char *crypt ();
	struct CLIENTS *c = getclient(sockfd);
	struct CLIENTS *x;
	struct IDENTS *idptr;

	if (buf == 0) {
		buf = malloc(sizeof(char) * BUFSZ);
		if (buf == 0) {
			alog("evalcom(): malloc() error");
			return 0;
		}
	}

	rname[0] = 0;


	/************ ***************/
	/**** Non-authed clients ****/
	/************ ***************/

	if ((sockfd != servinfos.sockfd) && (c == 0)) {
		for (a=0; a < NUMSLOTS; a++) {
			if (slots[a].fd == sockfd) {
				break;
			}
		}
		if (a == NUMSLOTS) {
			dout("Receiving data from a ghost. Are you high ? -> sockfd=%d\n", sockfd);
			alog("Receiving data from a ghost. Are you high ? -> sockfd=%d", sockfd);
			//close(sockfd);
			return -2;
		}
		if ((strcasecmp(w[0], "NICK") == 0) && (wcount == 1)) {
			strncpy(slots[a].nick,w[1],NICKLEN);
			slots[a].nick[NICKLEN] = '\0';
		}
		if ((strcasecmp(w[0], "USER") == 0) && (wcount > 3)) {
			strncpy(slots[a].user,w[1], USERLEN);
			slots[a].user[USERLEN] = '\0';
			strncpy(rname,&w[4][1],RNAMELEN);
			i=5;
			while(i <= wcount) {
				if ((RNAMELEN - strlen(rname)) > 2) {
					strcat(rname, " ");
					strncat(rname, w[i], (RNAMELEN - strlen(rname)));
				}
				i++;
			}
			rname[RNAMELEN] = '\0';
			dout("rname = %s\n", rname);
			strcpy(slots[a].realname, rname);
			slots[a].sendinfos = 1;
		}
		if ((strcasecmp(w[0], "PASS") == 0) && (wcount >= 1)) {
			if (PASSWORD[0] == '+') {
				strncpy(str, &PASSWORD[1], 2);
				str[2] = 0;
				if (strcasecmp(crypt(w[1], str), &PASSWORD[1]) == 0)
					passok = 1;
				else
					passok = 0;
			}
			else if (strcasecmp(w[1], PASSWORD) == 0) {
				passok = 1;
			}
			if ((passok) && (maxclients > 1) && (clientcount() == maxclients)) {
				sendt(sockfd, "NOTICE auth :Too many connections. Increase maxclients in conf");
				close(sockfd);
				slots[a].fd = -1;
				findlastfd();
			}
			else if ((passok) && (maxclients > 1) && (clientcount() > 0) && (WAIT_TIME > (getctime() - connecttime))) {
				sendt(sockfd, "NOTICE auth :The bnc is allowing only 1 client to connect during connection to server. Please wait %d seconds", (WAIT_TIME - (getctime() - connecttime)));
				close(sockfd);
				slots[a].fd = -1;
				findlastfd();
			}
			else if (passok) {
				if (debugtofile) {
					dout("\n\n");
					dout("----- Password accepted from %s -----\n", slots[a].ip);
				}


				if (*slots[a].nick == '\0')
					alog("(fd=%d) Password accepted from %s", slots[a].fd, slots[a].ip);
				else
					alog("(fd=%d) Password accepted from %s (%s)", slots[a].fd, slots[a].ip, slots[a].nick);
				if (connectedclient == 1) {
					//sendt(servinfos.clientfd, ":mybnc!mybnc@127.0.0.1 NOTICE %s :New client connected: %s", servinfos.nick, slots[a].ip);
					gnotice("Password accepted from %s", slots[a].ip);
					if ((connectedserver) && (KEEPALIVE == 0)) {
						sendt(servinfos.sockfd, "quit :ghosted client");
						closeclient();
					}
				}
				//closeclient();
				if (maxclients == 1)
					cleanclients();
				strcpy(servinfos.ip, slots[a].ip);
				addclient(slots[a].fd, slots[a].ip);
				c = getclient(slots[a].fd);
				active_c = c;
				//c->fullyconnected = 0;
				//sendt(sockfd, "NOTICE AUTH :Password accepted");
				sendt(sockfd, ":my.bnc NOTICE %s :Password accepted. mybnc v%s", servinfos.nick, bncversion);
				sendt(sockfd, ":my.bnc NOTICE %s :For help, type /bnchelp", servinfos.nick);
				if ((debugtofile == 1) || (debug == 1))
					sendt(sockfd, ":my.bnc NOTICE %s :%cThis bnc is currently in DEBUG MODE%c", servinfos.nick, 2, 2);
				dout(".-10.\n");
				c->clientidle = getctime();
				dout(".-9.\n");



				if (wcount > 1) {
					if (CMD_JUMP == 0) {
						sendt(sockfd, "NOTICE AUTH :JUMP disabled");
					}
					else {
						if (get_addr(&servinfos.server.sin_addr, w[2]) == -1) {
							sendt(sockfd, "NOTICE AUTH :Invalid server: %s", w[2]);
						}
						else {
							if (wcount > 2) {
								if (!(atoi(w[3]))) {
									sendt(sockfd, "NOTICE AUTH :Invalid port: %s", w[3]);
									nogo = 1;
								} else {
									servinfos.server.sin_port = htons(atoi(w[3]));
								}
							}
							if (wcount > 3) {
								strncpy(servinfos.serverPASSWORD, w[4], PASSLEN);
								servinfos.serverPASSWORD[PASSLEN] = '\0';
							}
							if (nogo == 0) {
								sendt(servinfos.sockfd, "QUIT :jump!");
								//sendt(sockfd, "NOTICE AUTH :Connecting to %s:%s", w[2], w[3]);
								gnotice("Connecting to %s:%s", w[2], w[3]);
								alog("JUMPING TO %s:%s", w[2], w[3]);
								dout("JUMPING TO %s:%s\n", w[2], w[3]);
								closeserver();
								cleanclients();
							}
						}
					}
				}


				dout(".-8.\n");

				if ((KEEPALIVE == 1) && ((connectedserver == 1) || ((*qlogbuf != '\0') && (maxclients == 1)))) {
					dout(".-7.\n");
					c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 0;
					//reattach=1;
					c->reattach=1;
					c->lastping = getctime();
					c->pingtime = 0;
					//servinfos.clientfd = slots[a].fd;
					if (connectedserver == 1) {
						if (clientcount() < 2) {
							sendt(servinfos.sockfd, "away");
						}
						else if ((*servinfos.nick == 0) || (*servinfos.user == 0) || (servinfos.recv001 == 0)) {
							snotice("Another client is currently connecting. Try again in a few seconds");
							slots[a].fd = -1;
							closeclient();
							return 0;
						}
					}


					sendt(sockfd, "%s 001 %s :Welcome to the %s IRC Network via mybnc, %s!%s@%s", servinfos.servername, servinfos.nick, servinfos.network, servinfos.nick, servinfos.user, c->ip);
					sendt(sockfd, "%s 376 %s :End of /MOTD command.", servinfos.servername, servinfos.nick);
					//sendt(sockfd, "%s NOTICE %s :on 6 ca 1(4) ft 10(10) tr", servinfos.servername, servinfos.nick);
					if (connectedserver == 1) {
						sendt(servinfos.sockfd, "mode %s", servinfos.nick);
					}
					if (*slots[a].user != 0)
						servinfos.state = 2;
					else
						servinfos.state = 1;
					cptr = chanlist;
					while (cptr != 0) {
						sendt(sockfd, ":%s!%s@%s JOIN %s", servinfos.nick, servinfos.user, c->ip, cptr->c);
						if (strlen(cptr->topic) > 1) {
							dout("Sending topic for %s\n", cptr->c);
							dout(": %s", cptr->topic);
							dout(" (%s)", cptr->topicby);
							dout(" (%d)\n", cptr->topictime);
							sendt(sockfd, "%s 332 %s %s %s", servinfos.servername, servinfos.nick, cptr->c, cptr->topic);
							sendt(sockfd, "%s 333 %s %s %s %d", servinfos.servername, servinfos.nick, cptr->c, cptr->topicby, cptr->topictime);
						}
						if (maxclients == 1) {
							if (cptr->qlog)
								sendt(sockfd, ":my.bnc NOTICE %s :Beginning of quick log", cptr->c);
						}
						cptr = cptr->next;
					}

					if (maxclients == 1) {
						if (*qlogbuf != '\0') {
							if (connectedserver == 0)
								c->SENDING_QLOG_BEFORE_DISCONNECTING = 1;
							dout("sending quicklog ...\n");
							sent = mywrite(sockfd, qlogbuf, strlen(qlogbuf));
							if (sent != strlen(qlogbuf) && (connectedserver == 0)) {
								c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 1;
								dout("Could not send complete sendq. Waiting before disconnecting\n");
							}
						}
						*qlogbuf = '\0';
						qloglen = 0;
					}

					cptr = chanlist;
					while (cptr != 0) {
						if (maxclients == 1) {
							if (cptr->qlog) {
								sendt(sockfd, ":my.bnc NOTICE %s :End of quick log", cptr->c);
								cptr->qlog=0;
							}
						}
						if (connectedserver == 1)
							sendt(servinfos.sockfd, "names %s", cptr->c);
						cptr = cptr->next;
					}
					if (connectedserver == 0) {
						snotice("Connection to server was lost before you reconnected. Please reconnect.");
						if (maxclients == 1)
							snotice("Quicklog played, reconnecting.");
						sendt(c->fd, "ERROR :Lost connection to server before you reconnected. Please reconnect.");
						if ((c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT == 1) && (c->c_sendqsize == 0)) {
							dout("Why the hell is c_sendqsize == 0 ...\n");
							connectedclient = 1;
							if (*slots[a].user != 0)
								servinfos.state = 2;
							else
								servinfos.state = 1;
						}
						else if (c->c_sendqsize > 0) {
							dout("Sendq not sent completely (%d). Waiting before disconnecting\n", c->c_sendqsize);
							c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 1;
							connectedclient = 1;
							if (*slots[a].user != 0)
								servinfos.state = 2;
							else
								servinfos.state = 1;
						}
						else {
							closeclient();
						}
						closeserver();
						slots[a].fd = -1;
						findlastfd();
						return 0;
					}
				}
				else {
					dout(".1.\n");
					closeserver();
					dout(".2.\n");
					if (slots[a].sendinfos == 1) {
						strcpy(servinfos.user, slots[a].user);
					}
					dout(".3.\n");
					strcpy(servinfos.nick, slots[a].nick);
					strcpy(servinfos.realname, slots[a].realname);
					dout(".4.\n");
					if ((servinfos.sockfd = Conn()) < 0) {
						dout(".5.\n");
						dout("error connecting ..\n");
						sendt(sockfd, "Connection to server failed");
						servinfos.sockfd=-1;
						//close(slots[a].fd);
						slots[a].fd=-1;
						//closeclient();
						cleanclients();
						return 0;
					}
					dout(".6.\n");
					dout("servinfos.sockfd=%d\n", servinfos.sockfd);
					servinfos.state = 1;
				}
				connectedclient = 1;
				//servinfos.state = 1;

				//servinfos.clientfd = slots[a].fd;
				// I was usually declaring this slot as the client connection here, but i'm now doing it earlier. will it cause problems ?
				//c->fullyconnected = 1
				//active_c = c;
				slots[a].fd = -1;

			}
			else {
				sendt(sockfd, "NOTICE auth :Wrong password");
				close(sockfd);
				slots[a].fd = -1;
			}
			findlastfd();
		}


		return 0;
	}

	/************ ***************/
	/****** Authed clients ******/
	/************ ***************/

	c = getclient(sockfd);
	//if (sockfd == servinfos.clientfd) {
	if (c != 0) {
		c->clientidle = getctime();
		if ((servinfos.sockfd == -1) && (c->SENDING_QLOG_BEFORE_DISCONNECTING == 1)) {
			dout("NOT sending: %s\n", line);
			return 0;
		}
		if (strcasecmp(w[0], "pong") == 0) {
			if (KEEPALIVE) {
				c->pingtime = 0;
				return 0;
			}
		}
		if (servinfos.state > 0) {
			if ((strcasecmp(w[0], "PRIVMSG") == 0) || (strcasecmp(w[0], "NOTICE") == 0) 
				|| (strcasecmp(w[0], "CPRIVMSG") == 0) || (strcasecmp(w[0], "CNOTICE") == 0)) {

				// Self quicklog
				if (strlen(line) > (BUFSZ - 18)) {
					alog("Error: line for quicklog too long, it exceeds (1024-18) chars: %zu", strlen(line));
					return 0;
				}
				*buf = 0;
				if ((*w[1] == '#') || (*w[1] == '&')) {
					sprintf(buf,":%s!%s@%s %s %s", servinfos.nick, servinfos.user, servinfos.ip, w[0], w[1]);
				}
				else {
					sprintf(buf,":%s!mybnc@127.0.0.1 %s %s", w[1], w[0], servinfos.nick);
				}
				strcat(buf, " ");
				strcat(buf, ":");
				qlogts(buf);
				strcat(buf, " ");
				if ((*w[1] != '#') && (*w[1] != '&')) {
					strcat(buf, "<<");
					strcat(buf, servinfos.nick);
					strcat(buf, ">> ");
				}

				/* Syntax for CPRIVMSG is "CPRIVMSG <dest> <common channel> :<text>",
				 * so we have to offset by one word the text
				 */
				if ((strcasecmp(w[0], "CPRIVMSG") == 0) || (strcasecmp(w[0], "CNOTICE") == 0))
					iscprivmsg = 1;
				else
					iscprivmsg = 0;

				strcat(buf, &w[2+iscprivmsg][1]);
				if (strcasecmp(w[2+iscprivmsg], ":login") == 0) {
					strcat(buf, " [sssshhh]");
				}
				else if (strcasecmp(w[2+iscprivmsg], ":auth") == 0) {
					strcat(buf, " [sssshhh]");
				}
				else {
					for (i=3+iscprivmsg; i<=wcount; i++) {
						strcat(buf, " ");
						strcat(buf, w[i]);
					}
				}
				addqlog(buf);
				// Self quicklog end



				if (clientcount() > 1) {
					*buf = 0;
					strcpy(buf, w[2+iscprivmsg]);
					if (strcasecmp(w[2+iscprivmsg], ":login") == 0) {
						strcat(buf, " [sssshhh]");
					}
					else if (strcasecmp(w[2+iscprivmsg], ":auth") == 0) {
						strcat(buf, " [sssshhh]");
					}
					else {
						for (i=3+iscprivmsg; i<=wcount; i++) {
							strcat(buf, " ");
							strcat(buf, w[i]);
						}
					}

					if ((w[1][0] == '#') || (w[1][0] == '&')) {
						x = clients;
						while (x != 0) {
							if (x != c) {
								sendt(x->fd, ":%s!%s@%s %s %s %s", servinfos.nick, servinfos.user, servinfos.ip, w[0], w[1], buf);
							}
							x = x->next;
						}
					}
					else {
						x = clients;
						while (x != 0) {
							if (x != c) {
								if (strcasecmp(w[0], "PRIVMSG") == 0)
									sendt(x->fd, ":%s!mybnc@127.0.0.1 PRIVMSG %s :<<%s>> %s", w[1], servinfos.nick, servinfos.nick, &buf[1]);
								else if (strcasecmp(w[0], "NOTICE") == 0)
									sendt(x->fd, ":-mybnc!mybnc@127.0.0.1 NOTICE %s :-> %s: %s", servinfos.nick, w[1], &buf[1]);
								else if (strcasecmp(w[0], "CPRIVMSG") == 0)
									sendt(x->fd, ":%s!mybnc@127.0.0.1 PRIVMSG %s :<<%s>> %s", w[1], servinfos.nick, servinfos.nick, &buf[1]);
								else if (strcasecmp(w[0], "CNOTICE") == 0)
									sendt(x->fd, ":%s!mybnc@127.0.0.1 PRIVMSG %s :<<%s>> %s", w[1], servinfos.nick, servinfos.nick, &buf[1]);
							}
							x = x->next;
						}
					}
				}
			}
			/*if ((wcount > 1) && (strcasecmp(w[0], "setqlog") == 0)) {
				idptr = getident(w[1]);
				if (idptr) {
					idptr->qlog = atoi(w[2]);
					snotice("Qlog size for ident %s is now %d", idptr->ident, idptr->qlog);
				}
				else {
					snotice("ident doesn't exist");
				}
				return 0;
			}*/

			if (strcasecmp(w[0], "bncdebug") == 0) {
				if (debugtofile == 0) {
					debugtofile = 1;
					dout("\n\n\n\n\n");
					dout("----- Debug enabled via IRC -----\n\n");
					gnotice("Debug to file enabled.");
				}
				else if (debugtofile == 1) {
					dout("\n\n");
					dout("----- Debug disabled via IRC -----\n\n");
					debugtofile = 0;
					gnotice("Debug to file disabled.");
				}
				return 0;
			}

			if (strcasecmp(w[0], "bnctime") == 0) {
				snotice("%s %d", fulltimestamp(getctime()), getctime());
				return 0;
			}
			if ((wcount > 0) && (strcasecmp(w[0], "ident") == 0)) {
				if (c->ident != 0) {
					snotice("You already identified");
					return 0;
				}
				i = 0;
				if (getident(w[1]) == 0) {
					i = 1;
					addident(w[1]);
				}
				idptr = getident(w[1]);
				if ((i == 1) && (idptr->fd != -1)) {
					snotice("thats a bug!");
					alog("bug bug bug ...");
					exit(0);
				}
				if (idptr->fd != -1) {
					snotice("Disconnecting another client (%s) to allow you to ident", idptr->ip);
					active_c = getclient(idptr->fd);
					snotice("(%s) Another client connected from your user (%s)", c->ip, idptr->ident);
					closeclient();
					active_c = c;
				}
				snotice("Identified as %s", idptr->ident);
				idptr->fd = c->fd;
				if (idptr->qlog > 0) {
					snotice("Sending quicklog (%d lines)", idptr->qlog);
					cptr = chanlist;
					while (cptr) {
						sendt(sockfd, ":my.bnc NOTICE %s :Beginning of quick log", cptr->c);
						cptr = cptr->next;
					}
					sendlog(c->fd, 0, idptr->qlog, 0);
					cptr = chanlist;
					while (cptr) {
						sendt(sockfd, ":my.bnc NOTICE %s :End of quick log", cptr->c);
						cptr = cptr->next;
					}
				}
				c->ident = idptr;
				if (i == 1)
					idptr->firstseen = getctime();
				idptr->lastseen = getctime();
				return 0;
			}
			if (strcasecmp(w[0], "bncwho") == 0) {
				x = clients;
				snotice("There are %d clients connected to this bnc right now.", clientcount());
				while (x != 0) {
					if (x->ident == 0)
						snotice("%s (connected on %s GMT %d)", x->ip, fulltimestamp(x->signon), TIMEZONE);
					else {
						idptr = x->ident;
						strcpy(buf, fulltimestamp(x->signon));
						snotice("%s %s (connected on %s GMT %d, first identified on %s)", idptr->ident, x->ip, buf, TIMEZONE, fulltimestamp(idptr->firstseen));
					}
					x = x->next;
				}
				idptr = idents;
				//if (idptr)
				//	snotice("Clients not connected:");
				while (idptr) {
					if (idptr->fd == -1) {
						strcpy(buf, fulltimestamp(idptr->lastseen));
						snotice("%s Last ip is %s (last connected on %s GMT %d, first identified on %s)", idptr->ident, idptr->ip, buf, TIMEZONE, fulltimestamp(idptr->firstseen));
					}
					idptr = idptr->next;
				}
				return 0;
			}
			if (strcasecmp(w[0], "bncdie") == 0) {
				if (connectedserver)
					sendt(servinfos.sockfd, "QUIT :Killed");
				closeserver();
				//closeclient();
				cleanclients();
				alog("Received bncdie");
				return -2;
			}
			if (strcasecmp(w[0], "qlog") == 0) {
				if (wcount < 1)
					sendlog(c->fd, 0, 1000, 0);
				else if ((wcount < 2) && (atoi(w[1]) > 0))
					sendlog(c->fd, 0, atoi(w[1]), 0);
				else if ((wcount < 2) && (strcasecmp(w[1], "msg") == 0))
					sendlog(c->fd, 1, 1000, 0);
				else if ((wcount < 2) && ((w[1][0] == '#') || (w[1][0] == '&')))
					sendlog(c->fd, 2, 1000, w[1]);
				else if ((wcount == 2) && ((w[1][0] == '#') || (w[1][0] == '&')) && (atoi(w[2]) > 0))
					sendlog(c->fd, 2, atoi(w[2]), w[1]);
				else if ((wcount == 2) && (strcasecmp(w[1], "msg") == 0) && (atoi(w[2]) > 0))
					sendlog(c->fd, 1, atoi(w[2]), 0);
				else
					snotice("Type /bnchelp for correct syntax");
				dout("done with /qlog\n");
				return 0;
			}
			if (strcasecmp(w[0], "bnchelp") == 0) {
				snotice("Commands available for mybnc v%s:", bncversion);
				snotice("/bncdie - kills the bnc");
				snotice("/conn - disconnects server + client connections, used for reconnecting to the irc server");
				snotice("/vhost [host or ip] - says it all");
				snotice("/jump <server> [port] [server password]");
				snotice("/bncwho - lists clients connected to the bnc");
				snotice("/qlog [number of lines] - Shows standard quicklog (messages + channels)");
				snotice("/qlog <#chan> [number of lines] - Shows conversations for one specific channel");
				snotice("/qlog msg [number of lines] - Shows private messages only");
				snotice("/ident <user> - Useful when maxclients > 1. You use a different ident for each computer, helpful for the quicklog if you do /ident <user> on connect.");
				snotice("/bnctime - returns the current bnc time");
				snotice("/bncdebug - Turns debug to file on and off (bncdir/debug.log)");
				snotice("-");
				snotice("When connecting to the bnc, you can choose your server when you send your password. Syntax: /pass <bnc pass> [server] [port] [server password]");
				return 0;
			}
			if (strcasecmp(w[0], "conn") == 0) {
				if (connectedserver)
					sendt(servinfos.sockfd, "QUIT :Reconnecting ...");
				//closeclient();
				gnotice("Reconnecting");
				cleanclients();
				alog("Reconnecting");
				closeserver();
				return 0;
			}
			if (strcasecmp(w[0], "vhost") == 0) {
				if (CMD_VHOST == 0) {
					//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :VHOST: command disabled", servinfos.nick);
					snotice("VHOST: command disabled");
				}
				else if (wcount < 1) {
					//sendt(c->fd, ":my.bnc NOTICE %s :VHOST: syntax: /vhost <host or ip>", servinfos.nick);
					snotice("VHOST: syntax: /vhost <host or ip>");
				}
				else {
					if (get_addr(&servinfos.vhost.sin_addr, w[1]) == -1) {
						//sendt(c->fd, ":my.bnc NOTICE %s :vhost did not resolve: %s - You could try with the IP directly", servinfos.nick, w[1]);
						snotice("vhost did not resolve: %s - You could try with the IP directly", w[1]);
					}
					else if (isvhostok() == -1) {
						//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :Could not bind to vhost: %s", servinfos.nick, w[1]);
						snotice("Could not bind to vhost: %s", w[1]);
					}
					else {
						//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :New vhost (%s) will be used until next rehash or restart", servinfos.nick, w[1]);
						gnotice("New vhost (%s) will be used until next rehash or restart", w[1]);
					}
				}
				return 0;
			}
			if (strcasecmp(w[0], "jump") == 0) {
				if (CMD_JUMP == 0) {
					//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :JUMP: command disabled", servinfos.nick);
					snotice("JUMP: command disabled");
				}
				else if (wcount < 1) {
					//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :JUMP: syntax: /jump <server> [port] [password]", servinfos.nick);
					snotice("JUMP: syntax: /jump <server> [port] [password]");
				}
				else {
					if (get_addr(&servinfos.server.sin_addr, w[1]) == -1) {
						//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :Invalid server: %s", servinfos.nick, w[1]);
						snotice("Invalid server: %s", w[1]);
					}
					else {
						if (wcount > 1) {
							if (!(atoi(w[2]))) {
								//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :Invalid port: %s", servinfos.nick, w[2]);
								snotice("Invalid port: %s", w[2]);
								nogo = 1;
							} else {
								servinfos.server.sin_port = htons(atoi(w[2]));
							}
						}
						if (wcount > 2) {
							strncpy(servinfos.serverPASSWORD, w[3], PASSLEN);
							servinfos.serverPASSWORD[PASSLEN] = '\0';
						}
						if (nogo == 0) {
							sendt(servinfos.sockfd, "QUIT :jump!");
							//sendt(c->fd, "-mybnc!mybnc@my.bnc NOTICE %s :Connecting to %s:%s", servinfos.nick, w[1], w[2]);
							gnotice("Connecting to %s:%s", w[1], w[2]);
							alog("JUMPING TO %s:%s", w[1], w[2]);
							dout("JUMPING TO %s:%s\n", w[1], w[2]);
							closeserver();
							closeclient();
						}
					}
				}
				return 0;
			}
		}
		//if ((servinfos.state > 1) || (clientcount() > 1)) {
		if (servinfos.state > 1) {
			if ((KEEPALIVE) && (strcasecmp(w[0], "QUIT") == 0)) {
				closeclient();
				if (clientcount() == 0) {
					sendt(servinfos.sockfd, "away :%s", servinfos.detachmsg);
					dout("sending detach msg ...\n");
				}
				return 0;
			}
			/*if ((wcount > 0) && (strcasecmp(w[0],"PART") == 0)) {
				dout("Del chan: %s\n", w[1]);
				remchan(w[1]);
			}*/
		}
		if (servinfos.state < 2) {
			if ((strcasecmp(w[0], "NICK") == 0) && (wcount == 1)) {
				if (c->reattach == 0) {
					strncpy(servinfos.nick,w[1],sizeof(servinfos.nick) - 1);
					dout("Nick received: %s\n", servinfos.nick);
				}
				else
					return 0;
			}
			if ((strcasecmp(w[0], "USER") == 0) && (wcount > 3)) {
				if (c->reattach == 0) {
					strncpy(servinfos.user,w[1], USERLEN);
					strncpy(rname,&w[4][1],RNAMELEN);
					i=5;
					while(i <= wcount) {
						if ((RNAMELEN - strlen(rname)) > 2) {
							strcat(rname, " ");
							strncat(rname, w[i], (RNAMELEN - strlen(rname)));
						}
						i++;
					}
					rname[RNAMELEN] = '\0';
					dout("rname = %s\n", rname);
					strcpy(servinfos.realname, rname);
				}
				else if (c->reattach == 1) {
					c->reattach=0;
					servinfos.state = 2;
					return 0;
				}
			}
		}
		return 100;
	}

	/************ ***************/
	/********** Server **********/
	/************ ***************/

	if (strcasecmp(w[0], "ping") == 0) {
		if (KEEPALIVE) {
			sendt(sockfd, "PONG %s", w[1]);
		}
		return 0;
	}
	if ((wcount > 5) && (strcasecmp(w[0], "ERROR") == 0) && (strcasecmp(w[6], "(re)connect") == 0)) {
		throttle_t = getctime();
	}
	if ((wcount > 2) && (strcasecmp(w[1],"KICK") == 0) && (strcasecmp(w[3],servinfos.nick) == 0)) {
		remchan(w[2]);
	}

	if ((wcount > 2) && (strcasecmp(w[1],"TOPIC") == 0)) {
		cptr = onchan(w[2]);
		if (cptr > 0) {
			strncpy(cptr->topic, w[3], 256);
			cptr->topic[256] = 0;
			for (i=4; i<=wcount; i++) {
				if (strlen(w[i]) < (255 - strlen(cptr->topic))) {
					strcat(cptr->topic, " ");
					strcat(cptr->topic, w[i]);
				}
			}
			strncpy(str, w[0], 63);
			str[63] = 0;
			ptr = &str[1];
			for (i=0; i<63 && str[i] != 0; i++) {
				if (str[i] == '!') {
					str[i] = 0;
					break;
				}
			}
			strcpy(cptr->topicby, ptr);
			cptr->topictime = getctime();
		}
	}

	if ((strncasecmp(&w[0][1], servinfos.nick, strlen(servinfos.nick)) == 0) && (w[0][strlen(servinfos.nick)+1] == '!')) {
		//It's _me_ !
		if (wcount > 0) {
			if (strcasecmp(w[1],"NICK") == 0) {
				if (*w[2] == ':')
					strncpy(servinfos.nick, &w[2][1], sizeof(servinfos.nick));
				else
					strncpy(servinfos.nick, &w[2][0], sizeof(servinfos.nick));
				dout("New nick = %s\n", servinfos.nick);
			}
			if (strcasecmp(w[1],"JOIN") == 0) {
				addchan(w[2]);
				dout("New chan: %s\n", w[2]);
			}
			if (strcasecmp(w[1],"PART") == 0) {
				remchan(w[2]);
				dout("Del chan: %s\n", &w[2][1]);
			}
		}
	}

	//if (connectedclient == 0) {
		if (wcount > 1) {
			if (strcasecmp(w[1], "WALLOPS") == 0) {
				if (strlen(line) > (BUFSZ - 18)) {
					alog("Error: line for quicklog too long, it exceeds (1024-18) chars: %zu", strlen(line));
					return 0;
				}
				*buf = 0;
				strcpy(buf, w[0]);
				for (i=1; i<3; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				strcat(buf, " ");
				//strcat(buf, ":");
				//strcat(buf, timestamp());
				qlogts(buf);
				//strcat(buf, " ");
				//strcat(buf, &w[3][1]);
				for (i=3; i<=wcount; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				addqlog(buf);
			}
			if (strcasecmp(w[1], "PRIVMSG") == 0) {
				if (strlen(line) > (BUFSZ - 18)) {
					alog("Error: line for quicklog too long, it exceeds (1024-18) chars: %zu", strlen(line));
					return 0;
				}
				if (onchan(w[2]))
					setqlogchan(w[2]);
				*buf = 0;
				strcpy(buf, w[0]);
				for (i=1; i<3; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				strcat(buf, " ");
				strcat(buf, ":");
				//strcat(buf, timestamp());
				qlogts(buf);
				strcat(buf, " ");
				strcat(buf, &w[3][1]);
				for (i=4; i<=wcount; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				addqlog(buf);
			}
			/*if (strcasecmp(w[1], "NICK") == 0) {
				if (onchan(w[2]))
					setqlogchan(w[2]);
				addqlog(line);
			}
			if (strcasecmp(w[1], "KICK") == 0) {
				if (onchan(w[2]))
					setqlogchan(w[2]);
				addqlog(line);
			}
			if (strcasecmp(w[1], "MODE") == 0) {
				if (onchan(w[2]))
					setqlogchan(w[2]);
				addqlog(line);
			}
			if (strcasecmp(w[1], "JOIN") == 0) {
				if (onchan(w[2]))
					setqlogchan(w[2]);
				addqlog(line);
			}
			if (strcasecmp(w[1], "PART") == 0) {
				if (onchan(w[2]))
					setqlogchan(w[2]);
				addqlog(line);
			}
			if (strcasecmp(w[1], "QUIT") == 0) {
				addqlog(line);
			}*/
			if (strcasecmp(w[1], "NOTICE") == 0) {
				if (strlen(line) > (BUFSZ - 18)) {
					alog("Error: line for quicklog too long, it exceeds (1024-18) chars: %zu", strlen(line));
					return 0;
				}
				*buf = 0;
				strcpy(buf, w[0]);
				for (i=1; i<3; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				strcat(buf, " ");
				strcat(buf, ":");
				//strcat(buf, timestamp());
				qlogts(buf);
				strcat(buf, " ");
				strcat(buf, &w[3][1]);
				for (i=4; i<=wcount; i++) {
					strcat(buf, " ");
					strcat(buf, w[i]);
				}
				if (onchan(w[2])) {
					setqlogchan(w[2]);
					addqlog(buf);
				}

				/*if (onchan(w[2])) {
					setqlogchan(w[2]);
					addqlog(line);
				}*/
				if (strcasecmp(w[2],servinfos.nick) == 0) {
					// Add to quicklog only if it's not a server notice
					if (strchr(w[0],'.') == NULL)
						addqlog(buf);
				}
			}
		}
	//}


	if ((wcount > 0) && (strcasecmp(w[1], "001") == 0)) {
		if (servinfos.state >= 2) {
			alog ("Why is state >= 2 for 001 numeric ?");
			gnotice ("Why is state >= 2 for 001 numeric ?");
		}
		strncpy(servinfos.servername,w[0],sizeof(servinfos.servername)-1);
		servinfos.servername[sizeof(servinfos.servername)-1] = 0;
		servinfos.state = 2;
		servinfos.recv001 = 1;
		strncpy(servinfos.network,w[6],sizeof(servinfos.network)-1);
		dout("001 received\n");
	}
	if ((wcount > 0) && (strcasecmp(w[0],servinfos.servername) == 0)) {
		switch(atoi(w[1])) {
			case 001:
				strncpy(servinfos.nick,w[2],sizeof(servinfos.nick)-1);
				//strncpy(servinfos.n001, line, sizeof(servinfos.n001)-1);
				//servinfos.n001[sizeof(servinfos.n001)-1] = '\0';
				dout("My nick = %s\n", servinfos.nick);
				break;
			case 332:
				cptr = onchan(w[3]);
				if (cptr > 0) {
					strncpy(cptr->topic, w[4], 256);
					cptr->topic[256] = 0;
					for (i=5; i<=wcount; i++) {
						if (strlen(w[i]) < (255 - strlen(cptr->topic))) {
							strcat(cptr->topic, " ");
							strcat(cptr->topic, w[i]);
						}
					}
				}
				break;
			case 333:
				cptr = onchan(w[3]);
				if (cptr > 0) {
					strncpy(cptr->topicby, w[4], 63);
					cptr->topicby[63] = 0;
					cptr->topictime = atoi(w[5]);
				}
				break;
			default:
				break;
		}
	}
	return 0;
}



int iswm (char *wc, char *str)
{
	int i=0;
	int a=0;
	int ind=0;
	char *ptrstr = str;
	char *ptrbuf;
	static char *buf = 0;

	if (buf == 0) {
		i = 512;
		if ((buf = malloc(i)) <= 0) {
			dout("iswm(): malloc() error\n");
			alog("iswm(): malloc() error");
			exit(0);
		}
		memset(buf,0,i);
		i=0;
	}

	if (strlen(wc) > 500) {
		dout("iswm(): String too large: %s\n", wc);
		alog("iswm(): String too large: %s", wc);
	}
	if (strlen(str) > 500) {
		dout("iswm(): String too large: %s\n", str);
		alog("iswm(): String too large: %s", str);
	}


	for (i=0; i<strlen(wc); i++) {
		if ((wc[i] == '*') && (wc[i+1] != '*')) {
			if (wc[i+1] == '\0')
				return 1;
			a=0;
			while ((wc[++i] != '*') && (wc[i] != '\0')) {
				buf[a++] = tolower(wc[i]);
			}
			i--;
			buf[a] = '\0';
			ptrbuf = buf;
			if (a > 0) {
				while (*ptrbuf++ == '?') {
					ptrstr++;
				}
				ptrbuf--;
				if (ptrstr > (str + strlen(str)))
					return 0;
				ind=0;
				while (ind == 0) {
					ind=1;
					while ((tolower(*ptrstr++) != tolower(ptrbuf[0])) && (*(ptrstr - 1) != '\0'));
					ptrstr--;
					if (strlen(ptrstr) < strlen(ptrbuf))
						return 0;
					for (a=0; a<strlen(ptrbuf); a++) {
						if ((tolower(*ptrstr++) != tolower(ptrbuf[a])) && (ptrbuf[a] != '?'))
							ind = 0;
					}
					if (ptrstr > (str + strlen(str))) {
						return 0;
					}
					if ((*ptrstr == '\0') && (wc[i+1] == '\0') && (ind == 1)) {
						//dout("um\n");
						return 1;
					}
					if (ind == 0)
						ptrstr -= (a - 1);
				}
				//ptrstr--; <-- commented on 2007-05-24
			}
		}
		else if (wc[i] == '\0') {
			return 1;
		}
		else if (wc[i] != '*') {
			while ((wc[i] != '*') && (wc[i] != '\0')) {
				if ((tolower(*ptrstr++) != tolower(wc[i++])) && (wc[i-1] != '?'))
					return 0;
				if ((wc[i] == '\0') && (*ptrstr == '\0')) {
					//dout("um\n");
					return 1;
				}
			}
			i--;
			//ptrstr--;
		}
	}

	if (strlen(ptrstr) > 0) {
		//dout("ok ..\n");
		return 0;
	}
	else
		return 1;
}

static void free_ipsallowed(struct IPSALLOWED **ex)
{
     struct IPSALLOWED *next;
     while (*ex) {
	  next = (*ex)->next;
	  free(*ex);
	  *ex = NULL;
	  ex = &next;
     }
}


int loadipsallowed ()
{
	FILE *f;
	struct IPSALLOWED *ptr;
	char wc[HOSTLEN+1];
	int len;


	free_ipsallowed(&ipsallowed);

	if ((f = fopen("mybnc.allow", "r")) == NULL) {
	     return -1;
	}

	while (fgets(wc, HOSTLEN, f) != NULL) {
	     ptr = malloc(sizeof(*ptr));
	     if (!ptr) {
		  free_ipsallowed(&ipsallowed);
		  return -1;
	     }
	     ptr->next = ipsallowed;
	     ipsallowed = ptr;
	     len = snprintf(ptr->mask, HOSTLEN, wc);
	     ptr->mask[len-1] = '\0';
	}

	fclose(f);
	return 0;

}

int isipallowed(char *address)
{
	struct IPSALLOWED *ptr;

	ptr = ipsallowed;
	while (ptr != 0) {
		if (iswm(ptr->mask, address))
			return 1;
		ptr = ptr->next;
	}
	return 0;
}

int dout (char const *format, ...)
{
	FILE *f;
	va_list vl;
	int nchars;
	char outbuf[MAX_OUT_PAYLOAD2+3];
	struct tm *today;
	time_t ltime;
	char fulltime[32];
	char *ptr;

	if ((debug == 0) && (debugtofile == 0))
		return -1;

	time(&ltime);
	today = gmtime(&ltime);

	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_OUT_PAYLOAD2+1, format, vl);
	va_end(vl);

	if (nchars >= MAX_OUT_PAYLOAD2) {
		dout("Output truncated: ");
		nchars = MAX_OUT_PAYLOAD2;

	}

	if (strncasecmp(outbuf, "[Client] OPER ", 14) == 0) {
		dout("oper [ssshhhhhh]\n");
		return 0;
	}

	if (debug)
		printf("%s", outbuf);

	if (debugtofile) {
		if ((f = fopen("debug.log", "a")) == NULL) {
			alog("error: fopen() for debug.log\n");
			return -1;
		}
		strncpy(fulltime,asctime(today),sizeof(fulltime)-1);
		ptr=0;
		ptr = strchr(fulltime,'\n');
		if (ptr != 0)
			*ptr = '\0';
		fprintf(f,"[%s] %s",fulltime,outbuf);
		fclose(f);
	}
	return 0;

}

char *fulltimestamp (time_t ltime)
{
	struct tm *today;
	//time_t ltime;
	static char fulltime[32];
	char *ptr;

	//time(&ltime);
	//ltime = getctime();
	ltime += 3600 * TIMEZONE;

	today = gmtime(&ltime);

	strncpy(fulltime,asctime(today),sizeof(fulltime)-1);
	ptr=0;
	ptr = strchr(fulltime,'\n');
	if (ptr != 0)
		*ptr = '\0';
	return fulltime;
}

int alog (char *format, ...)
{
	FILE *f;
	va_list vl;
	int nchars;
	char outbuf[MAX_OUT_PAYLOAD+3];
	struct tm *today;
	time_t ltime;
	char fulltime[32];
	char *ptr;

	time(&ltime);
	today = gmtime(&ltime);

	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_OUT_PAYLOAD, format, vl);
	va_end(vl);

	if (nchars >= MAX_OUT_PAYLOAD) {
		dout("alog(): Output truncated!\n");
		nchars = MAX_OUT_PAYLOAD - 1;
	}

	if ((f = fopen("mybnc.log", "a")) == NULL) {
		dout("error: fopen() for mybnc.log\n");
		return -1;
	}
	strncpy(fulltime,asctime(today),sizeof(fulltime)-1);
	ptr=0;
	ptr = strchr(fulltime,'\n');
	if (ptr != 0)
		*ptr = '\0';
	fprintf(f,"[%s] %s\n",fulltime,outbuf);
	fclose(f);
	dout("alog(): %s\n", outbuf);
	return 0;
}

int getctime()
{
	time_t ltime;

	time(&ltime);
	return ltime;
}

int findlastfd()
{
	int i=0;
	int a=0;
	struct CLIENTS *c;

	i = listenfd;

	c = clients;
	while (c != 0) {
		if (c->fd > i)
			i = c->fd;
		c = c->next;
	}


	//if (servinfos.clientfd > i) {
	//	i = servinfos.clientfd;
	//}
	if (servinfos.sockfd > i) {
		i = servinfos.sockfd;
	}

	for (a=0; a < NUMSLOTS; a++) {
		if (slots[a].fd > -1) {
			if (slots[a].fd > i)
				i = slots[a].fd;
		}
	}
	lastfd = i;
	return 0;
}

int addchan (char *chan)
{
	struct CHANLIST *mem;
	struct CHANLIST *ptr;

	mem = malloc(sizeof(struct CHANLIST));
	if (!mem) {
		dout("malloc() failed\n");
		alog("malloc() failed");
		exit(1);
	}
	memset(mem,0,sizeof(struct CHANLIST));


	if (*chan == ':')
		chan++;
	strncpy(mem->c, chan, CHANLEN);
	if (strlen(chan) >= CHANLEN)
		mem->c[CHANLEN] = '\0';
	dout("new chan = %s\n", mem->c);

	if (chanlist == 0) {
		chanlist = mem;
		return 0;
	}
	ptr = chanlist;
	while (ptr->next) {
		ptr = ptr->next;
	}
	ptr->next = mem;
	mem->prev = ptr;

	return 0;
}

int remchan (char *chan)
{
	struct CHANLIST *ptr;
	struct CHANLIST *ptr2;
	int a=0;
	int i=0;


	if (*chan == ':')
		chan++;
	ptr = chanlist;
	while (ptr != 0) {
		if (strcasecmp(ptr->c,chan) == 0) {
			if (ptr == chanlist) {
				chanlist = ptr->next;
				if (chanlist)
					chanlist->prev = 0;
				free(ptr);
				//return 0;
				a=1;
				i++;
				ptr = chanlist;
				continue;
			}
			if (ptr->prev) {
				ptr2 = ptr->prev;
				ptr2->next = ptr->next;
			}
			if (ptr->next) {
				ptr2 = ptr->next;
				ptr2->prev = ptr->prev;
			}
			ptr2 = ptr;
			ptr = ptr->next;
			free(ptr2);
			i++;
			a=1;
			continue;
		}
		ptr = ptr->next;
	}
	if (a == 1)
		return 0;
	return -1;
}

int cleanchan ()
{
	struct CHANLIST *ptr;
	struct CHANLIST *ptr2;

	ptr = chanlist;
	while (ptr != 0) {
		ptr2 = ptr->next;
		free(ptr);
		ptr = ptr2;
	}
	chanlist=0;
	return 0;
}

struct CHANLIST* onchan (char *chan)
{
	struct CHANLIST *ptr;

	ptr = chanlist;
	while (ptr != 0) {
		if (strcasecmp(chan,ptr->c) == 0)
			return ptr;
		ptr = ptr->next;
	}
	return 0;
}

int setqlogchan (char *chan)
{
	struct CHANLIST *ptr;

	if (connectedclient == 0) {
		ptr = chanlist;
		while (ptr != 0) {
			if (strcasecmp(chan,ptr->c) == 0) {
				ptr->qlog = 1;
				return 1;
			}
			ptr = ptr->next;
		}
	}
	return 0;
}

#define SER 1
#define VHO 2
#define SERP 4
#define LISP 8
#define PAS 16
#define KEEA 32
#define LIP 64
#define TZN 128

int readconf()
{
	FILE *f;
	char buf[256];
	char *ptr;
	int i=0;
	int lines=0;
	int err=0;
	int flags=0;

	strcpy(servinfos.detachmsg, "detached.");

	if ((f = fopen("mybnc.conf", "r")) == NULL) {
		fprintf(stderr, "error opening mybnc.conf\n");
		return -1;
	}

	while (fgets(buf,sizeof(buf)-1,f) != NULL) {
		lines++;
		i=0;
		while ((buf[i] == ' ') || (buf[i] == '\t')) i++;
		if ((ptr = strchr(buf,'\n'))) {
			*ptr = '\0';
			if (*--ptr == '\r')
				*ptr = '\0';
		}
		if ((buf[i] != '#') && (buf[i] != '\0')) {
			ptr = strchr(&buf[i],'=');
			if (!ptr) {
				fprintf(stderr, "Conf error line %d: could not find '='\n", lines);
				//fprintf(stderr, "Last char: %d\n", buf[i]);
				err = -1;
				break;
			}
			*ptr++ = '\0';
			if (strlen(ptr) <= 0) {
				fprintf(stderr, "Conf error line %d: len of %s's value = 0\n", lines, &buf[i]);
				err = -1;
				break;
			}

			if (strcasecmp(&buf[i],"server") == 0) {
				if (get_addr(&servinfos.server.sin_addr, ptr) == -1) {
					fprintf(stderr, "Invalid server: %s\n", ptr);
					err = -1;
					break;
				}
				if (!(flags & SER))
					flags |= SER;
			}
			else if (strcasecmp(&buf[i],"listenip") == 0) {
				if (strcasecmp(ptr, "0") == 0) {
					alog("Listening on all IP addresses");
					dout("Listening on all IP addresses\n");
					*servinfos.listenip = '\0';
				}
				else {
					strncpy(servinfos.listenip, ptr, 15);
					servinfos.listenip[15] = '\0';
				}

				if (!(flags & LIP))
					flags |= LIP;
			}
			else if (strcasecmp(&buf[i],"vhost") == 0) {
				if (get_addr(&servinfos.vhost.sin_addr, ptr) == -1) {
					fprintf(stderr, "Invalid vhost: %s\n", ptr);
					err = -1;
					break;
				}
				if (!(flags & VHO))
					flags |= VHO;
			}
			else if (strcasecmp(&buf[i],"serverport") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid port: %s\n", ptr);
					err = -1;
					break;
				} else {
					servinfos.server.sin_port = htons(atoi(ptr));
					if (!(flags & SERP))
						flags |= SERP;
				}
			}
			else if (strcasecmp(&buf[i],"serverpassword") == 0) {
				strncpy(servinfos.serverPASSWORD, ptr, PASSLEN);
				servinfos.serverPASSWORD[PASSLEN] = '\0';
			}
			else if (strcasecmp(&buf[i],"awaymsg") == 0) {
				strncpy(servinfos.detachmsg, ptr, 256);
				servinfos.detachmsg[256] = '\0';
			}
			else if (strcasecmp(&buf[i],"listenport") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid port: %s\n", ptr);
					err = -1;
					break;
				} else {
					servinfos.listenport = atoi(ptr);
					if (!(flags & LISP))
						flags |= LISP;
				}
			}
			else if (strcasecmp(&buf[i],"pingfreq") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid ping frequency value (in secs): %s\n", ptr);
					err = -1;
					break;
				} else {
					PINGFREQUENCY = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"maxclients") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid maxclients value: %s\n", ptr);
					err = -1;
					break;
				} else {
					maxclients = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"qlogsize") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid qlogsize value: %s\n", ptr);
					err = -1;
					break;
				} else {
					QLOGBUFSIZE = atoi(ptr);
					LOGBUFSIZE = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"wait_time") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid wait_time value: %s\n", ptr);
					err = -1;
					break;
				} else {
					WAIT_TIME = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"wait_throttle") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid wait_throttle value: %s\n", ptr);
					err = -1;
					break;
				} else {
					THROTTLE = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"pingtimeout") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid ping timeout value (in secs): %s\n", ptr);
					err = -1;
					break;
				} else {
					PINGTIMEOUT = atoi(ptr);
				}
			}
			else if (strcasecmp(&buf[i],"timezone") == 0) {
				if (!(atoi(ptr))) {
					fprintf(stderr, "Invalid timezone: %s\n", ptr);
					err = -1;
					break;
				} else {
					TIMEZONE = atoi(ptr);
					if (!(flags & TZN))
						flags |= TZN;
				}
			}
			else if (strcasecmp(&buf[i],"password") == 0) {
				strncpy(PASSWORD, ptr, PASSLEN);
				PASSWORD[PASSLEN] = '\0';
				if (!(flags & PAS))
					flags |= PAS;
			}
			else if (strcasecmp(&buf[i],"keepalive") == 0) {
				if (strcasecmp(ptr,"true") == 0)
					KEEPALIVE = 1;
				else
					KEEPALIVE = 0;
				if (!(flags & KEEA))
					flags |= KEEA;
			}
			else if (strcasecmp(&buf[i],"shorttimestamp") == 0) {
				if (strcasecmp(ptr,"true") == 0)
					SHORTTS = 1;
				else
					SHORTTS = 0;
			}
			else if (strcasecmp(&buf[i],"cmd_jump_disabled") == 0) {
				if (strcasecmp(ptr,"true") == 0)
					CMD_JUMP = 0;
				else
					CMD_JUMP = 1;
			}
			else if (strcasecmp(&buf[i],"cmd_vhost_disabled") == 0) {
				if (strcasecmp(ptr,"true") == 0)
					CMD_VHOST = 0;
				else
					CMD_VHOST = 1;
			}
			else {
				dout("Conf warning line %d: Unknown parameter: %s\n", lines, &buf[i]);
			}
		}
	}

	if (!(flags & KEEA))
		fprintf(stderr, "parameter KEEPALIVE missing. possible values = true or false\n");
	if (!(flags & SER))
		fprintf(stderr, "parameter server missing.\n");
	if (!(flags & SERP))
		fprintf(stderr, "parameter port missing\n");
	if (!(flags & LISP))
		fprintf(stderr, "parameter listenport missing\n");
	if (!(flags & PAS))
		fprintf(stderr, "parameter password missing\n");
	if (!(flags & LIP))
		fprintf(stderr, "parameter listenip	 missing\n");
	if (!(flags & VHO))
		fprintf(stderr, "parameter vhost missing\n");
	if (!(flags & TZN))
		fprintf(stderr, "parameter timezone missing\n");
	//printf("flags=%d\n", flags);
	fclose(f);
	if (flags < 127)
		return -1;
	if ((KEEPALIVE == 0) && (maxclients > 1)) {
		fprintf(stderr, "If you want to have maxclients>1, you need keepalive=true\n");
		return -1;
	}
	return err;
}

int addqlog (char *line)
{
	int len=0;
	int free = 0;
	int free2 = 0;
	static int loglen = 0;
	char *ptr;
	static char *target = 0;
	static char *target2 = 0;
	int shift=0;
	struct IDENTS *id = idents;

	if (connectedclient == 0)
		dout("[Qlog] %s\n", line);

	if (target == 0)
		target = qlogbuf;
	if (target2 == 0)
		target2 = logbuf;
	len = strlen(line);
	//free = QLOGBUFSIZE - strlen(qlogbuf) - 2;
	//free2 = LOGBUFSIZE - strlen(logbuf) - 2;

	free = QLOGBUFSIZE - qloglen - 2;
	free2 = LOGBUFSIZE - loglen - 2;

	if (qloglen == 0)
		target = qlogbuf;
	if (loglen == 0)
		target2 = logbuf;

	//dout("qlog_debug: free2=%d, loglen=%d, strlen(logbuf)=%d, (target2-logbuf)=%d\n", free2, loglen, strlen(logbuf), (target2 - logbuf));

	if (connectedclient == 0) {
		// Jcq: This is the old quicklog stuff, it doesn't have to do with the bug
		while (len > free) {
			ptr = strchr(qlogbuf, '\n');
			shift = ++ptr - qlogbuf;
			memmove(qlogbuf, qlogbuf + shift, QLOGBUFSIZE - shift + 1);
			free += shift;
			qloglen -= shift;
			target -= shift;
		}
		//strcat(qlogbuf,line);
		strcpy(target, line);
		target += len;
		if (strchr(line, '\n') == 0) {
			qloglen++;
			if (strchr(line, '\r') == 0) {
				qloglen++;
				//strcat(qlogbuf, "\r");
				*target++ = '\r';
			}
			//strcat(qlogbuf, "\n");
			*target++ = '\n';
		}
		*target = '\0';
		qloglen += len;
	}
	// Jcq: This is the stuff you'd need to look at (newest quicklog code)

	while (len > free2) {
		ptr = strchr(logbuf, '\n');
		shift = ++ptr - logbuf;
		memmove(logbuf, logbuf + shift, LOGBUFSIZE - shift + 1);
		free2 += shift;
		loglen -= shift;
		target2 -= shift;
	}
	//strcat(logbuf,line);
	strcpy(target2, line);
	target2 += len;
	if (strchr(line, '\n') == 0) {
		loglen++;
		if (strchr(line, '\r') == 0) {
			loglen++;
			//strcat(logbuf, "\r");
			*target2++ = '\r';
		}
		//strcat(logbuf, "\n");
		*target2++ = '\n';
	}
	*target2 = '\0';
	loglen += len;

	while (id) {
		if (id->fd == -1) {
			id->qlog++;
		}
		id = id->next;
	}

	return 0;
}

int sendqueue (int fd)
{
	char *buf;
	int bytessent=0;
	int totbs=0;
	//int bytestosend=0;
	int i=0;
	int buflen=0;
	int *sendqsize;
	int tosend=0;
	struct CLIENTS *c = getclient(fd);

	if (fd == servinfos.sockfd) {
		buf = s_sendqbuf;
		sendqsize = &s_sendqsize;
	}
	else if (c != 0) {
		buf = c->c_sendqbuf;
		sendqsize = &c->c_sendqsize;
	}
	else {
		alog("sendqueue(): bad fd. Shouldn't happen");
		return -1;
	}

	if (*buf == '\0') {
		return 0;
	}

	/*if ((bytessent = write(fd, buf, strlen(buf))) == strlen(buf)) {
		*buf = '\0';
	}
	*/

	buflen = strlen(buf);
	if (buflen != *sendqsize) {
		dout("sendqueue(): Damn, sendqsize=%d and buflen=%d\n", *sendqsize, buflen);
		//buflen = *sendqsize;
	}


	while (totbs < buflen) {
		if ((buflen - totbs) >= 1024)
			tosend = 1024;
		else
			tosend = buflen - totbs;
		if (tosend <= 0) {
			dout("Strange shit!\n");
			return totbs;
		}
		bytessent = write(fd, buf+i, tosend);




		/*if (strlen(buf+i) > 1024) {
			if ((bytessent = write(fd, buf+i, 1024)) == 1024) {
				totbs += bytessent;
				*sendqsize -= bytessent;
				i += bytessent;
				continue;
			}
		}
		else {*/

		if (bytessent == tosend) {
			totbs += bytessent;
			i += bytessent;
			*sendqsize -= bytessent;
			if (totbs == buflen) {
				if (*sendqsize != 0) {
					dout("sendqueue(): Shit!, sendqsize=%d and strlen(buf+i)=%zu\n", *sendqsize, strlen(buf+i));
					*sendqsize = 0;
				}
				*buf = '\0';
				dout("sendqueue() cleared!\n");
				//return totbs;
			}
			//return 0;
		}

		else if (bytessent == -1) {
			dout("sendqueue(): Write error: bufsize=%d and bytessent=%d and totbs=%d (%d) %s\n", buflen, bytessent, totbs, errno, strerror(errno));
			errno=0;
			if (totbs > 0) {
				memmove(buf,buf+totbs,(SENDQSIZE - totbs + 1));
			}
			return totbs;
		}
		else {
			totbs += bytessent;
			i += bytessent;
			*sendqsize -= bytessent;
			memmove(buf,buf+totbs,(SENDQSIZE - totbs + 1));
			dout("sendqueue(): no error but ... bufsize=%d and bytessent=%d and totbs=%d\n", buflen, bytessent, totbs);
			return totbs;
		}
	}

	if ((c != 0) && (c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT == 1) && (*sendqsize == 0)) {
		dout("Done with sending all sendq to client. Disconnecting client.\n");
		c->DISCONNECT_CLIENT_WHEN_SENDQ_SENT = getctime();
	}

	return totbs;
}

int addqueue (int fd, char *text, int n)
{
	char *buf;
	int buflen=0;
	int textlen=0;
	int *sendqsize;
	struct CLIENTS *c = getclient(fd);

	if (fd == servinfos.sockfd) {
		buf = s_sendqbuf;
		sendqsize = &s_sendqsize;
	}
	else if (c != 0) {
		buf = c->c_sendqbuf;
		sendqsize = &c->c_sendqsize;
		active_c = c;
	}
	else {
		alog("addqueue(): This shouldn't have happened");
		return -1;
	}

	buflen = strlen(buf);
	textlen = n;

	if (*sendqsize != buflen) {
		dout("addqueue(): Damn, sendqsize=%d and strlen(buf)=%d\n", *sendqsize, buflen);
		alog("addqueue(): Damn, sendqsize=%d and strlen(buf)=%d\n", *sendqsize, buflen);
		//buflen = *sendqsize;
	}

	if ((buflen + textlen) > SENDQSIZE) {
		// Max SendQ exceeded!
		if (c != 0) {
			if (clientcount() < 2) {
				sendt(servinfos.sockfd, "away :forced detach.");
				alog("Dropping client connection (%s). Max SendQ exceeded", c->ip);
			}
		}
		else {
			alog("Dropping server connection. Max SendQ exceeded");
			//sendt(servinfos.clientfd, "ERROR :Max SendQ exceeded .. dropping server connection");
			gnotice("ERROR :Max SendQ exceeded .. dropping server connection");
			closeserver();
		}

		cleanclients();
		return -1;
	}

	*sendqsize += n;
	//strncat(buf,text, n);
	memcpy(buf+buflen, text, n);
	*(buf + buflen + n) = '\0';
	return 0;
}

int clearqueue (char who)
{
	//Syntax: clearqueue('s') or clearqueue('c')
	char *buf;
	int *sendqsize;
	struct CLIENTS *c = active_c;

	if (who == 's') {
		buf = s_sendqbuf;
		sendqsize = &s_sendqsize;
	}
	else if (who == 'c') {
		buf = c->c_sendqbuf;
		sendqsize = &c->c_sendqsize;
	}
	else {
		alog("clearqueue(): This shouldn't have happened");
		return -1;
	}

	memset(buf,0,SENDQSIZE+1);
	*sendqsize = 0;
	return 0;
}

int mywrite (int tofd, char *buf, int n)
{
	int bytessent=0;
	char *ptrbuf;
	int totbs=0;
	int i=0;
	int buflen=0;
	int tosend=0;
	struct CLIENTS *c = getclient(tofd);

	if (tofd == -1) {
		dout("no real destination ...\n");
		return -1;
	}
	else if (tofd == servinfos.sockfd)
		ptrbuf = s_sendqbuf;
	else if (c != 0)
		ptrbuf = c->c_sendqbuf;
	else {
		bytessent = write(tofd,buf,n);
		return bytessent;
	}

	if (n > strlen(buf)) {
		dout("mywrite(): What the hell ? n=%d and strlen(buf)=%zu\n", n, strlen(buf));
		alog("mywrite(): error ...");
		dout("buf[n-2] = %d and buf[n-1] = %d", buf[n-2], buf[n-1]);
		dout("and buf = %s\n", buf);
		n = strlen(buf);
		//return -1;
	}


	buflen = n;

	if ((ptrbuf != 0) && (*ptrbuf != '\0')) {
		//sendqueue(tofd);
		//if (addqueue(tofd,buf+bytessent,n-bytessent) != -1)
		//	sendqueue(tofd);
		addqueue(tofd,buf+bytessent,n-bytessent);
	}
	else {
		while (totbs < buflen) {
			if ((buflen - totbs) >= 1024)
				tosend = 1024;
			else
				tosend = buflen - totbs;

			if (tosend <= 0) {
				dout("Strange shit: totbs=%d\n", totbs);
				alog("Strange shit: totbs=%d", totbs);
				return totbs;
			}

			bytessent = write(tofd, buf+i, tosend);

			if (bytessent == tosend) {
				totbs += bytessent;
				i += bytessent;
				if (totbs == buflen) {
					return totbs;
				}
			}

			else if (bytessent == -1) {
				dout("mywrite(): Write error: bufsize=%d and bytessent=%d and totbs=%d (%d) %s\n", buflen, bytessent, totbs, errno, strerror(errno));
				errno=0;
				addqueue(tofd,buf+totbs,n-totbs);
				return totbs;
			}
			else {
				totbs += bytessent;
				i += bytessent;
				dout("mywrite(): adding to queue ... bufsize=%d and bytessent=%d and totbs=%d\n", buflen, bytessent, totbs);
				addqueue(tofd,buf+totbs,n-totbs);
				return totbs;
			}
		}



		/*if ((bytessent = write(tofd,buf,n)) != n) {
			//alog("Write error: n=%d and bytessent=%d (%d) %s", n, bytessent, errno, strerror(errno));
			dout("Write error: n=%d and bytessent=%d (%d) %s\n", n, bytessent, errno, strerror(errno));
			errno=0;
			if (bytessent <= 0) {
				addqueue(tofd,buf,n);
			}
			else {
				addqueue(tofd,buf+bytessent,n-bytessent);
			}
		}*/
	}
	return totbs;
}

int qlogts(char* buf)
{
	if (SHORTTS)
		strcat(buf, shortts());
	else
		strcat(buf, timestamp());
	return SHORTTS;
}

char* timestamp()
{
	struct tm *today;
	time_t ltime;
	static char *ts = 0;
	int month=0;

	if (ts == 0) {
		ts = malloc(sizeof(char) * 17);
		if (ts == 0) {
			alog("timestamp(): malloc() error");
			return 0;
		}
	}

	time(&ltime);
	ltime += 3600 * TIMEZONE;
	today = gmtime(&ltime);

	month = today->tm_mon;
	if (month < 0)
		month += 12;
	month += 1;
	sprintf(ts, "[%.2d-%.2d %.2d:%.2d:%.2d]", today->tm_mday, month, today->tm_hour, today->tm_min, today->tm_sec);
	return ts;
}

char* shortts()
{
	struct tm *today;
	time_t ltime;
	static char *ts = 0;

	if (ts == 0) {
		ts = malloc(sizeof(char) * 17);
		if (ts == 0) {
			alog("timestamp(): malloc() error");
			return 0;
		}
	}

	time(&ltime);
	ltime += 3600 * TIMEZONE;
	today = gmtime(&ltime);

	sprintf(ts, "[%.2d:%.2d]", today->tm_hour, today->tm_min);
	return ts;
}


int sendlog (int fd, int type, int size, char *chan)
{
	/* Types:
	0: All channels + privates (everything)
	1: Only privates
	2: One specific channel only
	*/

	char *ptr;
	static char *line = 0;
	int i=0;
	int j=0;
	int a=0;
	static char** w=0;
	//int wcount=0;
	int sent=0;
	int logtbufsize=0;
	struct CLIENTS *c = getclient(fd);

	if (c == 0) {
		alog("Unexpected error in sendlog()");
		exit(1);
	}
	if (w == 0) {
		w = malloc(sizeof(char *) * (MAXWORDS+1));
		if (w == 0) {
			alog("malloc() error");
			exit(1);
		}
	}
	if (line == 0) {
		line = malloc(sizeof(char) * 2048);
		if (line == 0) {
			alog("malloc() error");
			exit(1);
		}
	}

	if (*logbuf == '\0')
		return 0;
	//ptr = logbuf + strlen(logbuf);
	ptr = logbuf;
	dout("ok0\n");
	while (*++ptr != '\0')
		a++;
	if (ptr > (logbuf + LOGBUFSIZE))
		alog("sendlog(): Bug! ptr > (logbuf + LOGBUFSIZE)");
	while ((ptr > logbuf) && (*--ptr != '\n'));
	*logtbuf = 0;


	// Below is the last line showed in debug before the program cores.
	dout("len = %d\n", a);
	a=0;

	if (type == 0) {
		//if (connectedserver == 0)
		//	SENDING_QLOG_BEFORE_DISCONNECTING = 1;
		//dout("sending log ...\n");
		for (i=0; i<size; i++) {
			j=0;
			if (ptr <= logbuf)
				break;
			while (*--ptr != '\n') {
				j++;
				if (ptr <= logbuf) {
					ptr--;
					break;
				}
			}
			j++;
			//if (j > 512)
			//	dout("Yep, the program would have died now if you didn't change sizeof(line)\n");
			if (j > 0) {
				strncpy(line, ptr+1, 2047);
				line[2047] = '\0';
				//wcount = readline(line, w, MAXWORDS, -10);
				readline(line, w, MAXWORDS, -10);
				if (logtbufsize != 0) {
					memmove(logtbuf+j, logtbuf, logtbufsize+1);
					if (*(logtbuf + j + logtbufsize) != '\0')
						dout("uhmmmm, missing endchar ?\n");
					memcpy(logtbuf, ptr+1, j);
				}
				else
					memcpy(logtbuf, ptr+1, j+1);
				logtbufsize += j;
			}
		}
	}
	// No need to look below, the program has already cored.
	else if (type == 1) {
		//if (connectedserver == 0)
		//	SENDING_QLOG_BEFORE_DISCONNECTING = 1;
		//dout("sending log ...\n");
		i=0;
		while (i < size) {
		//for (i=0; i<size; i++) {
			j=0;
			if (ptr <= logbuf)
				break;
			while (*--ptr != '\n') {
				j++;
				if (ptr <= logbuf) {
					ptr--;
					break;
				}
			}
			j++;
			if (j > 0) {
				strncpy(line, ptr+1, j);
				line[j] = '\0';
				//wcount = readline(line, w, MAXWORDS, -10);
				readline(line, w, MAXWORDS, -10);
				if (((strcasecmp(w[1], "PRIVMSG") == 0) || (strcasecmp(w[1], "NOTICE") == 0)) && (w[2][0] != '#') && (w[2][0] != '&')) {
					if (logtbufsize != 0) {
						memmove(logtbuf+j, logtbuf, logtbufsize+1);
						memcpy(logtbuf, ptr+1, j);
					}
					else
						memcpy(logtbuf, ptr+1, j+1);
					logtbufsize += j;
					i++;
				}
			}
		}
	}
	else if (type == 2) {
		//if (connectedserver == 0)
		//	SENDING_QLOG_BEFORE_DISCONNECTING = 1;
		//dout("sending log ...\n");
		i=0;
		while (i < size) {
		//for (i=0; i<size; i++) {
			j=0;
			if (ptr <= logbuf)
				break;
			while (*--ptr != '\n') {
				j++;
				if (ptr <= logbuf) {
					ptr--;
					break;
				}
			}
			j++;
			if (j > 0) {
				strncpy(line, ptr+1, j);
				line[j] = '\0';
				//wcount = readline(line, w, MAXWORDS, -10);
				readline(line, w, MAXWORDS, -10);
				if (((strcasecmp(w[1], "PRIVMSG") == 0) || (strcasecmp(w[1], "NOTICE") == 0)) && (strcasecmp(w[2], chan) == 0)) {
					if (logtbufsize != 0) {
						memmove(logtbuf+j, logtbuf, logtbufsize+1);
						memcpy(logtbuf, ptr+1, j);
					}
					else
						memcpy(logtbuf, ptr+1, j+1);
					logtbufsize += j;
					i++;
				}
			}
		}
	}

	dout("about to send qlog\n");
	//sent = mywrite(fd, logtbuf, strlen(logtbuf));
	logtbuf[logtbufsize] = '\0';
	sent = mywrite(fd, logtbuf, logtbufsize);
	if (sent != strlen(logtbuf) && (connectedserver == 0)) {
		//DISCONNECT_CLIENT_WHEN_SENDQ_SENT = 1;
		//dout("Could not send complete sendq. Waiting before disconnecting\n");

		/*cptr = chanlist;
		while (cptr != 0) {
			sendt(sockfd, ":my.bnc NOTICE %s :End of log", cptr->c);
			cptr = cptr->next;
		}*/
	}
	dout("end of sendlog()\n");
	return 0;

}


int addclient (int fd, char *ip)
{
	struct CLIENTS *mem;
	struct CLIENTS *ptr;

	mem = malloc(sizeof(struct CLIENTS));
	if (!mem) {
		dout("malloc() failed\n");
		alog("malloc() failed");
		exit(1);
	}
	memset(mem,0,sizeof(struct CLIENTS));


	strncpy(mem->ip, ip, 15);
	if (strlen(ip) >= 15)
		mem->ip[15] = '\0';
	dout("New client from %s\n", mem->ip);
	mem->signon = getctime();
	mem->fd = fd;

	if (clients == 0) {
		clients = mem;
		//return 0;
	}
	else {
		ptr = clients;
		while (ptr->next) {
			ptr = ptr->next;
		}
		ptr->next = mem;
		mem->prev = ptr;
	}
	ptr = mem;



	ptr->bufc = malloc(BUFSZ+1);
	if (ptr->bufc == 0) {
		alog("malloc() error");
		exit(1);
	}
	ptr->obufc = malloc(BUFSZ+1);
	if (ptr->obufc == 0) {
		alog("malloc() error");
		exit(1);
	}

	if (ptr->c_sendqbuf == 0) {
		if ((ptr->c_sendqbuf = malloc(SENDQSIZE+1)) == 0) {
			alog("sendqueue: malloc() failed");
			dout("sendqueue: malloc() failed\n");
			exit(1);
		}
		*ptr->c_sendqbuf = '\0';
	}


	return 0;
}

int remclient_free (struct CLIENTS *c)
{
	struct IDENTS *id = c->ident;
	free(c->bufc);
	free(c->obufc);
	free(c->c_sendqbuf);
	if (id > 0) {
		id->fd = -1;
		id->lastseen = getctime();
		id->qlog = 0;
	}
	return 0;
}

int remclient (int fd)
{
	struct CLIENTS *ptr;
	struct CLIENTS *ptr2;
	struct IDENTS *id = 0;
	int a=0;
	int i=0;


	ptr = clients;
	while (ptr != 0) {
		if (ptr->fd == fd) {
			ptr->fd = -1;
			id = ptr->ident;
			if (id)
				gnotice("Lost client connection from %s (%s)", ptr->ip, id->ident);
			else
				gnotice("Lost client connection from %s", ptr->ip);
			remclient_free(ptr);
			if (ptr == clients) {
				clients = ptr->next;
				if (clients)
					clients->prev = 0;
				free(ptr);
				//return 0;
				a=1;
				i++;
				ptr = clients;
				continue;
			}
			if (ptr->prev) {
				ptr2 = ptr->prev;
				ptr2->next = ptr->next;
			}
			if (ptr->next) {
				ptr2 = ptr->next;
				ptr2->prev = ptr->prev;
			}
			ptr2 = ptr;
			ptr = ptr->next;
			free(ptr2);
			i++;
			a=1;
			continue;
			//free(ptr);
			//i++;
			//a=1;
		}
		ptr = ptr->next;
	}
	if (a == 1)
		return 0;
	return -1;
}

int cleanclients ()
{
	struct CLIENTS *ptr;
	struct CLIENTS *ptr2;

	ptr = clients;
	while (ptr != 0) {
		ptr2 = ptr->next;
		remclient_free(ptr);
		close(ptr->fd);
		free(ptr);
		ptr = ptr2;
	}
	clients=0;
	connectedclient = 0;
	active_c = 0;
	findlastfd();
	return 0;
}

struct CLIENTS* getclient (int fd)
{
	struct CLIENTS *ptr;

	if (fd < 0)
		return 0;
	ptr = clients;
	while (ptr != 0) {
		if (fd == ptr->fd)
			return ptr;
		ptr = ptr->next;
	}
	return 0;
}

int clientcount ()
{
	struct CLIENTS *ptr;
	int i = 0;

	ptr = clients;
	while (ptr != 0) {
		i++;
		ptr = ptr->next;
	}
	return i;
}


int addident (char *ident)
{
	struct IDENTS *mem;
	struct IDENTS *ptr;

	mem = malloc(sizeof(struct IDENTS));
	if (!mem) {
		dout("malloc() failed\n");
		alog("malloc() failed");
		exit(1);
	}
	memset(mem,0,sizeof(struct IDENTS));
	mem->fd = -1;


	//if (*ident == ':')
	//	ident++;
	strncpy(mem->ident, ident, IDENTLEN);
	strcpy(mem->ip, active_c->ip);
	mem->ident[IDENTLEN] = '\0';
	dout("new ident = %s\n", mem->ident);

	if (idents == 0) {
		idents = mem;
		return 0;
	}
	ptr = idents;
	while (ptr->next) {
		ptr = ptr->next;
	}
	ptr->next = mem;
	mem->prev = ptr;

	return 0;
}

int remident (char *ident)
{
	struct IDENTS *ptr;
	struct IDENTS *ptr2;
	int a=0;
	int i=0;


	if (*ident == ':')
		ident++;
	ptr = idents;
	while (ptr != 0) {
		if (strcasecmp(ptr->ident,ident) == 0) {
			if (ptr == idents) {
				idents = ptr->next;
				if (idents)
					idents->prev = 0;
				free(ptr);
				//return 0;
				a=1;
				i++;
				ptr = idents;
				continue;
			}
			if (ptr->prev) {
				ptr2 = ptr->prev;
				ptr2->next = ptr->next;
			}
			if (ptr->next) {
				ptr2 = ptr->next;
				ptr2->prev = ptr->prev;
			}
			ptr2 = ptr;
			ptr = ptr->next;
			free(ptr2);
			i++;
			a=1;
			continue;
			//free(ptr);
			//i++;
			//a=1;
		}
		ptr = ptr->next;
	}
	if (a == 1)
		return 0;
	return -1;
}

int cleanidents ()
{
	struct IDENTS *ptr;
	struct IDENTS *ptr2;

	ptr = idents;
	while (ptr != 0) {
		ptr2 = ptr->next;
		free(ptr);
		ptr = ptr2;
	}
	idents=0;
	return 0;
}

struct IDENTS* getident (char *ident)
{
	struct IDENTS *ptr;

	ptr = idents;
	while (ptr != 0) {
		if (strcasecmp(ident,ptr->ident) == 0)
			return ptr;
		ptr = ptr->next;
	}
	return 0;
}
