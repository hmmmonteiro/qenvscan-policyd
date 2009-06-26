/* qenvscan-policyd.c
 * an c frontend to Postfix Access Policy servers to use primary whith qmail
 * 
 *
 * Based on code by Anton Lundin <glance@acc.umu.se>
 * Adapted by Hugo Monteiro <hugo.monteiro@fct.unl.pt>
 *
 * Licence: GPL 2+
 */

/*
 * A postfix smtpd_access_policy call looks like:
 *
 * These are what we have and matter at RCPT state
 *
 * request=smtpd_access_policy
 * protocol_name=SMTP
 * protocol_state=RCPT
 * sender=foo@bar.tld
 * recipient=bar@foo.tld
 * client_address=1.2.3.4
 * client_name=another.domain.tld
 * helo_name=some.domain.tld
 * 
 * The following ones are prior to RCPT or unavailable to us
 * 
 * queue_id=8045F2AB23
 * instance=123.456.7
 * sasl_method=plain
 * sasl_username=you
 * sasl_sender=
 * size=12345
 * [empty line]
 *
 * If greylisted, the policy server response contains
 * (answer should be treated case insensitive)
 * 
 * action=DEFER_IF_PERMIT
 * [empty line]
 *
 * If whitelisted, the policy server response contains
 * (answer should be treated case insensitive)
 * 
 * action=DUNNO
 * [empty line]
 *
 * If blacklisted, and policy server configured for permanent failure
 * (answer should be treated case insensitive)
 *
 * action=REJECT
 *
 * 
 * If any parameter (like helo_name=) is omited from the policy server,
 * or contains an empty string, for alphanumerical, or 0, for numerical values
 * then the policy server will disregard that particular parameter.
 * 
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>

#define EXIT_ERROR		102  /* something went wrong */
#define GREYLISTED		"Greylisted (see http://projects.puremagic.com/greylisting/)"
#define REJECTED		"You have been blacklisted. Contact you system administrator."
#define PLAIN			"plain"
#define CONNECT_TIMEOUT	10	/* timout connection to policyd server after 10 seconds */

/* nice to have to access keys */
enum KEY_REQ {
	KEY_REQUEST = 0,
	KEY_PROTO_NAME,
	KEY_PROTO_STATE,
	KEY_CLIENT_ADDR,
	KEY_CLIENT_NAME,
	KEY_SENDER,
	KEY_RCPT,
	KEY_HELO_NAME,
	KEY_INSTANCE,
	KEY_SIZE,
	KEY_RCPT_COUNT,
	KEY_SASL_METHOD,
	KEY_SASL_USERNAME
};

/* policyd keys */
struct pkeys {
	char *key;
	char *val;
	unsigned int ksize;
	unsigned int vsize;
};

/* macro to build array of keys, precompute available sizes to speed up */
#define ARRAYADD(k,v)  { k, v, sizeof k - 1, sizeof v - 1 }

/* policyd protocol keys. NULLs will be filled runtime (or not) */
struct pkeys keys[] = {
	ARRAYADD("request=",        	"smtpd_access_policy"),
	ARRAYADD("protocol_name=",  	"SMTP"),
	ARRAYADD("protocol_state=", 	"RCPT"), /* defaults to RCPT, rebuilt later if defined */
	ARRAYADD("client_address=", 	NULL), /* build later: must exist */
	ARRAYADD("client_name=",    	NULL), /* build later: must exist */
	ARRAYADD("sender=",         	NULL), /* build later: must exist */
	ARRAYADD("recipient=",      	NULL), /* build later: must exist */
	ARRAYADD("helo_name=",		NULL), /* build later: must exist */
	ARRAYADD("instance=",      	NULL), /* build later: may exist */
	ARRAYADD("size=",           	NULL), /* build later: may exist */
	ARRAYADD("recipient_count=",	NULL), /* build later: may exist */
	ARRAYADD("sasl_method=",	NULL), /* build later: may exist */
	ARRAYADD("sasl_username=",	NULL), /* build later: may exist */
	{ NULL, NULL, 0, 0 }
};

/* macro to add new values+vsizes to keys */
#define KEYSET(i,v) \
	keys[i].val = v; \
	keys[i].vsize = keys[i].val ? strlen(keys[i].val) : 0;

/* policy actions */
struct pactions {
	char *act;
	unsigned int ret;
};

/* policyd action keys */
struct pactions actions[] = {
	{ "DEFER_IF_PERMIT", 	101 }, /* tempfail, aka graylist */
	{ "DEFER",		101 }, /* tempfail, aka graylist */
	{ "REJECT_IF_PERMIT",	100 }, /* permanent reject of mail */ 
	{ "REJECT",		100 }, /* permanent reject of mail */
	{ "DUNNO",		0 },   /* good to go, accept email */
	{ NULL,			EXIT_ERROR }  /* default */
};

#define ORDERLY_EXIT(e) \
	if (sock >= 0) close(sock); \
	if (query) free(query); \
	exit(e);

void usage(char *err)
{
	printf("qenvscan-policyd: %s\n", err);
	exit(EXIT_ERROR);
}

void 
sig_alrm(int signum)
{
   fprintf(stderr,"Policy server connect timeout: %s\n", strerror(errno));
   exit(EXIT_ERROR);
}

int main(int argc, char *argv[])
{
	int i, j, sock, size, policyd_port, len ;
	long lpolicyd_port;
	struct sockaddr_in saddr;
	struct hostent *hp;
	char answer[32];
	char *policyd_server, *policyd_env_port, *end_ptr;
	/* smtp data */
	char *remoteip, *smtp_state, *sender, *recipient, *helo, *mailsize, *rcpt_count, *instance;
	char *query, *p;

	query = NULL;
	sock = -1;

	sender = recipient = helo = NULL;

	/* get envelope data, either from command line of env */
#ifdef QENVSCAN_LEGACY
	/* if LEGACY we expect to get something from command line or FAIL */
	if (argc != 3 && argc != 4 && argc != 5)
		usage("use with qenvscan-policyd mailfrom.s addr.s [ helohost.s [ size ] ]");
	
	sender = argv[1];
	recipient = argv[2];
	helo = argv[3];
	mailsize = (argc == 5) ? argv[4] : NULL;
#else
	/* if !LEGACY we expect to get something from env or FAIL */
	sender = getenv("SENDER");
	recipient = getenv("RECIPIENT");
	helo = getenv("HELO");

	if (!sender || !recipient || !helo)
		usage("you need to define HELO, SENDER and RECIPIENT");

#endif
	policyd_server = getenv("POLICYD_SERVER");
	policyd_env_port = getenv("POLICYD_PORT");
	remoteip = getenv("TCPREMOTEIP");
	mailsize = getenv("SIZE");
	rcpt_count = getenv("RCPTCOUNT");
	instance = getenv("SESSIONID");

	if ( !remoteip || !policyd_server || !policyd_env_port )
		usage("TCPREMOTEIP, POLICYD_SERVER or POLICYD_PORT not set!");

	errno = 0;

	lpolicyd_port = strtol(policyd_env_port, &end_ptr, 0);

	if ( errno != 0 || lpolicyd_port < INT_MIN || 
			lpolicyd_port > INT_MAX || *end_ptr != '\0')
		usage("invalid POLICYD_PORT port number");

	policyd_port = (int)lpolicyd_port;

	/* set runtime envelope keys: */

	KEYSET(KEY_CLIENT_ADDR, remoteip);

	p = getenv("SMTPSTATE");
	if (p) /* override the default */
		KEYSET(KEY_PROTO_STATE, p);

	p = getenv("AUTH_USER");
	if (p) { /* set authenticated username if available */
		KEYSET(KEY_SASL_METHOD, PLAIN);
		KEYSET(KEY_SASL_USERNAME, p);
	}
	
	KEYSET(KEY_RCPT_COUNT, rcpt_count);

	KEYSET(KEY_INSTANCE, instance);

	p = getenv("TCPREMOTEHOST");
	if (!p) p = keys[KEY_CLIENT_ADDR].val;
	KEYSET(KEY_CLIENT_NAME, p);

	KEYSET(KEY_SENDER, sender);
	KEYSET(KEY_RCPT, recipient);

	/* these may exist or not */
	if (helo)
		KEYSET(KEY_HELO_NAME, helo );
	if (mailsize)
		KEYSET(KEY_SIZE, mailsize );

	/* calculate buffer size */
	for ( len = 1, i = 0 ; keys[i].key ; i++ ) {
		if (keys[i].val) /* just add if val != NULL */
			len += (keys[i].ksize + keys[i].vsize + 1);
	}

	query = malloc(len);
	if (!query) {
		fprintf(stderr,"Failed to alloc memory for query: %s\n", strerror(errno));
		exit(EXIT_ERROR);
	}

	/* fill query buffer */
	for ( j = i = 0 ; keys[i].key && i < len ; i++ ) {
		if (keys[i].val) { /* just put entry if val != NULL */
			strncpy(query + j, keys[i].key, keys[i].ksize);
			j += keys[i].ksize;

			strncpy(query + j, keys[i].val, keys[i].vsize);
			j += keys[i].vsize;

			query[j++] = '\n'; /* and so we have a key = val line */
		}
	}
	query[j++] = '\n';
	query[j++] = '\0';

	/* init so we have all the structs for connect */
	bzero(&saddr, sizeof (saddr));
	saddr.sin_family = AF_INET;

	if ((hp = gethostbyname(policyd_server)) == NULL) {
		perror("gethostbyname");
		ORDERLY_EXIT(EXIT_ERROR);
	}

	bcopy(hp->h_addr, &saddr.sin_addr, hp->h_length);
	saddr.sin_port = htons(policyd_port);

	/* get a socket */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("socket");
		ORDERLY_EXIT(EXIT_ERROR);
	}

	/* set alarm handler */
	signal(SIGALRM, sig_alrm);
	alarm(CONNECT_TIMEOUT);

	/* connect the socket to the other end */
	if (connect(sock, (struct sockaddr *)&saddr, sizeof (saddr)) != 0) {
		if (errno != EINPROGRESS)
		{
			perror("connect");
			ORDERLY_EXIT(EXIT_ERROR);
		}
		alarm( 0 ); /* cancel alarm */
	}

	/* send the query */
	if ( send(sock,query,strlen(query),0) != strlen(query)) {
		perror("send");
		ORDERLY_EXIT(EXIT_ERROR);
	}
	/* recive the answer from policy daemon */
	if ( (size = recv(sock, query, strlen(query), 0)) <= 0 ) {
		fprintf(stderr,"Policy server recv error or shutdown: %s\n", strerror(errno));
		ORDERLY_EXIT(EXIT_ERROR);
	}

	/* don't overflow query buffer */
	query[size - 1] = '\0';
    
	/* pase out the action=? */
	if (sscanf(query,"action=%31s",answer) < 1 ) {
		fprintf(stderr,"Policy server response contains no action: %s\n", query);
		ORDERLY_EXIT(EXIT_ERROR);
	}

	/* figure out how to exit */
	for ( i = 0 ; actions[i].act ; i++ ) {
		if ( strcasecmp(answer,actions[i].act) == 0 ) {
#ifdef DEBUG
			fprintf(stderr,"qenscan-policyd: server response was: %s\n", query);
#endif
			ORDERLY_EXIT(actions[i].ret);
			break; /* well ... */
		}
	}

	/* actions fall to last element. ret defines the default return */
	fprintf(stderr,"Policy server response is strange to me : %s\n",query);
	ORDERLY_EXIT(actions[i].ret);

}
