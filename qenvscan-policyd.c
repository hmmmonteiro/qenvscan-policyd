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


#define SIZEOF_INT		sizeof(int)

#define ANSWER_GREYLIST	"DEFER_IF_PERMIT"
#define ANSWER_GO		"DUNNO"
#define ANSWER_PERM		"REJECT"
#define EXIT_GO			0   /* good to go, accept email */
#define EXIT_PERM		100 /* permanent reject of mail */
#define EXIT_TEMP		101 /* tempfail, aka graylist */
#define EXIT_ERROR		102  /* something went wrong */
#define GREYLISTED		"Greylisted (see http://projects.puremagic.com/greylisting/)"
#define REJECTED		"You have been blacklisted. Contact you system administrator."

int main(int argc, char *argv[]) {
    int i, j, sock, size, policyd_port, len ;
	int keylen=0, valuelen=0;
	long lpolicyd_port;
    struct sockaddr_in saddr;
    struct hostent *hp;
    char answer[32];
	char *policyd_server, *policyd_env_port, *end_ptr;

	char *key[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	char *value[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	char *query;
	
	int keylens[8];
	int valuelens[8];

	policyd_server = getenv("POLICYD_SERVER");
	policyd_env_port = getenv("POLICYD_PORT");
	
    if ((argc < 3 ) || getenv("TCPREMOTEIP") == NULL || policyd_server == NULL || policyd_env_port == NULL ) {
        fprintf(stderr,"usage:  qenvscan-policyd mailfrom.s addr.s [helohost.s]\n");
        if ( getenv("TCPREMOTEIP") == NULL || policyd_server == NULL || policyd_env_port == NULL ) {
            fprintf(stderr,"TCPREMOTEIP, POLICYD_SERVER or POLICYD_PORT not set!\n");
        }
        exit(EXIT_ERROR);
    } else {
		errno=0;
		lpolicyd_port = strtol(policyd_env_port, &end_ptr, 0);
		if ( (errno != 0) || (lpolicyd_port < INT_MIN) || (lpolicyd_port > INT_MAX) || (*end_ptr != '\0')) {
			fprintf(stderr, "qenvscan-policyd: invalid POLICYD_PORT port number\n");
			exit(EXIT_ERROR);
		} else
			policyd_port = (int)lpolicyd_port;
    }

	key[0] = "request=";
	key[1] = "protocol_name=";
	key[2] = "protocol_state=";
	key[3] = "client_address=";
	key[4] = "client_name=";
	key[5] = "sender=";
	key[6] = "recipient=";
	key[7] = argv[3] != NULL ? "helo_name=" : 0;

	value[0] = "smtpd_access_policy";
	value[1] = "SMTP";
	value[2] = "RCPT";
	value[3] = getenv("TCPREMOTEIP");
	value[4] = getenv("TCPREMOTEHOST") != NULL ? getenv("TCPREMOTEHOST") : getenv("TCPREMOTEIP");
	value[5] = argv[1];
	value[6] = argv[2];
	value[7] = argv[3] != NULL ? argv[3] : 0;

	for (i=0;i<sizeof(key)/SIZEOF_INT;i++) {
		if (key[i] != NULL) {
			keylens[i] = strlen(key[i]);
			keylen += keylens[i];
		}
	}

	for (i=0;i<sizeof(value)/SIZEOF_INT;i++) {
		if (value[i] != NULL) {
			valuelens[i] = strlen(value[i]);
			valuelen += valuelens[i];
		}
	}

	len = keylen + valuelen + sizeof(key)/SIZEOF_INT + 2;

	query = malloc(len);

	for (i=j=0;i<sizeof(key)/SIZEOF_INT && j<len;i++) {
		if (key[i] != NULL && value[i] != NULL) {
			strcpy(query+j, key[i]);
			j += keylens[i];
			strcpy(query+j, value[i]);
			j += valuelens[i];
			query[j++] = '\n';
		}
	}
	query[j++] = '\n';
	query[j++] = '\0';
	
    /* init so we have all the structs for connect */
    bzero(&saddr, sizeof (saddr));
    saddr.sin_family = AF_INET;

    if ((hp = gethostbyname(policyd_server)) == NULL) {
        perror("gethostbyname");
		free(query);
        return EXIT_ERROR;
    }

    bcopy(hp->h_addr, &saddr.sin_addr, hp->h_length);
    saddr.sin_port = htons(policyd_port);

    /* get a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket");
		free(query);
        return EXIT_ERROR;
    }

    /* connect the socket to the other end */
    if (connect(sock, (struct sockaddr *)&saddr, sizeof (saddr)) != 0) {
        perror("connect");
		free(query);
        return EXIT_ERROR;
    }

    /* send the query */
    if ( send(sock,query,strlen(query),0) != strlen(query)) {
        perror("send");
		free(query);
        exit(EXIT_ERROR);
    }
    /* recive the answer from postgrey */
    size = recv(sock, query, strlen(query), 0);
    
    close(sock);
    /* pase out the action=? */
    if (sscanf(query,"action=%31s",answer) < 1 ) {
        perror("sscanf");
		free(query);
        exit(EXIT_ERROR);
    }

	free(query);
	
    /* figure out how to exit */
	if ( strcasecmp(answer,ANSWER_PERM) == 0) {
		/* is rejected */
		exit(EXIT_PERM);
	} else if ( strcasecmp(answer,ANSWER_GREYLIST) == 0) {
        /* is greylisted */
        exit(EXIT_TEMP);
    } else if ( strcasecmp(answer,ANSWER_GO) == 0) {
        /* is good to go */
        exit(EXIT_GO);
    } else {
        fprintf(stderr,"Policy server response is strange to me : %s\n",query);
        exit(EXIT_ERROR);
    }

    /* shud not happen, but anyway. */
    exit(EXIT_GO);
}
