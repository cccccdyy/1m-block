#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <time.h>
#include "iphdr.h"
#include "tcphdr.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

set<string> blocked;
uint8_t dropflag;

void usage() {
	printf("<usage>\n");
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

void readfile(char* filename) {
	FILE* fp = fopen(filename, "r");
	if (!fp) {
		printf("FILE OPEN ERROR\n");
		exit(1);
	}

	uint32_t num;
	char host_to_filter[0x100];
	time_t before, after;
	double diff;
	time(&before);
	while (fscanf(fp, "%d,%s\n", &num, host_to_filter) != EOF) {
		string str(host_to_filter);
		blocked.insert(str);
	}
	time(&after);
	diff = difftime(after, before);
  	printf("diff time : %lf\n", diff);

	fclose(fp);
	return;
}

void dump(unsigned char* buf, int size) {

	time_t before, after;
	double diff;

	char buf_copy[size+1];
	memset(buf_copy, 0, size); // null
	memcpy(buf_copy, buf, size); 

	uint32_t ipv4hdr_len = ((PIpHdr)buf_copy)->ip_len * 4; // ipv4 header length
	char* tcp_header = buf_copy + ipv4hdr_len;
	uint32_t tcphdr_len = ((PTcpHdr)tcp_header)->th_off * 4; // tcp header length;
	char* http_header = buf_copy + (ipv4hdr_len + tcphdr_len);
	uint32_t http_len = size - (ipv4hdr_len + tcphdr_len); // http length

	/* check tcp */
	if (((PIpHdr)buf_copy)->proto != 6) {
		printf("[NOT TCP PACKET]\n");
		dropflag = 0;
		return;
	}
	/* check http */
	if (http_len == 0) {
		printf("[NOT HTTP PACKET]\n");
		dropflag = 0;
		return;
	}
	if(memcmp(http_header, "GET", 3) && memcmp(http_header, "POST", 4) && memcmp(http_header, "HEAD", 4) && memcmp(http_header, "OPTIONS", 7) && \
		memcmp(http_header, "PUT", 3) && memcmp(http_header, "DELETE", 6) && memcmp(http_header, "PATCH", 5) && memcmp(http_header, "CONNECT", 7) && memcmp(http_header, "TRACE", 5) && memcmp(http_header, "HTTP", 4)){
		printf("[NOT HTTP PACKET]\n");
		dropflag = 0;
		return;
	}

	printf("\n[IP] : \n");
	for (int i = 0; i < ipv4hdr_len; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n[TCP] : \n");
	for (int i = 0; i < tcphdr_len; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[ipv4hdr_len + i]);
	}
	printf("\n[HTTP] : \n");
	for (int i = 0; i < size - (ipv4hdr_len + tcphdr_len); i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[ipv4hdr_len + tcphdr_len + i]);
	}
	
	/* get hostname */
	char* host = strstr(http_header, "Host: ");
	if (host) {
		host = strtok(host + 6, "\r\n");
		time(&before);
		bool exist = blocked.find(host) != blocked.end() ? true : false;
		time(&after);
		diff = difftime(after, before);
  		printf("\ndiff time : %lf\n", diff);
		if (exist) dropflag = 1; // hostname is in the blocked site list
		else dropflag = 0;
	}
	else dropflag = 0;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
		dump(data, ret);
	}	

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(dropflag) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{	
	if (argc != 2) {
		usage();
		return 0;
	}
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	readfile(argv[1]); // read site list file 

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}