// (c)2007 Andy Green <andy@warmcat.com>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

// Thanks for contributions:
// 2007-03-15 fixes to getopt_long code by Matteo Croce rootkit85@yahoo.it

#include <getopt.h>
#include <pcap.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const uint8_t radiotap_hdr[] = {

	0x00, 0x00, // <-- radiotap version
	0x19, 0x00, // <- radiotap header length
	0x6f, 0x08, 0x00, 0x00, // <-- bitmap
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
	0x00, // <-- flags
	0x0c, // <-- rate
	0x71, 0x09, 0xc0, 0x00, // <-- channel
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna
};

static const char wifi_hdr[] = {
	0x80, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x5e, 0xcf, 0x7f, 0xd9, 0xf8, 0xbf,
	0x5e, 0xcf, 0x7f, 0xd9, 0xf8, 0xbf,
	0xe0, 0x80
};

static const char mgmt_frame_first[] = {
	0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x11, 0x00, 0x00, 0x0c, 0x6d, 0x65,
	0x73, 0x68, 0x2d, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x37, 0x01, 0x08, 0x8b, 0x96, 0x82, 0x84,
	0x0c, 0x18, 0x30, 0x60, 0x03, 0x01, 0x0a, 0x05, 0x04, 0x01, 0x02, 0x00, 0x00, 0x25, 0x03, 0x01
};

static const char mgmt_frame_last[] = {
	0x03, 0x07, 0x06, 0x44, 0x4b, 0x20, 0x01, 0x0b, 0x14, 0x32, 0x04, 0x6c, 0x12, 0x24, 0x48,
	0xdd, 0x09, 0x18, 0xfe, 0x34, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
	
	0x30, 0x18, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x02, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f,
	0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
	
	0xdd, 0x1a, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x02, 0x00, 0x00, 0x50,
	0xf2, 0x04, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02
};


void
usage(void)
{
	printf(
		"(c)2006-2007 Andy Green <andy@warmcat.com>  Licensed under GPL2\n\n"
		"packet spammer\n=========================================="
		"\n"
		"Usage: packetspammer <interface> [options] \n\nOptions\n\n"
		"      -n/--number <nr packets> number of packets to send\n\n"
		"      -r/--rate   <rate> packets per second\n\n"
		"      -c/--channel <channel> channel to send as CSA\n\n"
		"\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	uint8_t buf[4092];
	char szErrbuf[PCAP_ERRBUF_SIZE];
	int r, nDelay = 100000;
	pcap_t *ppcap = NULL;
	char fBrokenSocket = 0;

	int rate    = 1;
	int number  = 50;
	int size    = 157;	// <- hardcoded length
	int channel = 7;
	
	while (1) {
		int nOptionIndex;
		static const struct option optiona[] = {
			{ "run", required_argument, NULL, 'R' },
			{ "rate", required_argument, NULL, 'r' },
			{ "number", required_argument, NULL, 'n' },
			{ "channel", required_argument, NULL, 'c' },
			{ "help", no_argument, NULL, 1 },
			{ 0, 0, 0, 0 }
		};

		int c = getopt_long(argc, argv, "R:r:n:c:h",
			optiona, &nOptionIndex);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0: // long option
			break;

		case 'h': // help
			usage();
			break;

		case 'r':
			rate = atoi(optarg);
			break;

		case 'n':
			number = atoi(optarg);
			break;

		case 'c':
			channel = atoi(optarg);
			break;

		default:
			printf("unknown switch %c\n", c);
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	// open the interface in pcap
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL) {
		printf("Unable to open interface %s in pcap: %s\n",
				argv[optind], szErrbuf);
		return 1;
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

	nDelay = 1000000 / rate;

	printf("rate %d\n", rate);
	printf("number %d\n", number);
	printf("delay %d\n", nDelay);
	printf("channel %d\n", channel);

	memset(buf, 0, sizeof(buf));

	while (!fBrokenSocket && number) {
		uint8_t *pu8 = buf;

		// radiotap header
		memcpy(buf, radiotap_hdr,
			sizeof(radiotap_hdr));
		pu8 += sizeof(radiotap_hdr);

		// wifi header
		memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
		pu8 += sizeof(wifi_hdr);

		// mgmt frame first part
		memcpy(pu8, mgmt_frame_first, sizeof(mgmt_frame_first));
		pu8 += sizeof(mgmt_frame_first);

		// Channel Switch Announcement channel
		*pu8 = channel;
		pu8++;
//		pu8 += sprintf((char *)pu8, "%02d ", channel);
		
		// mgmt frame last part
		memcpy(pu8, mgmt_frame_last, sizeof(mgmt_frame_last));
		pu8 += sizeof(mgmt_frame_last);

		// add number and size as payload
		pu8 += sprintf((char *)pu8, "%06d ", number);
		pu8 += sprintf((char *)pu8, "%06d ", size);

		// subtract 4 bytes here, since CRC is added by mac layer
		int packet_size = size + sizeof(radiotap_hdr) - 4;

		r = pcap_inject(ppcap, buf, packet_size);

		if(r != packet_size) {
			perror("Trouble injecting packet");
			return 1;
		}

		if(nDelay) {
			usleep(nDelay);
		}
		number--;
	}

	return 0;
}
