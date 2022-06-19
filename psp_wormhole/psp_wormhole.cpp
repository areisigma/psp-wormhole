/*
	PSP Low Level WiFi Proxy

	Author:
		Olaf Struck

	Date:
		12.06.2022 (Birth bigger knowledge)


	I tried many solutions, but this seems to be the best. Low Level always wins. Simplicity in complexity!

*/

#pragma comment(lib,  "ws2_32.lib")

#include <iostream>
#include <stdio.h>
#include <string.h>

#include "pcap.h"

// C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\um
// Later I will include all headers to local project folder for everyone to have no issues to run.


#include <winsock.h>
//#include <WS2tcpip.h>
#include <tchar.h>


BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}



// Function prototypes
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


// Print available devices.
// I need is some basic networking. Sending/Capturing Beacon/Probe frames.

int main(int argc, char *argv[]) {

	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *aHandle;
	bpf_program fcode;
	bpf_u_int32 netmask;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];
	int adapter;
	int result;
	int cpid; // Capture child
	int tpid; // Transmit child

	// Load Npcap and its functions. 
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "[!] Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "[!] Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// Scan the list printing every entry 
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d);
	}

	printf("Choose WLAN adapter: ");
	scanf_s("%d", &adapter);
	printf("\nAdapter %d\n", adapter);

	// Chosing adapter
	d = alldevs;
	for (; adapter; adapter--)
	{
		d = d->next;
	}
	printf("%s\n", d->description);

	// Open handle for adapter
	if ((aHandle = pcap_open_live(d->name,
								65536,
								PCAP_OPENFLAG_PROMISCUOUS,
								1000,
								errbuf
	)) == NULL)
	{
		fprintf(stderr, "\n[!] Unable to open the adapter.");
	}

	// Check link layer, supporting only ethernet
	if (pcap_datalink(aHandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\n[!] This program works only on Ethernet networks\n");
		pcap_freealldevs(alldevs);
		pcap_close(aHandle);
		exit(1);
	}

	// Retrieve mask of selected network adapter
	if (d->addresses == NULL)
	{
		printf("[!] Device struct is NULL, cannot assign netmask");
		pcap_freealldevs(alldevs);
		pcap_close(aHandle);
		exit(1);
	}

	netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	printf("[+] Netmask assigned");

	// Compile the filter
	if ((result = pcap_compile(aHandle, &fcode, "", 1, netmask)) < 0) //wlan.ssid == PSP_AUCES01421_L_LABOMAT
	{
		fprintf(stderr, "\n[!] Error compiling filter: %s\n", pcap_statustostr(result));
		pcap_freealldevs(alldevs);
		pcap_close(aHandle);
		exit(1);
	}

	// Use the filter
	if ((result = pcap_setfilter(aHandle, &fcode)) < 0)
	{
		fprintf(stderr, "\n[!] Error setting the filter: %s\n", pcap_statustostr(result));
		pcap_freealldevs(alldevs);
		pcap_close(aHandle);
		exit(1);
	}


	// Start capturing
	pcap_loop(aHandle, 0, packet_handler, NULL);


	// Close everything that has to be closed
	pcap_freealldevs(alldevs);
	pcap_close(aHandle);
	system("pause");
	return 1;
}




/* Child birth
pid = fork();
if(pid != 0)
	printf("child created");
*/


// Packet handle function; is invoked for every incoming packet
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	(VOID)(param);
	printf("\nNew packet\n");
	printf("len: %d\n", header->len);
	printf("data: %s", pkt_data);
}


// Print all the available information on the given interface 
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	char ip6str[128];
	static int i = 0;

	// Name
	//printf("%s\n", d->name);


	if (d->description) {
		printf("[%2d] %s", i, d->description);
		i++;
	}

	// Loopback Address
	//printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	// IP addresses 
	/*for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}*/
	printf("\n");
}



// From tcptraceroute, convert a numeric IP address to a string 
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;


	sockaddrlen = sizeof(struct sockaddr_in6);

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
