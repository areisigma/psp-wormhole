#include <iostream>
#include <adhoc.h>


struct adhocNetworkInit {
	LPCWSTR name;						// Name
	LPCWSTR pass;						// Password
	LONG geo; // 0xbf (Poland)			// Geographical Info
	IDot11AdHocInterface* intf;			// AdHoc Interface (optional)
	IDot11AdHocSecuritySettings* sec;	// Security Settings
	GUID* contextGuid;					// List of available connections
	IDot11AdHocNetwork** iAdHoc;		// some output idk
};

int main() {

	printf("[*] Defining interfaces\n");

	IDot11AdHocManager *adhocManager;
	adhocManager = (IDot11AdHocManager*)std::malloc(sizeof(IDot11AdHocManager));

	IDot11AdHocSecuritySettings *adhocSec;
	adhocSec = (IDot11AdHocSecuritySettings*)std::malloc(sizeof(IDot11AdHocSecuritySettings));

	IDot11AdHocNetwork *adhocNetwork;
	adhocNetwork = (IDot11AdHocNetwork*)std::malloc(sizeof(IDot11AdHocNetwork));

																// I don't know
	printf("[*] Setting authentication algorythm\n");

	DOT11_ADHOC_AUTH_ALGORITHM *authAlgo = (tagDOT11_ADHOC_AUTH_ALGORITHM *)DOT11_ADHOC_AUTH_ALGO_80211_OPEN;
	//*authAlgo = DOT11_ADHOC_AUTH_ALGO_80211_OPEN;

	// Setting authentication algorithm
	if (adhocSec->GetDot11AuthAlgorithm(authAlgo) == S_OK) {
		printf("[+] Auth -> OK\n");
	}
	else {
		printf("[!] adhocAuth Failed\n");
	}

	// Struct with basic information of Ad Hoc Network
	adhocNetworkInit net;
	memset(&net, 0, sizeof(net));
	net.name = (LPCWSTR)"PSP Proxy";
	net.pass = 0;
	net.geo = 0xbf;
	net.intf = NULL; // first unused
	net.sec = adhocSec;
	net.contextGuid = NULL;
	net.iAdHoc = &adhocNetwork;

	// Some creation of network
	if (adhocManager->CreateNetwork(net.name, net.pass, net.geo, net.intf, net.sec, net.contextGuid, net.iAdHoc) == S_OK) {
		printf("[+] Network created\n");
	}
	else {
		printf("[!] Creating network failed\n");
	}

	DOT11_ADHOC_NETWORK_CONNECTION_STATUS *adhocNetworkStatus = 0;

	printf("%d\n", adhocNetwork->GetStatus(adhocNetworkStatus));


	std::free(adhocManager);
	std::free(adhocNetwork);
	std::free(adhocSec);

	return 1;
}
