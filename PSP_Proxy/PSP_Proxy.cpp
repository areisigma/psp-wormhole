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

	IDot11AdHocManager *adhocManager = 0;
	IDot11AdHocSecuritySettings *adhocSec = 0;
	IDot11AdHocNetwork *adhocNetwork = 0;
																// I don't know
	DOT11_ADHOC_AUTH_ALGORITHM *authAlgo = 0;
	*authAlgo = DOT11_ADHOC_AUTH_ALGO_80211_OPEN;

	if (adhocSec->GetDot11AuthAlgorithm(authAlgo) == S_OK) {
		printf("[+] Auth -> OK");
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
		printf("[+] Network created");
	}



	return 1;
}