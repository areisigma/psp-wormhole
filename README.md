# psp-adhoc-proxy
AdHoc Proxy for PSP connection
##
### Requirements
Npcap 1.60
  You should install support for raw 802.11 packets.
##
### Few word of mine, what is a thing I'm working on
This is my attempt of creating infrastructure through AdHoc. I doing it to play Patapon 3 online.
Since PSP servers are down for a long time and will never be up again, I'm creating my own using the only possible way to communicate consoles.
##
### What's the plan?
So there is this Ad Hoc system. I'm diggin deep inside it to find a way to connect it to PC and then use a computer as proxy server.
Then proxy will send all traffic to defined server (a player who will host a session).
This solve won't be efficient, since program will send broadcastly (?) to every player. (Yeah I think i will solve it later, firstly I will connect two devices)
##
### What direction this project is moving in?
I ended up using Npcap c++ architecture. It's more understandable to me than writing my own driver for network card.
Application scans available network interfaces, user must choose wireless adapter. Then the adapter is opened and is capturing packets.
The problem is every user need network card, that can be set in promiscuous/monitor mode. Since not every adapter can be set to monitor, I have to implement associaton with Ad Hoc network. I know my only monitor-mode adapter can actually be set to monitor mode, not only promiscuous. Even now I cannot see every packet, so I think i didn't put it in monitor, but promiscuous mode and now I see packets from other other devices from my local network.
