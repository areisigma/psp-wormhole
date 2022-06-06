# psp-adhoc-proxy
AdHoc Proxy for PSP connection
##

## Few word of mine, what is a thing I'm working on
This is my attempt of creating infrastructure through AdHoc. I doing it to play Patapon 3 online.
Since PSP servers are down for a long time and will never be up again, I'm creating my own using the only possible way to communicate consoles.

## What's the plan?
So there is this AdHoc system. I'm diggin deep inside it to find a way to connect it to PC and then use a computer as proxy server.
Then proxy will send all traffic to defined server (a player who will host a session).
This solve won't be efficient, since program will send broadcastly (?) to every player. (Yeah I think i will solve it later, firstly I will connect two devices)

## Actual implementation
I know that PSP_Proxy.cpp doesn't seem to be the proxy yet. It's because I'm learning about AdHoc protocol on low level.
There's no technical documentation (I didn't found any), thus I'm reversing it, learning about it from scrath, from back.
There will be some code in a while.
