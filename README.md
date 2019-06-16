Little script which catch tcp packets on an interface.
We use the diffent flags to fingerprint the OS of the clients.
The script use the etter.finger.os fingerprinting database.

===Install===

aptitude install libpcap-dev &&
gcc -lpcap fingerprint.c -o arp

