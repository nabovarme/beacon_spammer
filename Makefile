beacon_spammer: beacon_spammer.c
	gcc  -Wall beacon_spammer.c -o beacon_spammer -lpcap

clean:
	rm -f beacon_spammer
