# beacon_spammer
Simple command line util to send 802.11 beacons with Channel Switch Announcements

ESP's appear to honour 802.11 beacons containing CSA even if they are not connected to the AP sending the beacon.

To try out given wireless interface is wlan1:
```  
airmon-ng start wlan1

cd beacon_spammer
make
./packetspammer wlan1mon -n 1000 -r 10 -c [CSA channel]
```  

while packetspammer is running, ESP's in the range of the box running packetspammer gives: "switch to channel [CSA channel]"
