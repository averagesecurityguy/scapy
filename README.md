# Scapy
## All Your Packets are Belong To Us

This is a quick introduction to the scapy library. Using the slide deck in the scapy.pdf file and the code in the the Python files, the user should gain a basic understanding of the Scapy library. The slide deck includes links to additional resources for learning more about Scapy.

All of the code samples were created and tested on Ubuntu 14.04 using the standard Scapy package installed using `sudo apt-get install scapy`. Users of other distributions should be able to install Scapy using the built in package manager.

## Special Setup
Some of the scripts require special setup to execute properly and to understand what is happening.

### rewrite.py
The old_server variable should be set to the server that is running the Scapy script. The new server should be some other server that the Scapy server can reach and on which the user can run Tcpdump or Wireshark.

On the new_server run `tcpdump -i eth0 port 8888`. On the old_server run `sudo python rewrite.py` in one terminal window and then, in another terminal window, run `nc <old_server> 8000`. On the new server Tcpdump or Wireshark should be showing a packet from the old_server to the new_server on port 8888.

### send_recv.py
The server variable should be set to any server that the user can reach and on which the user can run a server on port 8000, 8001, or 8002.

First, run the send_recv.py script and there should be no answered packets and three unanswered packets. Next, start up a listening service on port 8000, 8001, or 8002 on the server. Finally run the send_recv.py script again and this time there should be one answered packet and two unanswered packets.

### send.py
The server variable can be set to the server running the scapy script. The sendp function will send a packet to the local server without trouble. The server2 variable should be set to another server that the user has access to because the send function has trouble sending to the local host.

Start tcpdump on the server running Scapy using `tcpdump -i eth0 port 8000`. Next, run the send.py script. Both packets should be seen in the Tcpdump output. Modify the script and set the server2 variable to the same as the server variable and run the script again. This time only one packet should show up in the Tcpdump output.

### sniff_dns.py
Run the sniff_dns.py script in one terminal window. In a second terminal window run `dig google.com`. In the terminal window running sniff_dns.py the sniffed DNS packets should be displayed.