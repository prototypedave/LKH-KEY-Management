# FLATKEY VIDEO DOCUMENTATION
-> Ensure you have a working environment with inet and lkh project installed correctly

## Running FLATKEY
1. Navigate from project explorer:
	lkh -> simulations -> flat -> omnetpp.ini
2. Run the omnetpp.ini file as omnetpp simulation
3. On the qtenv window, select the scenario you wish to simulate from the three (config-16|128|1024)
4. The simulation may take a while for large number of members if its for result generation I prefer you use the express mode.
5. Repeat for other simulations

The simulation involves simulating the flat key management system where nodes in a multicast network sends join request packet to the server, and the server keeps records of nodes connected in the system that can communicate with each other and thus it generates session keys each time a new node joins and updates the whole system of the new key. Same to when a node wants to leave a leave request is sent to server which removes the node from the network and shares a new session key for the multicast groups.

