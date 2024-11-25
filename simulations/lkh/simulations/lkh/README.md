# LKH VIDEO DOCUMENTATION
-> Ensure you have a working environment with inet and lkh project installed correctly

## Running LKH
1. Navigate from project explorer:
	lkh -> simulations -> lkh -> omnetpp.ini
2. Run the omnetpp.ini file as omnetpp simulation
3. On the qtenv window, select the scenario you wish to simulate from the three (config-16|128|1024)
4. The simulation may take a while for large number of members if its for result generation I prefer you use the express mode.
5. Repeat for other simulations

The simulation involves simulating the lkh key management system where a node sends join request packet to the server and 
it gets added to the tree, and the server shares new keys to affected members through the key update packets.
Similar to this when a member wants to leave they send a leave request and the server removes the node from the tree and shares a new key to the remaining affected nodes.

