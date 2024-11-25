//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package lkh.simulations.lkh;

import inet.node.inet.StandardHost;
import ned.DatarateChannel;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;

network Lkhnetwork
{
    parameters:
        int numHost = default(16);
        int value = default(6);
    types:
        channel C extends DatarateChannel
        {
            datarate = 10Mbps;
            delay = 0.1us;
        }
    submodules:
        configurator: Ipv4NetworkConfigurator {
            parameters:
                @display("p=180,31;is=s");
        }
        node[numHost]: StandardHost {
            parameters:
                forwarding = true;
                //multicastForwarding = true;
                @display("i=device/pc3;is=vs");              
        }

        Server: StandardHost {
            @display("p=172,92");
            
        }
    connections:
        Server.pppg++ <--> C <--> node[0].pppg++;
        Server.pppg++ <--> C <--> node[1].pppg++;
        for i=0..value{
            node[i].pppg++ <--> C <--> node[2 * i + 2].pppg++;
            node[i].pppg++ <--> C <--> node[2 * i + 3].pppg++;
        }
}
