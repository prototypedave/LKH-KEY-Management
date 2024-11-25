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

package lkh.simulations.flat;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;

network Flatnetwork
{
    parameters:
        int rt1 = default(5);
        int rt2 = default(5);
        int rt3 = default(6);

    types:
        channel C extends DatarateChannel
        {
            datarate = 10Mbps;
            delay = 0.1us;
        }
        channel fiberrouter extends DatarateChannel
        {
            delay = normal(0.000001s, 0.0000001s);
            datarate = 512Mbps;
        }
    submodules:
        host1[rt1]: StandardHost {
            
        }
        host2[rt2]: StandardHost {
            
        }
        host3[rt3]: StandardHost {
            
        }

        router1: Router {
            @display("p=326,220");
        }
        router2: Router {

            @display("p=493,220");
        }
        router3: Router {
            @display("p=493,335");
        }
        router4: Router {
            @display("p=679,224");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,100;is=s");
        }
        Server: StandardHost {
            @display("p=493,80");
        }
    connections:
        // * Domain 1 * (172.0.0.x)
        for i=0..rt1-1 {
            host1[i].pppg++ <--> C <--> router1.pppg++;
        }

        // * Domain 2 * (172.0.1.x)
        for i=0..rt2-1 {
            host2[i].pppg++ <--> C <--> router3.pppg++;
        }

        // * Domain 3 * (172.0.2.x)
        for i=0..rt3-1 {
            host3[i].pppg++ <--> C <--> router4.pppg++;
        }

        // * Router Connections * (172.1.0.x)
        router2.pppg++ <--> fiberrouter <--> router1.pppg++;
        router2.pppg++ <--> fiberrouter <--> router3.pppg++;
        router2.pppg++ <--> fiberrouter <--> router4.pppg++;

        Server.pppg++ <--> fiberrouter <--> router2.pppg++;
}
