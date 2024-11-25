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

#include "LKHManager.h"
#include "lkh_m.h"

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/mobility/base/MobilityBase.h"
#include "inet/networklayer/configurator/ipv4/Ipv4NetworkConfigurator.h"

namespace inet {

Define_Module(LKHManager);

LKHManager::~LKHManager()
{
    cancelAndDelete(selfMsg);
}

void LKHManager::initialize(int stage)
{
    ClockUserModuleMixin::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        numSent = 0;
        numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);

        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        dontFragment = par("dontFragment");
        nodeLimit = par("maxNodes");
        if (stopTime >= CLOCKTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new ClockEvent("sendTimer");
        key = getParentModule()->getFullName();
        server = this;
        // initialize tree
        LKHTree = new Tree(server);
    }
}

void LKHManager::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}


void LKHManager::setSocketOptions()
{
    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *multicastInterface = par("multicastInterface");
    if (multicastInterface[0]) {
        IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        NetworkInterface *ie = ift->findInterfaceByName(multicastInterface);
        if (!ie)
            throw cRuntimeError("Wrong multicastInterface setting: no interface named \"%s\"", multicastInterface);
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    bool receiveBroadcast = par("receiveBroadcast");
    if (receiveBroadcast)
        socket.setBroadcast(true);

    bool joinLocalMulticastGroups = par("joinLocalMulticastGroups");
    if (joinLocalMulticastGroups) {
        MulticastGroupList mgl = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this)->collectMulticastGroups();
        socket.joinLocalMulticastGroups(mgl);
    }
    socket.setCallback(this);
}

void LKHManager::handleJoinRequest(Packet *pkt)
{
    auto payload = pkt->removeAtFront<JoinRequestPacket>();
    if (payload != nullptr) {
        const char * path = payload->getNode();
        cModule* appModule = getModuleByPath(path);
        if (appModule != nullptr) {
            LKHNode* node = dynamic_cast<LKHNode*>(appModule);
            if (node != nullptr) {
                LKHNode *parent = LKHTree->getBranch();
                activeNodes++;
                if (activeNodes > nodeLimit) {
                    EV_INFO << "Maximum number of nodes reached" << endl;
                    delete pkt;
                    return;
                }
                int msgs = 0;
                auto start = std::chrono::high_resolution_clock::now();
                double startT = std::chrono::duration<double>(start.time_since_epoch()).count();
                std::vector<PathData> kek = LKHTree->AddNode(parent, node);
                for (const auto& data : kek) {
                    if (data.localAddr != localAddr) {
                        Packet *packet = new Packet();
                        if (dontFragment)
                            packet->addTag<FragmentationReq>()->setDontFragment(true);
                        const auto& msg = makeShared<SessionKeyPacket>();
                        msg->setChunkLength(B(par("messageLength")));
                        msg->setKey(data.sessionKey.c_str());
                        msg->setStart(startT);
                        msg->addTag<CreationTimeTag>()->setCreationTime(simTime());
                        packet->insertAtBack(msg);
                        packet->setName("KeyUpdate");
                        emit(packetSentSignal, packet);
                        socket.sendTo(packet, data.localAddr, destPort);
                        numSent++;
                        msgs++;
                    }
                    else {
                        EV_ERROR <<"Not working" << endl;
                    }
                }
                auto end = chrono::high_resolution_clock::now();
                chrono::duration<double> duration = end - start;

                std::ofstream file;
                file.open("results/distDelay.csv", std::ios::app);
                if (file.is_open()) {
                    file << duration.count() << "," << activeNodes << "," << msgs << "\n";
                    file.close();
                }
            }
        }
    }
    LKHTree->displayTree(server);
    delete pkt;
}

void LKHManager::handleLeaveRequest(Packet *pkt)
{
    auto payload = pkt->removeAtFront<LeaveRequestPacket>();
    if (payload != nullptr) {
        const char * path = payload->getNode();
        cModule* appModule = getModuleByPath(path);
        if (appModule != nullptr) {
            LKHNode* node = dynamic_cast<LKHNode*>(appModule);
            if (node != nullptr) {
                int msgs = 0;
                auto start = std::chrono::high_resolution_clock::now();
                double startT = std::chrono::duration<double>(start.time_since_epoch()).count();
                std::vector<PathData> kek = LKHTree->RemoveNode(node);
                activeNodes--;
                for (const auto& data : kek) {
                    if (data.localAddr != localAddr) {
                        EV<<startT << endl;
                        Packet *packet = new Packet();
                        if (dontFragment)
                            packet->addTag<FragmentationReq>()->setDontFragment(true);
                        const auto& msg = makeShared<SessionKeyPacket>();
                        msg->setChunkLength(B(par("messageLength")));
                        msg->setKey(data.sessionKey.c_str());
                        msg->setStart(startT);
                        msg->addTag<CreationTimeTag>()->setCreationTime(simTime());
                        packet->insertAtBack(msg);
                        packet->setName("KeyUpdate");
                        emit(packetSentSignal, packet);
                        socket.sendTo(packet, data.localAddr, destPort);
                        numSent++;
                        msgs++;
                    }
                }
                auto end = chrono::high_resolution_clock::now();
                chrono::duration<double> duration = end - start;

                if (activeNodes >= 0) {
                    std::ofstream file;
                    file.open("results/delDelay.csv", std::ios::app);
                    if (file.is_open()) {
                        file << duration.count() << "," << activeNodes << "," << msgs << "\n";
                        file.close();
                    }
                }
            }
        }
    }
    LKHTree->displayTree(server);
    delete pkt;
}

void LKHManager::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
    setSocketOptions();

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;

    while ((token = tokenizer.nextToken()) != nullptr) {
        destAddressStr.push_back(token);
        L3Address result;
        L3AddressResolver().tryResolve(token, result);
        if (result.isUnspecified())
            EV_ERROR << "cannot resolve destination address: " << token << endl;
        destAddresses.push_back(result);
    }

    if (stopTime >= CLOCKTIME_ZERO) {
        selfMsg->setKind(STOP);
        scheduleClockEventAt(stopTime, selfMsg);
    }
    localAddr = L3AddressResolver().resolve(key);
}

void LKHManager::processSend()
{
    sendPacket();
    clocktime_t d = par("sendInterval");
    if (stopTime < CLOCKTIME_ZERO || getClockTime() + d < stopTime) {
        selfMsg->setKind(SEND);
        scheduleClockEventAfter(d, selfMsg);
    }
    else {
        selfMsg->setKind(STOP);
        scheduleClockEventAt(stopTime, selfMsg);
    }
}

void LKHManager::processStop()
{
    socket.close();
}

void LKHManager::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        ASSERT(msg == selfMsg);
        switch (selfMsg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)selfMsg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void LKHManager::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    std::string pkname = packet->getName();
    if (pkname == "JoinRequest") {
        handleJoinRequest(packet);
    } else if (pkname == "LeaveRequest") {
        handleLeaveRequest(packet);
    }
    //processPacket(packet);
}

void LKHManager::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void LKHManager::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void LKHManager::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void LKHManager::handleStartOperation(LifecycleOperation *operation)
{
    clocktime_t start = std::max(startTime, getClockTime());
    if ((stopTime < CLOCKTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        processStart();
    }
}

void LKHManager::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void LKHManager::handleCrashOperation(LifecycleOperation *operation)
{
    cancelClockEvent(selfMsg);
    socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

} // namespace inet
