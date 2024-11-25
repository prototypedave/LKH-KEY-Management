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

#include "FlatServer.h"

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
#include "inet/applications/lkh/lkh_m.h"

namespace inet {

Define_Module(FlatServer);

FlatServer::~FlatServer()
{
    cancelAndDelete(selfMsg);
}

void FlatServer::initialize(int stage)
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
        if (stopTime >= CLOCKTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        selfMsg = new ClockEvent("sendTimer");
    }
}

void FlatServer::finish()
{
    recordScalar("packets sent", numSent);
    recordScalar("packets received", numReceived);
    ApplicationBase::finish();
}

void FlatServer::setSocketOptions()
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

L3Address FlatServer::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    if (destAddresses[k].isUnspecified() || destAddresses[k].isLinkLocal()) {
        L3AddressResolver().tryResolve(destAddressStr[k].c_str(), destAddresses[k]);
    }
    EV << k << endl;
    EV << "Destination Addresses: ";
    for (const std::string &address : destAddressStr) {
        EV << address << " ";
    }
    EV << endl;
    return destAddresses[k];
}

void FlatServer::sendPacket()
{
    std::ostringstream str;
    str << packetName << "-" << numSent;
    Packet *packet = new Packet(str.str().c_str());
    if (dontFragment)
        packet->addTag<FragmentationReq>()->setDontFragment(true);
    const auto& payload = makeShared<ApplicationPacket>();
    payload->setChunkLength(B(par("messageLength")));
    payload->setSequenceNumber(numSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    L3Address destAddr = chooseDestAddr();
    emit(packetSentSignal, packet);
    socket.sendTo(packet, destAddr, destPort);
    numSent++;
}

void FlatServer::processStart()
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

}

void FlatServer::processSend()
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

void FlatServer::processStop()
{
    socket.close();
}

void FlatServer::handleMessageWhenUp(cMessage *msg)
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

void FlatServer::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    std::string pkname = packet->getName();
    if (pkname == "JoinRequest") {
        handleJoinRequest(packet);
    } else if (pkname == "LeaveRequest") {
        handleLeaveRequest(packet);
    }
}

void FlatServer::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void FlatServer::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void FlatServer::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void FlatServer::handleJoinRequest(Packet *pkt)
{
    L3Address remoteAddress = pkt->getTag<L3AddressInd>()->getSrcAddress();
    destAddresses.push_back(remoteAddress);
    activeNodes++;

    auto payload = pkt->removeAtFront<JoinRequestPacket>();
    if (payload != nullptr) {
        const char * path = payload->getNode();
        EV << "===========================================" << endl;
        EV << "| " << path << "Added to Group" << endl;
        EV << "===========================================" << endl;
    }

    int msgs = 0;
    flatKey = generateKey();
    auto start = std::chrono::high_resolution_clock::now();
    double startT = std::chrono::duration<double>(start.time_since_epoch()).count();
    for (const auto& address : destAddresses) {
        Packet *packet = new Packet();
        if (dontFragment)
            packet->addTag<FragmentationReq>()->setDontFragment(true);
        const auto& msg = makeShared<SessionKeyPacket>();
        msg->setChunkLength(B(par("messageLength")));
        msg->setKey(flatKey.c_str());
        msg->setStart(startT);
        msg->addTag<CreationTimeTag>()->setCreationTime(simTime());
        packet->insertAtBack(msg);
        packet->setName("KeyUpdate");
        emit(packetSentSignal, packet);
        socket.sendTo(packet, address, destPort);
        numSent++;
        msgs++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    std::ofstream file;
    file.open("results/distDelay.csv", std::ios::app);
    if (file.is_open()) {
        file << duration.count() << "," << activeNodes << "," << msgs << "\n";
        file.close();
    }
    delete pkt;
}

void FlatServer::handleLeaveRequest(Packet *pkt)
{
    L3Address remoteAddress = pkt->getTag<L3AddressInd>()->getSrcAddress();
    auto it = std::remove(destAddresses.begin(), destAddresses.end(), remoteAddress);
    // confirm removal
    if (it != destAddresses.end()) {
        destAddresses.erase(it, destAddresses.end());
    }
    activeNodes--;

    auto payload = pkt->removeAtFront<LeaveRequestPacket>();
    if (payload != nullptr) {
        const char * path = payload->getNode();
        EV << "===========================================" << endl;
        EV << "| " << path << "Removed from Group" << endl;
        EV << "===========================================" << endl;
        cModule* appModule = getModuleByPath(path);
        cModule* parent = appModule->getParentModule();
        if (parent != nullptr)
            parent->deleteModule();
    }
    auto star = std::chrono::high_resolution_clock::now();
    flatKey = generateKey();
    auto en = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> dura = en - star;

    auto start = std::chrono::high_resolution_clock::now();
    double startT = std::chrono::duration<double>(start.time_since_epoch()).count();
    int msgs = 0;
    for (const auto& address : destAddresses) {
        Packet *packet = new Packet();
        if (dontFragment)
            packet->addTag<FragmentationReq>()->setDontFragment(true);
        const auto& msg = makeShared<SessionKeyPacket>();
        msg->setChunkLength(B(par("messageLength")));
        msg->setKey(flatKey.c_str());
        msg->setStart(startT);
        msg->addTag<CreationTimeTag>()->setCreationTime(simTime());
        packet->insertAtBack(msg);
        packet->setName("KeyUpdate");
        emit(packetSentSignal, packet);
        socket.sendTo(packet, address, destPort);
        numSent++;
        msgs++;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    std::ofstream file;
    file.open("results/delDelay.csv", std::ios::app);
    if (file.is_open()) {
        file << duration.count() << "," << activeNodes << "," << msgs << "\n";
        file.close();
    }
    file.open("results/keyDelay.csv", std::ios::app);
    if (file.is_open()) {
        file << dura.count() << "," << activeNodes << "\n";
        file.close();
    }
    delete pkt;
}

void FlatServer::processPacket(Packet *pk)
{
    emit(packetReceivedSignal, pk);
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
    delete pk;
    numReceived++;
}

void FlatServer::handleStartOperation(LifecycleOperation *operation)
{
    clocktime_t start = std::max(startTime, getClockTime());
    if ((stopTime < CLOCKTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        processStart();
    }
}

void FlatServer::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void FlatServer::handleCrashOperation(LifecycleOperation *operation)
{
    cancelClockEvent(selfMsg);
    socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

} // namespace inet

