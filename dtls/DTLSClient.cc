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

#include "DTLSClient.h"
#include <chrono>
#include <fstream>

#include "inet/common/ModuleAccess.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/applications/dtls/dtls_m.h"

namespace inet {

Define_Module(DTLSClient);

void DTLSClient::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        selfMsg = new cMessage("UDPVideoStreamStart");
    }
    sessionId = getSessionId();
}

void DTLSClient::finish()
{
    ApplicationBase::finish();
}

void DTLSClient::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        clientHello();
    }
    else
        socket.processMessage(msg);
}

void DTLSClient::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    //receiveStream(packet);
    std::string pkname = packet->getName();
    if (pkname == "ServerHello")
    {
        handleServerHello(packet);
    }
    else if (pkname == "HandShake")
    {
        handleHandShake(packet);
    }
    else
        receiveStream(packet);
}

void DTLSClient::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void DTLSClient::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void DTLSClient::clientHello()
{
    startKeyTime = simTime().dbl();
    EV_INFO << "Client sending Hello message to " << svrAddr << ":" << svrPort << "\n";

    auto start = std::chrono::high_resolution_clock::now();
    double startT = std::chrono::duration<double>(start.time_since_epoch()).count();
    Packet *packet = new Packet("ClientHello");
    const auto& payload = makeShared<ClientHello>();
    payload->setChunkLength(B(400));
    payload->setProtocolVersion("TLS_1.3");
    payload->setSessionId(sessionId);
    payload->setStart(startT);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    packet->insertAtBack(payload);
    socket.sendTo(packet, svrAddr, svrPort);
}

void DTLSClient::handleServerHello(Packet *packet)
{
    auto end = std::chrono::high_resolution_clock::now();
    double endTime = std::chrono::duration<double>(end.time_since_epoch()).count();


    // retrieve chunk from the client
    if (helloCount > 0)
    {
        delete packet;
        return;
    }
    helloCount++;

    auto payload = packet->removeAtFront<ServerHello>();
    if (payload != nullptr)
    {
        // retrieve certificate
        const char * cert = payload->getCertificate();
        const char * iv_c = payload->getTempkey();
        double startT = payload->getStart();
        double elapsed = payload->getElapsed();
        double elapsedTime = endTime - startT;
        elapsed += elapsedTime;
        iv = base64_decode(iv_c);

        cModule *serverModule = findModuleByPath(par("path"));
        if (serverModule != nullptr)
        {
            DTLSServer *server = check_and_cast<DTLSServer *>(serverModule);
            if (server != nullptr)
            {
                // verify certificate
                bool valid = server->verifyCert(cert);
                if (valid)
                {
                    EV << "Server Certificate Valid" << std::endl;

                    clientKey = generate_key_pair();

                    secret = server->create_shared_secret(clientKey, sessionId);
                    if (!secret.empty())
                    {

                        std::string sct = base64_encode(secret);

                        auto start = std::chrono::high_resolution_clock::now();
                        double startP = std::chrono::duration<double>(start.time_since_epoch()).count();
                        // key exchange with the server
                        Packet *pkt = new Packet("KeyExchange");
                        const auto& exchange = makeShared<KeyExchange>();
                        exchange->setChunkLength(B(400));
                        exchange->setKey(sct.c_str());
                        exchange->setSessionId(sessionId);
                        exchange->setLen(sizeof(secret));
                        exchange->setElapsed(elapsed);
                        exchange->setStart(startP);
                        exchange->addTag<CreationTimeTag>()->setCreationTime(simTime());
                        pkt->insertAtBack(exchange);
                        socket.sendTo(pkt, svrAddr, svrPort);
                    }

                }
                else
                    EV_DETAIL << "Certificate not valid: Connection terminated" << std::endl;
            }
        }
    }
    delete packet;

}

void DTLSClient::handleHandShake(Packet *packet)
{
    double keyTime = simTime().dbl() - startKeyTime;
    std::ofstream file;
    file.open("results/computation.csv", std::ios::app);
    if (file.is_open()) {
        file << keyTime << "\n";
        file.close();
    }

    auto end = std::chrono::high_resolution_clock::now();
    double endTime = std::chrono::duration<double>(end.time_since_epoch()).count();

    if (handshake > 0)
    {
        delete packet;
        return;
    }

    auto payload = packet->removeAtFront<HandShake>();
    if (payload != nullptr)
    {
        const char *command = payload->getCommand();
        double startT = payload->getStart();
        double elapsed = payload->getElapsed();
        double elapsedTime = endTime - startT;
        elapsed += elapsedTime;

        std::ofstream file;
        file.open("results/communication.csv", std::ios::app);
        if (file.is_open()) {
            file << elapsed << "\n";
            file.close();
        }

        if (strcmp(command, "Success") == 0)
        {
            requestStream();
        }
        else if (strcmp(command, "Failed") == 0)
        {
            // failed to communicate to DTLS server exit
            //exit(1);
        }
    }
    delete packet;
    handshake++;
}

void DTLSClient::requestStream()
{
    EV_INFO << "Requesting video stream from " << svrAddr << ":" << svrPort << "\n";
    std::string videoRqst = "VideoStrmReq";
    // encrypt
    cModule *serverModule = getModuleByPath(par("path"));
    if (serverModule != nullptr)
    {
        DTLSServer *server = check_and_cast<DTLSServer *>(serverModule);
        if (server != nullptr)
        {
            std::vector<unsigned char> plaintext(videoRqst.begin(), videoRqst.end());
            std::vector<unsigned char> encrypted = server->encrypt(plaintext, secret);

            // stream video
            Packet *pkt = new Packet();
            const auto& stream = makeShared<StreamData>();
            stream->setChunkLength(B(128));
            stream->setSessionId(sessionId);
            stream->setLen(videoRqst.length());
            //stream->setCipherlen(enc_len);
            stream->addTag<CreationTimeTag>()->setCreationTime(simTime());
            pkt->insertAtBack(stream);
            pkt->setName(base64_encode(encrypted).c_str());
            socket.sendTo(pkt, svrAddr, svrPort);

        }
    }
}

void DTLSClient::receiveStream(Packet *pk)
{
    EV_INFO << "Video stream packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
    const char* pkname = pk->getName();
    std::vector<unsigned char> cipher = base64_decode(pkname);

    cModule *serverModule = getModuleByPath(par("path"));
    if (serverModule != nullptr)
    {
        DTLSServer *server = check_and_cast<DTLSServer *>(serverModule);
        if (server != nullptr)
        {
            EV_DETAIL << "Video Decrypted Successfully" << "\n";
            auto payload = pk->removeAtFront<Msg>();
            if (payload != nullptr)
            {
                simtime_t start = payload->getTag<CreationTimeTag>()->getCreationTime();
                double latency = simTime().dbl() - start.dbl();
                double jitter = start.dbl() - lastJitter.dbl();
                lastJitter = start;
                count++;

                std::ofstream file;
                file.open("results/results.csv", std::ios::app);
                if (file.is_open()) {
                    file << latency << "," << jitter << "," << "," << count << "," << simTime().dbl() << "\n";
                    file.close();
                }
            }
        }
    }
    //emit(packetReceivedSignal, pk);
    delete pk;
}

void DTLSClient::handleStartOperation(LifecycleOperation *operation)
{
    svrPort = par("serverPort");
    localPort = par("localPort");
    address = par("serverAddress");
    svrAddr = L3AddressResolver().resolve(address);

    if (svrAddr.isUnspecified()) {
        EV_ERROR << "Server address is unspecified, skip sending video stream request\n";
        return;
    }

    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);
    socket.setCallback(this);

    simtime_t startTimePar = par("startTime");
    simtime_t startTime = std::max(startTimePar, simTime());
    scheduleAt(startTime, selfMsg);
}

void DTLSClient::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void DTLSClient::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(selfMsg);
    if (operation->getRootModule() != getContainingNode(this)) // closes socket when the application crashed only
        socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

EVP_PKEY* DTLSClient::generate_key_pair()
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (!ctx) {
        throw cRuntimeError("Error initializing key context");
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        throw cRuntimeError("Error initializing keygen");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        throw cRuntimeError("Error setting EC curve");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        throw cRuntimeError("Error generating key");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

std::string DTLSClient::base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Write data to BIO
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    // Get the Base64 encoded string
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string base64_str(buffer_ptr->data, buffer_ptr->length - 1); // Remove the null terminator

    // Clean up
    BIO_free_all(bio);

    return base64_str;
}

std::vector<unsigned char> DTLSClient::base64_decode(const std::string& base64_str) {
    BIO* bio = BIO_new_mem_buf(base64_str.data(), base64_str.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Calculate the expected length of the decoded data
    size_t decoded_length = (base64_str.size() * 3) / 4;
    std::vector<unsigned char> decoded_data(decoded_length);

    // Read data from BIO
    int actual_length = BIO_read(bio, decoded_data.data(), decoded_data.size());

    // Resize vector to the actual length of the decoded data
    decoded_data.resize(actual_length);

    // Clean up
    BIO_free_all(bio);

    return decoded_data;
}

} // namespace inet
