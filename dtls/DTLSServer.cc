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

#include "DTLSServer.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/Simsignals.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/applications/dtls/dtls_m.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <fstream>
#include <chrono>

namespace inet {

Define_Module(DTLSServer);

simsignal_t DTLSServer::reqStreamBytesSignal = registerSignal("reqStreamBytes");

inline std::ostream& operator<<(std::ostream& out, const DTLSServer::VideoStreamData& d)
{
    out << "client=" << d.clientAddr << ":" << d.clientPort
        << "  size=" << d.videoSize << "  pksent=" << d.numPkSent << "  bytesleft=" << d.bytesLeft;
    return out;
}

DTLSServer::~DTLSServer()
{
    for (auto& elem : streams)
        cancelAndDelete(elem.second.timer);
}

void DTLSServer::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        sendInterval = &par("sendInterval");
        packetLen = &par("packetLen");
        videoSize = &par("videoSize");
        localPort = par("localPort");

        // statistics
        numStreams = 0;
        numPkSent = 0;

        WATCH_MAP(streams);
    }
    OpenSSL_add_all_algorithms();

}

void DTLSServer::finish()
{
}

void DTLSServer::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        // timer for a particular video stream expired, send packet
        sendStreamData(msg);
    }
    else
        socket.processMessage(msg);
}

void DTLSServer::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    std::string pkname = packet->getName();
    if (pkname == "ClientHello")
    {
        handleClientHello(packet, socket);
    }
    else if(pkname == "KeyExchange")
    {
        handleKeyExchange(packet, socket);
    }
    else if(pkname == "AttackedPacket")
    {
        handleAttack(packet, socket);
    }
    else
    {
        processStreamRequest(packet);
    }
}

void DTLSServer::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void DTLSServer::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void DTLSServer::handleClientHello(Packet *packet, UdpSocket *socket)
{
    auto end = std::chrono::high_resolution_clock::now();
    double endTime = std::chrono::duration<double>(end.time_since_epoch()).count();

    L3Address remoteAddress = packet->getTag<L3AddressInd>()->getSrcAddress();
    int srcPort = packet->getTag<L4PortInd>()->getSrcPort();
    // remove chunk
    auto payload = packet->removeAtFront<ClientHello>();
    if (payload != nullptr)
    {
        double startT = payload->getStart();
        double elapsedTime = endTime - startT;

        const char * proto = payload->getProtocolVersion();
        if (version == (std::string)proto)
        {
            int sId = payload->getSessionId();

            auto it = sharedSecrets.find(sId);
            if (it != sharedSecrets.end())
            {
                delete packet;
                return;
            }
            else
                sharedSecrets[sId] = "string";

            // create key pair
            pkey = generate_key_pair();
            if (!pkey)
                return;

            // generate certificate
            bool fake = par("fake");
            server_cert = create_certificate(pkey,fake);
            if (!server_cert)
            {
                EVP_PKEY_free(pkey);
                return;
            }

            iv = generate_iv();

            auto start = std::chrono::high_resolution_clock::now();
            double startP = std::chrono::duration<double>(start.time_since_epoch()).count();

            // if true: share certificate with server
            EV << "Server selected the protocol version supported by client, TLS PROTOCOL: " << version << std::endl;
            const auto& serv = makeShared<ServerHello>();
            serv->setChunkLength(B(256));
            serv->setCertificate(ConvertCerttoChar(server_cert));
            serv->setTempkey(base64_encode(iv).c_str());
            serv->setStart(startP);
            serv->setElapsed(elapsedTime);
            serv->addTag<CreationTimeTag>()->setCreationTime(simTime());
            packet->insertAtBack(serv);
            packet->setName("ServerHello");
            packet->clearTags();
            packet->trim();

            emit(packetSentSignal, packet);
            // send back
            socket->sendTo(packet, remoteAddress, srcPort);

            X509_free(server_cert);
        }
   }

}

void DTLSServer::handleKeyExchange(Packet *packet, UdpSocket *socket)
{
    auto end = std::chrono::high_resolution_clock::now();
    double endTime = std::chrono::duration<double>(end.time_since_epoch()).count();
    if (key > 0)
    {
        delete packet;
        return;
    }

    L3Address remoteAddress = packet->getTag<L3AddressInd>()->getSrcAddress();
    int srcPort = packet->getTag<L4PortInd>()->getSrcPort();

    // remove chunk
    auto payload = packet->removeAtFront<KeyExchange>();
    if (payload != nullptr)
    {
        const char *received_value = payload->getKey();
        int sId = payload->getSessionId();
        int received_len = payload->getLen();
        double startT = payload->getStart();
        double elapsed = payload->getElapsed();
        double elapsedTime = endTime - startT;
        elapsed += elapsedTime;

        auto it = sharedSecrets.find(sId);
        if (it == sharedSecrets.end())
            return;
        std::string sharedSecret = sharedSecrets[sId];

        if (strcmp(received_value, sharedSecret.c_str()) == 0)
        {
            auto start = std::chrono::high_resolution_clock::now();
            double startP = std::chrono::duration<double>(start.time_since_epoch()).count();

            EV_DETAIL << "Key Exchange Successful" << "\n";
            const auto& serv = makeShared<HandShake>();
            serv->setChunkLength(B(400));
            serv->setCommand("Success");
            serv->setElapsed(elapsed);
            serv->setStart(startP);
            serv->addTag<CreationTimeTag>()->setCreationTime(simTime());
            packet->insertAtBack(serv);
            packet->setName("HandShake");
            packet->clearTags();
            packet->trim();

            emit(packetSentSignal, packet);
            // send back
            socket->sendTo(packet, remoteAddress, srcPort);
            EV_DETAIL << "HandShake Successful" << "\n";
        }
    }
    key++;
}

void DTLSServer::processStreamRequest(Packet *msg)
{
    // remove chunk
    if (req > 0)
    {
        delete msg;
        return;
    }
    const char * data = msg->getName();


    auto payload = msg->removeAtFront<StreamData>();
    if (payload != nullptr)
    {
        int sId = payload->getSessionId();
        auto it = sharedSecrets.find(sId);
        if (it == sharedSecrets.end())
            return;
        std::string secret = sharedSecrets[sId];
        std::vector<unsigned char> c_key = base64_decode(secret);
        std::vector<unsigned char> cipher = base64_decode(data);

        std::vector<unsigned char> decipher = decrypt(cipher, c_key);
        std::string decry(decipher.begin(), decipher.end());
        if (decry == "VideoStrmReq")
        {
            // register video stream...
            cMessage *timer = new cMessage("VideoStreamTmr");
            VideoStreamData *d = &streams[timer->getId()];
            d->timer = timer;
            d->clientAddr = msg->getTag<L3AddressInd>()->getSrcAddress();
            d->clientPort = msg->getTag<L4PortInd>()->getSrcPort();
            d->videoSize = (*videoSize);
            d->bytesLeft = d->videoSize;
            d->numPkSent = 0;
            d->sId = sId;
            ASSERT(d->videoSize > 0);
            delete msg;

            numStreams++;
            emit(reqStreamBytesSignal, d->videoSize);

            // ... then transmit first packet right away
            sendStreamData(timer);
        }
    }
    req++;
}

void DTLSServer::sendStreamData(cMessage *timer)
{
    auto it = streams.find(timer->getId());
    if (it == streams.end())
        throw cRuntimeError("Model error: Stream not found for timer");

    VideoStreamData *d = &(it->second);

    std::string videoStrm = "videoStrmPk";

    std::vector<unsigned char> plaintext(videoStrm.begin(), videoStrm.end());
    auto il = sharedSecrets.find(d->sId);
    if (il == sharedSecrets.end())
        return;
    std::string secret = sharedSecrets[d->sId];
    std::vector<unsigned char> c_key = base64_decode(secret);
    std::vector<unsigned char> encrypted = encrypt(plaintext, c_key);

    // generate and send a packet
    Packet *pkt = new Packet(base64_encode(encrypted).c_str());
    long pktLen = *packetLen;

    if (pktLen > d->bytesLeft)
        pktLen = d->bytesLeft;
    const auto& payload = makeShared<Msg>();
    payload->setChunkLength(B(pktLen));
    payload->setCount(numPkSent);
    payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
    pkt->insertAtBack(payload);

    emit(packetSentSignal, pkt);
    socket.sendTo(pkt, d->clientAddr, d->clientPort);

    d->bytesLeft -= pktLen;
    d->numPkSent++;
    numPkSent++;

    std::ofstream file;
    file.open("results/packetcount.csv", std::ios::app);
    if (file.is_open()) {
        file << numPkSent << "\n";
        file.close();
    }

    // reschedule timer if there's bytes left to send
    if (d->bytesLeft > 0) {
        simtime_t interval = (*sendInterval);
        scheduleAfter(interval, timer);
    }
    else {
        streams.erase(it);
        delete timer;
    }
}

void DTLSServer::clearStreams()
{
    for (auto& elem : streams)
        cancelAndDelete(elem.second.timer);
    streams.clear();
}

void DTLSServer::handleAttack(Packet *packet, UdpSocket *socket)
{
    EV_DETAIL << "====================================" << "\n";
    EV_DETAIL << "Received an attacked Packet" << "\n";
    EV_DETAIL << "DROPPING PACKET" << "\n";
    EV_DETAIL << "====================================" << "\n";
    delete packet;
}

void DTLSServer::handleStartOperation(LifecycleOperation *operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localPort);

    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);
}

void DTLSServer::handleStopOperation(LifecycleOperation *operation)
{
    clearStreams();
    socket.setCallback(nullptr);
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void DTLSServer::handleCrashOperation(LifecycleOperation *operation)
{
    clearStreams();
    if (operation->getRootModule() != getContainingNode(this)) // closes socket when the application crashed only
        socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
    socket.setCallback(nullptr);
}

// Generate EC key pair
EVP_PKEY* DTLSServer::generate_key_pair()
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

X509* DTLSServer::create_certificate(EVP_PKEY* pkey, bool expired)
{
    X509* x509 = X509_new();
    if (!x509) {
        throw cRuntimeError("Error creating X509 object");
        return nullptr;
    }

    X509_set_version(x509, 2); // Version 3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), expired ? -31536000L : 0); // 1 year ago if expired
    X509_gmtime_adj(X509_get_notAfter(x509), expired ? -15768000L : 31536000L); // 6 months ago if expired
    X509_set_pubkey(x509, pkey);

    // Set fake certificate fields
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"XX", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"Fake Organization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"fake.local", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Sign the certificate with the private key
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        throw cRuntimeError("Error signing certificate");
        X509_free(x509);
        return nullptr;
    }

    return x509;
}

std::vector<unsigned char> DTLSServer::create_shared_secret(EVP_PKEY* peerkey, int sId) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        throw cRuntimeError("Error creating context");
        return {};
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        throw cRuntimeError("Error initializing derivation");
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        throw cRuntimeError("Error setting peer key");
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        throw cRuntimeError("Error determining secret length");
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        throw cRuntimeError("Error deriving secret");
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // save key in string format for comparison later
    auto it = sharedSecrets.find(sId);
    if (it == sharedSecrets.end())
        return {};
    sharedSecrets[sId] = base64_encode(secret);

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

const char * DTLSServer::ConvertCerttoChar(X509 *cert)
{
    // Create a memory BIO to hold the certificate data
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        // Error handling
        return nullptr;
    }

    // Write the certificate to the memory BIO in PEM format
    if (!PEM_write_bio_X509(bio, cert)) {
        // Error handling
        BIO_free(bio);
        return nullptr;
    }

    // Extract the certificate data from the memory BIO
    char* bufferPtr = nullptr;
    long bufferSize = BIO_get_mem_data(bio, &bufferPtr);
    if (bufferSize <= 0 || !bufferPtr) {
        // Error handling
        BIO_free(bio);
        return nullptr;
    }

    // Allocate memory for the null-terminated string
    char* pemCert = new char[bufferSize + 1];
    if (!pemCert) {
        // Error handling
        BIO_free(bio);
        return nullptr;
    }

    // Copy the certificate data and null-terminate the string
    memcpy(pemCert, bufferPtr, bufferSize);
    pemCert[bufferSize] = '\0';

    // Clean up and return the certificate data
    BIO_free(bio);
    return pemCert;
}

X509 * DTLSServer::ConverttoX509(const char *certData)
{
    // Create a memory BIO to hold the certificate data
    BIO* bio = BIO_new_mem_buf(certData, -1);
    if (!bio) {
        // Error handling
        return nullptr;
    }

    // Read the certificate from the memory BIO
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        // Error handling
        BIO_free(bio);
        return nullptr;
    }

    // Clean up and return the X509 certificate
    BIO_free(bio);
    return cert;
}

std::vector<unsigned char> DTLSServer::base64_decode(const std::string& base64_str) {
    BIO* bio = BIO_new_mem_buf(base64_str.data(), base64_str.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newline flag
    bio = BIO_push(b64, bio);

    size_t decoded_length = base64_str.size() * 3 / 4;
    std::vector<unsigned char> decoded_data(decoded_length);

    int actual_length = BIO_read(bio, decoded_data.data(), decoded_data.size());
    decoded_data.resize(actual_length);

    BIO_free_all(bio);

    return decoded_data;
}

std::string DTLSServer::base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newline flag
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string base64_str(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);

    return base64_str;
}

bool DTLSServer::verifyCert(const char *cert) {
    Enter_Method("Load DTLS Server");
    X509 *serverCert = ConverttoX509(cert);

    // Check if the certificate is expired
    time_t currentTime = time(NULL);
    if (X509_cmp_time(X509_get_notBefore(serverCert), &currentTime) > 0 ||
        X509_cmp_time(X509_get_notAfter(serverCert), &currentTime) < 0) {
        ERR_print_errors_fp(stderr);
        X509_free(serverCert);  // Free the allocated X509 structure
        throw cRuntimeError("Invalid Certificate");
        return false; // The certificate is either not yet valid or expired
    }

    // Create SSL context
    ctx = SSL_CTX_new(DTLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        EV_DETAIL << "SSL" << "\n";
        return false;
    }
    // Use the generated certificate and private key in the SSL context
    if (SSL_CTX_use_certificate(ctx, serverCert) <= 0) {
        ERR_print_errors_fp(stderr);
        EV_DETAIL << "CERT" << "\n";
        return false;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EV_DETAIL << "PRIVATE" << "\n";
        return false;
    }
    // Get the server's X.509 certificate
    server_cert = SSL_CTX_get0_certificate(ctx);
    if (server_cert == NULL) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    // Extract the public key from the certificate
    public_key = X509_get_pubkey(server_cert);
    if (public_key == NULL) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    // if all successful the certificate is valid
    return true;
}

std::vector<unsigned char> DTLSServer::encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::vector<unsigned char> DTLSServer::decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

} // namespace inet
