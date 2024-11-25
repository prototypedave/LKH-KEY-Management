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

#ifndef __INET_DTLSCLIENT_H_
#define __INET_DTLSCLIENT_H_

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/packet/Packet.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

#include <iostream>
#include <random>
#include "DTLSServer.h"

#include <fstream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#define AES_KEY_LEN 32

namespace inet {

/**
 * A "Realtime" VideoStream client application.
 *
 * Basic video stream application. Clients connect to server and get a stream of
 * video back.
 */
class INET_API DTLSClient : public ApplicationBase, public UdpSocket::ICallback
{
  protected:

    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;

    int svrPort = -1;
    int localPort = 0;
    const char *address = nullptr;
    L3Address svrAddr;

    // DTLS
    int sessionId = 0;
    int helloCount = 0;
    int handshake = 0;

    std::vector<unsigned char> secret;
    std::vector<unsigned char> iv;
    simtime_t lastJitter = 0;

    int count = 0;
    double startKeyTime;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void requestStream();
    virtual void receiveStream(Packet *msg);

    // ApplicationBase:
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    // DTLS
    void clientHello();
    void handleServerHello(Packet *packet);
    void handleHandShake(Packet *packet);
    EVP_PKEY* generate_key_pair();
    std::string base64_encode(const std::vector<unsigned char>& data);
    std::vector<unsigned char> base64_decode(const std::string& base64_str);

    int getSessionId()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(10000000, 99999999);
        return dist(gen);
    }

    char* unsigned_char_to_string(const unsigned char *data, int data_len) {
        char *str = (char *)malloc(data_len * 2 + 1);
        if (str == NULL)
            return NULL;

        for (int i = 0; i < data_len; i++) {
            sprintf(str + i * 2, "%02x", data[i]);
        }

        str[data_len * 2] = '\0';
        return str;
    }

    std::string shared_secret;
    size_t client_secret_len = 0;
    EVP_PKEY* clientKey;

  public:
    DTLSClient() {}
    virtual ~DTLSClient() { cancelAndDelete(selfMsg); }
};

} // namespace inet

#endif
