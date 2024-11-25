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

#ifndef __INET_DTLSSERVER_H_
#define __INET_DTLSSERVER_H_

#include <map>
#include <unordered_map>

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/packet/Packet.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <vector>
#include <utility>
#include <cstdlib>
#include <cstring>
#include <random>

#define AES_KEY_LEN 32
#define ERROR_BUF_SIZE 256


namespace inet {

/**
 * Stream VBR video streams to clients.
 *
 * Cooperates with UdpVideoStreamClient. UdpVideoStreamClient requests a stream
 * and DTLSServer starts streaming to them. Capable of handling
 * streaming to multiple clients.
 */
class INET_API DTLSServer : public ApplicationBase, public UdpSocket::ICallback
{
  public:
    struct VideoStreamData {
        cMessage *timer = nullptr; // self timer msg
        L3Address clientAddr; // client address
        int clientPort = -1; // client UDP port
        long videoSize = 0; // total size of video
        long bytesLeft = 0; // bytes left to transmit
        long numPkSent = 0; // number of packets sent
        int sId = 0;
    };

  protected:
    typedef std::map<long int, VideoStreamData> VideoStreamMap;

    // state
    VideoStreamMap streams;
    UdpSocket socket;

    // parameters
    int localPort = -1;
    cPar *sendInterval = nullptr;
    cPar *packetLen = nullptr;
    cPar *videoSize = nullptr;

    // DTLS
    std::string version = "TLS_1.3"; // for now we use string, in a complex env a vector will be preferred
    SSL_CTX *ctx;
    X509 *server_cert;
    EVP_PKEY *public_key;
    EVP_PKEY *pkey;
    RSA *rsa;

    int key = 0;
    int req = 0;

    std::unordered_map<int, std::string> sharedSecrets;
    std::unordered_map<int, int> length;
    std::vector<unsigned char> iv;

    // statistics
    unsigned int numStreams = 0; // number of video streams served
    unsigned long numPkSent = 0; // total number of packets sent
    static simsignal_t reqStreamBytesSignal; // length of video streams served

    virtual void processStreamRequest(Packet *msg);
    virtual void sendStreamData(cMessage *timer);

    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void clearStreams();

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    void handleClientHello(Packet *packet, UdpSocket *socket);
    void handleKeyExchange(Packet *packet, UdpSocket *socket);
    void handleData(Packet *packet, UdpSocket *socket);
    void handleAttack(Packet *packet, UdpSocket *socket);

    EVP_PKEY * generate_key_pair();
    X509 * create_certificate(EVP_PKEY* pkey, bool expired = true);

    const char * ConvertCerttoChar(X509 *cert);
    X509 * ConverttoX509(const char *cert);

    std::vector<unsigned char> base64_decode(const std::string& base64_str);
    std::string base64_encode(const std::vector<unsigned char>& data);

    std::vector<unsigned char> generate_iv(size_t iv_size = 16) {
        std::vector<unsigned char> iv(iv_size);

        // Use a cryptographically secure random number generator
        std::random_device rd;
        std::default_random_engine generator(rd());
        std::uniform_int_distribution<int> distribution(0, 255); // Range for byte values

        // Fill the IV with random bytes
        for (unsigned char& byte : iv) {
            byte = static_cast<unsigned char>(distribution(generator));
        }

        return iv;
    }

  public:
    DTLSServer() {}
    virtual ~DTLSServer();
    bool verifyCert(const char *cert);
    std::vector<unsigned char> create_shared_secret(EVP_PKEY* peerkey, int sId);
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);

};

} // namespace inet

#endif

