import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;

namespace inet;

class ClientHello extends FieldsChunk
{
    string protocolVersion;
    int sessionId;
    double start;
}

class ServerHello extends FieldsChunk
{
    string certificate;
    string tempkey;
    double start;
    double elapsed;
}

class KeyExchange extends FieldsChunk
{
    string key;
    int sessionId;
    int len;
    double start;
    double elapsed;
}

class HandShake extends FieldsChunk
{
    string command;
    double start;
    double elapsed;
}

class StreamData extends FieldsChunk
{
    int sessionId;
    int len;
    int cipherlen;
}

class Msg extends FieldsChunk
{
    int count;
}

