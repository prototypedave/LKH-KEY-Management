import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;

namespace inet;

class JoinRequestPacket extends FieldsChunk
{
    string node;
}

class SessionKeyPacket extends FieldsChunk
{
    string key;
    double start;
}

class LeaveRequestPacket extends FieldsChunk
{
    string node;
}
