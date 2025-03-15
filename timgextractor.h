#ifndef TIMGEXTRACTOR_H
#define TIMGEXTRACTOR_H

#include "IpAddress.h"
#include <Packet.h>
#include <PcapFileDevice.h>
#include <vector>

struct FlowStruct_t
{
    pcpp::IPv4Address srcAddr;
    pcpp::IPv4Address dstAddr;
    uint32_t srcPort;
    uint32_t dstPort;
};

class TImgExtractor
{
    std::unique_ptr<pcpp::PcapFileReaderDevice> capFile;
    FlowStruct_t flowStruct;
    std::vector<char> imgBytes;

    bool CheckIpAddr(const char* addr);
    bool CheckPort(char* port, uint32_t& srcPort);
    FlowStruct_t GetFlowParams(char* argv[]);
    bool DataFiltrated(const pcpp::Packet& dPack) const;

public:
    TImgExtractor(int argc, char* argv[]);
    ~TImgExtractor();
    void ProcessPackets();
    void CreateImgFile() const;
    bool DataImgExist() const;
};

#endif // TIMGEXTRACTOR_H
