#include "timgextractor.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include <iostream>
#include <charconv>
#include <sstream>


TImgExtractor::TImgExtractor(int argc, char* argv[])
{
    if (argc != 6)
        throw std::runtime_error("Number of input parameters should be 5\n");

    flowStruct = GetFlowParams(argv);
    capFile = std::make_unique<pcpp::PcapFileReaderDevice>(argv[1]);
    if (!capFile->open())
        throw std::runtime_error("Error opening the pcap file\n");
}

TImgExtractor::~TImgExtractor()
{
    capFile->close();
}

bool TImgExtractor::CheckIpAddr(const char* addr)
{
    unsigned int ipAddr;
    std::string str(addr);
    std::replace(str.begin(), str.end(), '.', ' ');
    std::istringstream ss(str);
    while (ss >> str)
    {
        auto res = std::from_chars(str.data(), str.data() + str.size(), ipAddr);
        if (res.ec != std::errc())
            return false;
        if (ipAddr > 255 )
            return false;
    }
    return true;
}

bool TImgExtractor::CheckPort(char* port, uint32_t& srcPort)
{
    auto res = std::from_chars(port, port + strlen(port), srcPort);
    if (res.ec != std::errc())
        return false;
    if (srcPort > 65535 )
        return false;

    return true;
}

FlowStruct_t TImgExtractor::GetFlowParams(char* argv[])
{
    FlowStruct_t flowStruct;
    if (!CheckIpAddr(argv[2]))
        throw std::runtime_error("Invalid source IP address\n");
    flowStruct.srcAddr = pcpp::IPv4Address(argv[2]);

    if (!CheckPort(argv[3], flowStruct.srcPort))
        throw std::runtime_error("Invalid source port number\n");

    if (!CheckIpAddr(argv[4]))
        throw std::runtime_error("Invalid distanation IP address\n");
    flowStruct.dstAddr = pcpp::IPv4Address(argv[4]);

    if (!CheckPort(argv[5], flowStruct.dstPort))
        throw std::runtime_error("Invalid distanation port number\n");

    return flowStruct;
}


bool TImgExtractor::DataFiltrated(const pcpp::Packet& dPack) const
{
    auto* ipLayer = dPack.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer->getSrcIPAddress().getIPv4() != flowStruct.srcAddr)
        return false;
    if (ipLayer->getDstIPAddress().getIPv4() != flowStruct.dstAddr)
        return false;

    auto* tcpLayer = dPack.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer)
        return false;
    if (tcpLayer->getSrcPort() != flowStruct.srcPort)
        return false;
    if (tcpLayer->getDstPort() != flowStruct.dstPort)
        return false;

    return true;
}

void TImgExtractor::ProcessPackets()
{
    pcpp::RawPacket rawDataPacket;
    pcpp::Packet dataPacket;
    bool readBytesStarted = false;
    size_t dataInd;

    while (capFile->getNextPacket(rawDataPacket))
    {
        dataPacket.setRawPacket(&rawDataPacket, false);
        /* filtration of the frames */
        if (!DataFiltrated(dataPacket))
            continue;

        if (!readBytesStarted)
        {
            /* check firstly http layer */
            auto* httpRespLayer = dataPacket.getLayerOfType<pcpp::HttpResponseLayer>();
            auto* httpReqLayer = dataPacket.getLayerOfType<pcpp::HttpRequestLayer>();
            pcpp::HttpMessage* httpLayer = nullptr;

            if (httpRespLayer)
                httpLayer = static_cast<pcpp::HttpMessage*>(httpRespLayer);
            if (httpReqLayer)
                httpLayer = static_cast<pcpp::HttpMessage*>(httpReqLayer);

            if (httpLayer)
            {
                if (!httpLayer->getFieldByName("Content-Type"))
                    continue;

                if (httpLayer->getFieldByName("Content-Type")->getFieldValue().find("image") != std::string::npos)
                {
                    /* payload is image */
                    size_t dataSize;
                    std::string sizeStr(httpLayer->getFieldByName("Content-Length")->getFieldValue());
                    auto res = std::from_chars(sizeStr.data(), sizeStr.data() + sizeStr.size(), dataSize);
                    if (res.ec != std::errc())
                        throw std::runtime_error("Error in Content-Length field conversion\n");

                    imgBytes.resize(dataSize);
                    memcpy(imgBytes.data(), httpLayer->getLayerPayload(), httpLayer->getLayerPayloadSize());
                    dataInd = httpLayer->getLayerPayloadSize();
                    if (dataInd < dataSize)
                        readBytesStarted = true;
                    else
                        break;
                }
            }
        }
        else
        {
            /* obtain image data from tcp layer */
            auto* tcpLayer = dataPacket.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer)
            {
                memcpy(imgBytes.data() + dataInd, tcpLayer->getLayerPayload(), tcpLayer->getLayerPayloadSize());
                dataInd += tcpLayer->getLayerPayloadSize();
                if (dataInd == imgBytes.size()) // last frame
                    break;
            }
        }
    }
}

bool TImgExtractor::DataImgExist() const
{
    return !imgBytes.empty();
}

void TImgExtractor::CreateImgFile() const
{
    std::ofstream ofs("image.out", std::ios::out | std::ios::binary);
    ofs.write(imgBytes.data(), imgBytes.size());
    ofs.close();
}

