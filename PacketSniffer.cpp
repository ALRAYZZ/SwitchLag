#include "PacketSniffer.h"
#include <QDebug>
#include <algorithm>

// Static callback
void PacketSniffer::packetHandler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* sniffer = reinterpret_cast<PacketSniffer*>(user);
    if (!sniffer) return;
    sniffer->handlePacket(pkthdr, packet);
}

PacketSniffer::PacketSniffer(const QString& interfaceName, QObject* parent)
    : QObject(parent)
    , m_interfaceName(interfaceName)
    , m_pcapHandle(nullptr, pcap_close) // <- initialize unique_ptr with deleter here
{
    char errbuf[PCAP_ERRBUF_SIZE];
    m_pcapHandle.reset(pcap_open_live(interfaceName.toUtf8().constData(), 65536, 1, 1000, errbuf));
    if (!m_pcapHandle) {
        qDebug() << "pcap_open_live failed:" << errbuf;
    }
    else {
        // Filter: UDP or TCP
        struct bpf_program fp;
        char filter[] = "udp or tcp";
        if (pcap_compile(m_pcapHandle.get(), &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(m_pcapHandle.get(), &fp);
            pcap_freecode(&fp);
        }
        else {
            qDebug() << "Filter compile failed for" << filter;
        }
    }
}

PacketSniffer::~PacketSniffer() {
    stopCapture();
}

bool PacketSniffer::startCapture(int packetLimit) {
    if (!m_pcapHandle || m_isRunning) return false;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qDebug() << "WSAStartup failed";
        return false;
    }
#endif

    m_packetLimit = packetLimit;
    m_captureThread = new QThread(this);
    connect(m_captureThread, &QThread::started, [this]() {
        // Use pcap_loop for efficiency instead of manual loop
        pcap_loop(m_pcapHandle.get(), m_packetLimit, packetHandler, reinterpret_cast<u_char*>(this));
        });
    connect(m_captureThread, &QThread::finished, m_captureThread, &QThread::deleteLater);
    m_captureThread->start();
    m_isRunning = true;
    return true;
}

void PacketSniffer::stopCapture() {
    if (m_isRunning) {
        m_isRunning = false;
        if (m_pcapHandle) {
            pcap_breakloop(m_pcapHandle.get());
        }
        if (m_captureThread) {
            m_captureThread->quit();
            m_captureThread->wait(3000);
        }
#ifdef _WIN32
        WSACleanup();
#endif
    }
}

void PacketSniffer::handlePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    info.timestamp = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(pkthdr->ts.tv_sec) * 1000 + pkthdr->ts.tv_usec / 1000);
    info.length = pkthdr->len;
    if (parsePacket(packet, pkthdr->caplen, info)) {
        emit newPacket(info);
    }
}

bool PacketSniffer::parsePacket(const u_char* packetData, int len, PacketInfo& info) {
    // Assume Ethernet header (14 bytes); check pcap_datalink() in future for robustness
    const int ethOffset = 14;
    if (len < ethOffset + static_cast<int>(sizeof(ip_header))) return false;

    const ip_header* ih = reinterpret_cast<const ip_header*>(packetData + ethOffset);
    const int ipHdrLen = (ih->ver_ihl & 0xf) * 4;
    if (len < ethOffset + ipHdrLen) return false;

    // Protocol
    switch (ih->proto) {
    case 6: info.protocol = "TCP"; break;
    case 17: info.protocol = "UDP"; break;
    default: info.protocol = "Other"; return false;  // Skip non-TCP/UDP for MVP
    }

    // IPs: Build dotted strings from bytes
    info.sourceIP = QString("%1.%2.%3.%4")
        .arg(static_cast<int>(ih->saddr.byte1))
        .arg(static_cast<int>(ih->saddr.byte2))
        .arg(static_cast<int>(ih->saddr.byte3))
        .arg(static_cast<int>(ih->saddr.byte4));
    info.destIP = QString("%1.%2.%3.%4")
        .arg(static_cast<int>(ih->daddr.byte1))
        .arg(static_cast<int>(ih->daddr.byte2))
        .arg(static_cast<int>(ih->daddr.byte3))
        .arg(static_cast<int>(ih->daddr.byte4));

    // Transport header offset
    const u_char* transportHdr = packetData + ethOffset + ipHdrLen;
    if (len < static_cast<int>(transportHdr - packetData + sizeof(tcp_header))) return false;

    if (info.protocol == "TCP") {
        const tcp_header* th = reinterpret_cast<const tcp_header*>(transportHdr);
        info.sourcePort = ntohs(th->sport);
        info.destPort = ntohs(th->dport);
    }
    else {  // UDP
        const udp_header* uh = reinterpret_cast<const udp_header*>(transportHdr);
        info.sourcePort = ntohs(uh->sport);
        info.destPort = ntohs(uh->dport);
    }

    // Payload snippet: Hex of first 50 bytes after transport header (skip 8 bytes for ports/etc.)
    const u_char* payloadStart = transportHdr + 8;
    int snippetLen = (std::min)(50, len - static_cast<int>(payloadStart - packetData));
    info.payloadSnippet.reserve(3 * snippetLen);
    for (int i = 0; i < snippetLen; ++i) {
        info.payloadSnippet += QString::asprintf("%02x ", payloadStart[i]);
    }
    info.payloadSnippet.chop(1);  // Remove trailing space

    return true;
}