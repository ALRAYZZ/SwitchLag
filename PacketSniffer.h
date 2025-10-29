#pragma once
#include <QString>
#include <QDateTime>
#include <QObject>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <queue>
#include <memory>
#include <pcap.h>  // Npcap core

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

struct PacketInfo {
    QDateTime timestamp;
    QString sourceIP;
    QString destIP;
    quint16 sourcePort = 0;
    quint16 destPort = 0;
    QString protocol;
    int length = 0;
    QString payloadSnippet;

    PacketInfo() = default;
};

// Custom structs for headers (Windows-compatible, no netinet needed)
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + IP header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol (e.g., 6=TCP, 17=UDP)
    u_short crc;            // Header checksum
    ip_address saddr;       // Source address
    ip_address daddr;       // Destination address
    u_int   op_pad;         // Option + Padding
} ip_header;

typedef struct tcp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int   sequence;       // Sequence number
    u_int   ack;            // Acknowledgment number
    u_char  doff_res;       // Data offset (4 bits) + Reserved (4 bits)
    u_char  flags;          // TCP flags
    u_short window;         // Window size
    u_short checksum;       // Checksum
    u_short urgent;         // Urgent pointer
    // Options follow...
} tcp_header;

typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
} udp_header;

class PacketSniffer : public QObject {
    Q_OBJECT

public:
    explicit PacketSniffer(const QString& interfaceName, QObject* parent = nullptr);
    ~PacketSniffer();

    bool startCapture(int packetLimit = -1);  // -1 = infinite
    void stopCapture();
    QString getInterface() const { return m_interfaceName; }

signals:
    void newPacket(const PacketInfo& packet);

private:
    bool parsePacket(const u_char* packetData, int len, PacketInfo& info);
    std::unique_ptr<pcap_t, decltype(&pcap_close)> m_pcapHandle;
    QString m_interfaceName;
    QThread* m_captureThread = nullptr;
    bool m_isRunning = false;
    int m_packetLimit = -1;

    // Static callback for pcap
    static void packetHandler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void handlePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
};