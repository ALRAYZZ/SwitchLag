#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QDebug>
#include <pcap.h>  

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("SwitchLag MVP - Packet Sniffer");
    resize(1200, 800);

    // Temp: List interfaces to find a valid one (run once, check Debug Output)
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            qDebug() << "Dev:" << d->name << (d->description ? d->description : "No desc");
        }
        pcap_freealldevs(alldevs);
    }
    else {
        qDebug() << "pcap_findalldevs failed:" << errbuf;
    }

    // Pick an interface GUID from above logs (e.g., Ethernet, not loopback). Replace below!
    QString iface = R"(\Device\NPF_{YOUR_GUID_HERE})";  // e.g., \Device\NPF_{12345678-ABCD-...}
    // For loopback testing: iface = R"(\Device\NPF_Loopback)";  // Generate traffic with ping 127.0.0.1

    m_sniffer = std::make_unique<PacketSniffer>(iface);
    if (m_sniffer->startCapture(20)) {  // Capture 20 packets for testing
        connect(m_sniffer.get(), &PacketSniffer::newPacket, [](const PacketInfo& p) {
            qDebug() << p.timestamp << p.sourceIP << ":" << p.sourcePort
                << "->" << p.destIP << ":" << p.destPort << p.protocol
                << "Len:" << p.length << "Snippet:" << p.payloadSnippet.left(50);
            });
        qDebug() << "Started capture on" << iface << "- generate traffic (e.g., ping 8.8.8.8 or browse)!";
    }
    else {
        qDebug() << "Failed to start capture on" << iface;
    }
}

MainWindow::~MainWindow()
{
    if (m_sniffer) {
        m_sniffer->stopCapture();
    }
    delete ui;
}