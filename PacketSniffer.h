#pragma once
#include <QString>
#include <QDateTime>
#include <cstdint>

struct PacketInfo
{
	QDateTime timestamp;
	QString sourceIP;
	QString destIP;
	quint16 sourcePort = 0;
	quint16 destPort = 0;
	QString protocol;
	int length = 0;
	QString payloadSnipper;

	PacketInfo() = default;
};
