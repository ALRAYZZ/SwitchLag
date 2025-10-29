#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <memory>  // For std::unique_ptr
#include "PacketSniffer.h"  // For PacketSniffer and PacketInfo

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow* ui;
    std::unique_ptr<PacketSniffer> m_sniffer;
};

#endif // MAINWINDOW_H