#include "MainWindow.h"
#include "ui_MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("SwitchLag MVP - Packet Sniffer");
	resize(1200, 800);
}

MainWindow::~MainWindow()
{
    delete ui;
}

