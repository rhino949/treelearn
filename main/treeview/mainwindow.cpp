#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    tablemodel = new QStandardItemModel(this);
    treemodel = new QStandardItemModel(this);

    // 右对齐  左对齐  左对齐  右对齐  左对齐
    QStringList strlist;
    strlist << "NO." << "Time" << "Protocol" << "Length" << "Info";
    tablemodel->setHorizontalHeaderLabels(strlist);

    ui->tableView->setModel(tablemodel);
    ui->tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);  // 整行选中
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);   // 禁止修改
    ui->tableView->horizontalHeader()->setStyleSheet("QHeaderView::section{\
        border: 1px solid rgb(200,200,200);\
        border-left:0px solid rgb(200,200,200);\
        padding: 1px 1px 1px 3px;}");  // up right down left
    ui->tableView->verticalHeader()->setVisible(false);
    ui->tableView->setShowGrid(true);
}

MainWindow::~MainWindow()
{
    delete ui;
}
