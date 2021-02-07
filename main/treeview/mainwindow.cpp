#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <QStyleFactory>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    modelTable = new QStandardItemModel(this);
    modelTree = new QStandardItemModel(this);
    modelTableHex = new QStandardItemModel(this);

    // 右对齐  左对齐  左对齐  右对齐  左对齐
    QStringList strlist;
    strlist << "NO." << "Time" << "Protocol" << "Length" << "Info";
    modelTable->setHorizontalHeaderLabels(strlist);

    ui->tableView->setModel(modelTable);
    ui->tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);  // 整行选中
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);   // 禁止修改
    ui->tableView->horizontalHeader()->setStyleSheet("QHeaderView::section{\
        border: 1px solid rgb(200,200,200);\
        border-left:0px solid rgb(200,200,200);\
        padding: 1px 1px 1px 3px;}");  // up right down left
    ui->tableView->verticalHeader()->setVisible(false);
    ui->tableView->setShowGrid(true);

    ui->treeView->setStyle(QStyleFactory::create("windows"));
    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->treeView->setModel(modelTree);

    ui->tableView_hex->setModel(modelTableHex);

    slotTreeShow(NULL);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::slotTreeShow(proto_tree *tree)
{
    Q_UNUSED(tree);
//    QStandardItem *rootItem = modelTree->invisibleRootItem();
//    if (!rootItem)
//        return;
    QStandardItem *item,*item2,*item3;
    QStandardItem *currItem;
    item = new QStandardItem("a");

    modelTree->appendRow(item);
    item2 = new QStandardItem("b");
    item->appendRow(item2);
    item3 = new QStandardItem("c");
    item2->appendRow(item3);
//    QStandardItem *currItem;
//    int row = modelTree->rowCount();
//    currItem = modelTree->item(row, 0);
//    currItem->appendRow(item);

}

