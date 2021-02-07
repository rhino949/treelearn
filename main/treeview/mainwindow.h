#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "proto.h"

#define VERSION "PAN.1.0"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void slotTreeShow(proto_tree *tree);

private:
    Ui::MainWindow *ui;
    QStandardItemModel *modelTable;
    QStandardItemModel *modelTree;
    QStandardItemModel *modelTableHex;
};

#endif // MAINWINDOW_H
