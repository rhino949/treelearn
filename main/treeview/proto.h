#ifndef PROTO_H
#define PROTO_H

#include <QByteArray>
#include <QStandardItemModel>

typedef struct {
    QString tm;
    QString proto;
    int     length;
    QString info;
}st_pack_info;

typedef struct {
    QByteArray          pack_data;
    st_pack_info        pack_info;
    QStandardItemModel *pack_diss;
}st_pack;








#endif // PROTO_H
