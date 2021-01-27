#include "proto.h"
#include <QDateTime>

void dissect_pack(st_pack *pack)
{
    pack->pack_info.tm = QTime::currentTime().toString("hh:mm:ss.zzz");
    pack->pack_info.proto = "dl645";
    pack->pack_info.length = pack->pack_data.size();
    pack->pack_info.info = "none";



}
