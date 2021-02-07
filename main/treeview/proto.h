#ifndef PROTO_H
#define PROTO_H

#include <QByteArray>
#include <QStandardItemModel>

#include "types.h"

#define FILED_INFO_NAMELEN    64


/*------------------------------------------------------------------------------*/
/* 包信息 */
/*------------------------------------------------------------------------------*/
typedef struct {
    QString tm;        // 包接收时间点
    QString proto;     // 包协议
    int     length;    // 包长度
    QString info;      // 包其它信息
}st_pack_info;

typedef struct {
    QByteArray          pack_data;  // 包原始数据
    st_pack_info        pack_info;  // 包信息
    QStandardItemModel *pack_diss;  // 包解析后数据
}st_pack;

/*------------------------------------------------------------------------------*/
/* 包解析的树信息 */
/*------------------------------------------------------------------------------*/
/** information describing a header field */
typedef struct _header_field_info header_field_info;

/** information describing a header field */
struct _header_field_info {
    /* ---------- set by dissector --------- */
    char               name[FILED_INFO_NAMELEN];              /**< [FIELDNAME] full name of this field */
    char               abbrev[FILED_INFO_NAMELEN];            /**< [FIELDABBREV] abbreviated name of this field */
    enum ftenum        type;              /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
//    int                display;           /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
//    const void        *strings;           /**< [FIELDCONVERT] value_string, val64_string, range_string or true_false_string,
//                                               typically converted by VALS(), RVALS() or TFS().
//                                               If this is an FT_PROTOCOL or BASE_PROTOCOL_INFO then it points to the
//                                               associated protocol_t structure */
//    guint64            bitmask;           /**< [BITMASK] bitmask of interesting bits */
//    const char        *blurb;             /**< [FIELDDESCR] Brief description of field */

    /* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
//    int                id;                /**< Field ID */
//    int                parent;            /**< parent protocol tree */
//    hf_ref_type        ref_type;          /**< is this field referenced by a filter */
//    int                same_name_prev_id; /**< ID of previous hfinfo with same abbrev */
//    header_field_info *same_name_next;    /**< Link to next hfinfo with same abbrev */
};


/** Contains the field information for the proto_item. */
typedef struct field_info {
    header_field_info   *hfinfo;          /**< pointer to registered field information */
    int                  start;           /**< current start of data in field_info.ds_tvb */
    int                  length;          /**< current data length of item in field_info.ds_tvb */
//    int                  appendix_start;  /**< start of appendix data */
//    int                  appendix_length; /**< length of appendix data */
//    int                  tree_type;       /**< one of ETT_ or -1 */
//    uint32_t             flags;           /**< bitfield like FI_GENERATED, ... */
//    item_label_t        *rep;             /**< string for GUI tree */
//    tvbuff_t            *ds_tvb;          /**< data source tvbuff */
//999999999    fvalue_t             value;
} field_info;

/** Each proto_tree, proto_item is one of these. */
typedef struct _proto_node {
    struct _proto_node *first_child;
    struct _proto_node *last_child;
    struct _proto_node *next;           // 兄弟指针
    struct _proto_node *parent;
    field_info         *finfo;
//    tree_data_t        *tree_data;
} proto_node;

/** A protocol tree element. */
typedef proto_node proto_tree;
/** A protocol item element. */
typedef proto_node proto_item;




#endif // PROTO_H
