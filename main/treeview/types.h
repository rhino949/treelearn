#ifndef TYPES_H
#define TYPES_H

/* field types */
enum ftenum {
    FT_NONE,	/* used for text labels with no value */
    FT_PROTOCOL,
    FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
    FT_CHAR,	/* 1-octet character as 0-255 */
    FT_UINT8,
    FT_UINT16,
    FT_UINT24,	/* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
    FT_UINT32,
    FT_UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
    FT_UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
    FT_UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
    FT_UINT64,
    FT_INT8,
    FT_INT16,
    FT_INT24,	/* same as for UINT24 */
    FT_INT32,
    FT_INT40, /* same as for UINT40 */
    FT_INT48, /* same as for UINT48 */
    FT_INT56, /* same as for UINT56 */
    FT_INT64,
    FT_IEEE_11073_SFLOAT,
    FT_IEEE_11073_FLOAT,
    FT_FLOAT,
    FT_DOUBLE,
    FT_ABSOLUTE_TIME,
    FT_RELATIVE_TIME,
    FT_STRING,	/* counted string, with no null terminator */
    FT_STRINGZ,	/* null-terminated string */
    FT_UINT_STRING,	/* counted string, with count being the first part of the value */
    FT_ETHER,
    FT_BYTES,
    FT_UINT_BYTES,
    FT_IPv4,
    FT_IPv6,
    FT_IPXNET,
    FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
    FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
    FT_GUID,	/* GUID, UUID */
    FT_OID,		/* OBJECT IDENTIFIER */
    FT_EUI64,
    FT_AX25,
    FT_VINES,
    FT_REL_OID,	/* RELATIVE-OID */
    FT_SYSTEM_ID,
    FT_STRINGZPAD,	/* null-padded string */
    FT_FCWWN,
    FT_STRINGZTRUNC,	/* null-truncated string */
    FT_NUM_TYPES /* last item number plus one */
};



#endif // TYPES_H
