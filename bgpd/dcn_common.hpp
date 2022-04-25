#ifndef __DCN_COMMON_HPP__
#define __DCN_COMMON_HPP__

#include <iostream>
#include "dcn_master.hpp"

void set_dcn_master(std::shared_ptr<dcn::DcnMaster>);
std::shared_ptr<dcn::DcnMaster> get_dcn_master();

/* BGP message types.  */
static const uint8_t DCN_BGP_MSG_OPEN = 1;
static const uint8_t  DCN_BGP_MSG_UPDATE =                      2;
static const uint8_t  DCN_BGP_MSG_NOTIFY =                      3;
static const uint8_t DCN_BGP_MSG_KEEPALIVE =                   4;
static const uint8_t DCN_BGP_MSG_ROUTE_REFRESH_NEW   =         5;
static const uint8_t DCN_BGP_MSG_CAPABILITY          =         6;
static const uint8_t DCN_BGP_MSG_SESSION             =         7;
static const uint8_t DCN_BGP_MSG_ROUTE_REFRESH_OLD   =         128;
static const uint8_t DCN_BGP_MSG_NO_NEIGHBOR   =         200;


static const uint16_t UPDATE_REFRESH_TIME =1800;
static const uint8_t RIB_REFRESH_TIME = 1;

struct bgp_header{
 uint8_t marker[16];
 uint16_t length;
 uint8_t type;
 };

static const uint8_t DCN_ERR_NO             =         0;
static const uint8_t DCN_ERR_NO_EXIST             =         1;
typedef struct _dcn_status{
    uint16_t code;
    uint16_t subcode;
    uint64_t aux;
}__attribute__ ((packed)) DCN_STATUS_T;

char *toErrString(uint8_t err);

void dcn_master_terminate();

#endif
