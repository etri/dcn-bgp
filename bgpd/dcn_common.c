#include "dcn_common.hpp"

std::shared_ptr<dcn::DcnMaster> g_dcn_master;
void set_dcn_master(std::shared_ptr<dcn::DcnMaster> dcn_master)
{
    g_dcn_master = dcn_master;
}
std::shared_ptr<dcn::DcnMaster> get_dcn_master()
{
    return g_dcn_master;
}

char *toErrString(uint8_t err)
{
    if( err == DCN_ERR_NO )
        return (char *)"No Error";
    else if( err == DCN_ERR_NO_EXIST )
        return (char *)"Exist Error";
    else
        return (char *)"Unknown Error";
}

void dcn_master_terminate()
{

    get_dcn_master()->terminate(); 
}

