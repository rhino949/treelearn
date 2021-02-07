

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <prefs.h>

static int proto_rrc_rrc_ctrl_sap = -1;


static int hf_padding = -1;
static int hf_emProcedureCode = -1;
static int hf_emMsgType = -1;
static int hf_u16OldUeid = -1;
static int hf_u16NewUeid = -1;
static int hf_u16TargetCellMid = -1;
static int hf_u8Num = -1;
static int hf_u8ErabId = -1;
static int hf_u32TransAddr = -1;
static int hf_u8GtpTeid = -1;
static int hf_emCauseGroupSelect = -1;
static int hf_emCauseRadioNetworkLayer = -1;
static int hf_emCauseTransportLayer = -1;
static int hf_emCauseProtocol = -1;
static int hf_emCauseMiscellaneous = -1;
static int hf_u16BufferLen = -1;
static int hf_rrcdata = -1;
static int hf_u8ProcedureCode = -1;
static int hf_emTriggeringMessage = -1;
static int hf_emProcedureCriticality = -1;
static int hf_u8Elem = -1;
static int hf_u16IeId = -1;
static int hf_emTypeOfError = -1;
static int hf_u8ReceiveStatusofULPDCPSDUs = -1;
static int hf_u16PdcpSN = -1;
static int hf_u32Hfn = -1;
static int hf_u8ErabnotAdmittedP = -1;
static int hf_u8CriticalDiagnosP = -1;
static int hf_u8ULGtpTunnelEndpointP = -1;
static int hf_u8DLGtpTunnelEndpointP = -1;
static int hf_u8ProcedureCodeP = -1;
static int hf_u8TriggeringMessageP = -1;
static int hf_u8ProcedureCriticalityP = -1;
static int hf_u8IeCriticalityDiagnosticsP = -1;
static int hf_u8ReceiveStatusofULPDCPSDUsP = -1;
static int hf_u8NewUeidP = -1;


static gint ett_X2AP_Criticality_DIAGONSTICS = -1;
static gint ett_rrc = -1;
static gint ett_X2AP_TRANSPARENT_CONTAINER = -1;
static gint ett_CauseGroup = -1;
static gint ett_X2AP_CAUSE_S = -1;
static gint ett_X2AP_E_RAB_ITEM = -1;
static gint ett_X2AP_E_RAB_LIST = -1;
static gint ett_Dl_X2AP_GTPTUNNEL_ENDPOINT = -1;
static gint ett_X2AP_GTP_TEID = -1;
static gint ett_Ul_X2AP_GTPTUNNEL_ENDPOINT = -1;
static gint ett_X2AP_E_RAB_ADMITTED_ITEM = -1;
static gint ett_X2AP_E_RABS_ADMITTED_LIST = -1;
static gint ett_X2AP_MESSAGE_TYPE = -1;
static gint ett_X2AP_CRITICALTY_DIAGONSTICS_IE_LIST = -1;
static gint ett_X2AP_IE_CRITICALTY_DIAGONSTICS = -1;
static gint ett_X2AP_E_RAB_STATUS_TRANSFER_ITEM = -1;
static gint ett_UL_X2AP_COUNT_VALUE = -1;
static gint ett_X2AP_E_RAB_STATUS_TRANSFER_LIST = -1;
static gint ett_DL_X2AP_COUNT_VALUE = -1;

static gint ett_rrc_rrc_ctrl_sap = -1;


static const char *rrc_rrc_ctrl_proto_name = "RRC RRC CTRL SAP";
static const char *rrc_rrc_ctrl_proto_name_short = "rrc rrc ctrl";

dissector_handle_t rrc_rrc_ctrl_handle=NULL;
extern dissector_handle_t lte_rrc_handle;

#define X2AP_MAX_NO_OF_ERABS         4
#define X2AP_MAX_RRC_CONTEXT         1024
#define X2AP_MAX_NO_OF_ERRORS        32
#define X2AP_ULPDCP_SDU_STATUS       512




const value_string emCauseGroupSelect_vals[] = {
  {   1, "X2_S_CAUSE_RADIONETWORK_LAYER" },
  {   2, "X2_S_CAUSE_TRANSPORT_LAYER" },
  {   3, "X2_S_CAUSE_PROTOCOL" },
  {   4, "X2_S_CAUSE_MISCELLANEOUS" },
  { 0, NULL }
};


const value_string emCauseRadioNetworkLayer_vals[] = {
  {   0, "X2_HANDOVER_DESIRABLE_FOR_RADIO_REASONS" },
  {   1, "X2_TIME_CRITICAL_HANDOVER" },
  {   2, "X2_RESOURCE_OPTIMISATION_HANDOVER" },
  {   3, "X2_REDUCE_LOAD_IN_SERVING_CELL" },
  {   4, "X2_PARTIAL_HANDOVER" },
  {   5, "X2_UNKNOWN_NEW_ENB_UE_X2AP_ID" },
  {   6, "X2_UNKNOWN_OLD_ENB_UE_X2AP_ID" },
  {   7, "X2_UNKNOWN_PAIR_OF_UE_X2AP_ID" },
  {   8, "X2_HO_TARGET_NOT_ALLOWED" },
  {   9, "X2_TX2RELOCOVERALL_EXPIRY" },
  {   10, "X2_TRELOCPREP_EXPIRY" },
  {   11, "X2_CELL_NOT_AVAILABLE" },
  {   12, "X2_NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL" },
  {   13, "X2_INVALID_MME_GROUPID" },
  {   14, "X2_UNKNOWN_MME_CODE" },
  {   15, "X2_UNSPECIFIED_2" },
  { 0, NULL }
};

const value_string emCauseTransportLayer_vals[] = {
  {   0, "X2_TRANSPORT_RESOURCE_UNAVAILABLE" },
  {   1, "X2_UNSPECIFIDE_3" },
  { 0, NULL }
};


const value_string emCauseProtocol_vals[] = {
  {   0, "X2_TRANSFER_SYNTAX_ERROR" },
  {   1, "X2_ABSTRACT_SYNTAX_ERROR_REJECT" },
  {   2, "X2_ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY" },
  {   3, "X2_MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE" },
  {   4, "X2_SEMANTIC_ERROR" },
  {   5, "X2_UNSPECIFIED_1" },
  {   6, "X2_ABSTRACT_SYNTAX_ERROR_FALSELY_CONSTRUCTED_MESSAGE" },
  { 0, NULL }
};

const value_string emCauseMiscellaneous_vals[] = {
  {   0, "X2_CONTROL_PROCESSING_OVERLOAD" },
  {   1, "X2_HARDWARE_FAILURE" },
  {   2, "X2_OM_INTERVENTION" },
  {   3, "X2_NOT_ENOUGH_USER_PLANE_PROCESSING_RESOURCES" },
  {   4, "X2_UNSPECIFIED" },
  { 0, NULL }
};

const value_string emProcedureCode_val[] = {
  {   0, "X2AP_ID_HANDOVER_PREPARATION" },
  {   1, "X2AP_ID_HANDOVER_CANCEL" },
  {   2, "X2AP_ID_LOAD_INDICATION" },
  {   3, "X2AP_ID_ERROR_INDICATION" },
  {   4, "X2AP_ID_SN_STATUS_TRANSFER" },
  {   5, "X2AP_ID_UE_CONTEXT_RELEASE" },
  {   6, "X2AP_ID_X2_SETUP" },
  {   7, "X2AP_ID_RESET" },
  {   8, "X2AP_ID_ENB_CONFIGRATION_UPDATE" },
  {   9, "X2AP_ID_RESOURCE_STATUS_UPDATE_INITIATION" },
  {   10, "X2AP_ID_RESOURCE_STATUS_REPORTING" },
  {   11, "X2AP_ID_PRIVATE_MESSAGE" },
  { 0, NULL }
};


const value_string emMsgType_val[] = {
  {   0, "X2AP_INITIATING_MESSAGE" },
  {   1, "X2AP_SUCCESSFUL_OUTCOME" },
  {   2, "X2AP_UNSUCCESSFUL_OUTCOME" },
  { 0, NULL }
};


const value_string emProcedureCriticality_val[] = {
  {   0, "X2AP_reject" },
  {   1, "X2AP_ignore" },
  {   2, "X2AP_notify" },
  { 0, NULL }
};


const value_string emTypeOfError_val[] = {
  {   0, "X2AP_not_understood" },
  {   1, "X2AP_missing" },
  { 0, NULL }
};


static void dissect_trcp_srcp_intra_handover_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	int i=0;
	int j=0;
	int k=0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
	proto_tree* X2AP_E_RABS_ADMITTED_LIST_tree = NULL;
	proto_tree* X2AP_E_RAB_ADMITTED_ITEM_tree = NULL;
	proto_tree* UL_X2AP_GTPTUNNEL_ENDPOINT_tree = NULL;
	proto_tree* DL_X2AP_GTPTUNNEL_ENDPOINT_tree = NULL;
	proto_tree* X2AP_GTP_TEID_tree = NULL;
	proto_tree* X2AP_E_RAB_LIST_tree = NULL;
	proto_tree* X2AP_E_RAB_ITEM_tree = NULL;
	proto_tree* X2AP_CAUSE_S_tree = NULL;
	proto_tree* CauseGroup_tree = NULL;
	proto_tree* X2AP_TRANSPARENT_CONTAINER_tree = NULL;
	proto_tree* X2AP_Criticality_DIAGONSTICS_tree = NULL;
	proto_tree* X2AP_IE_CRITICALTY_DIAGONSTICS_tree = NULL;
	proto_tree* X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree = NULL;
	guint16 CauseGroupSelect = 0;
	gchar *ValStr = (gchar*)malloc(50);
	const guint8* dataPtr;
	//tvbuff_t* next_tvb = NULL;
	//proto_tree* rrc_tree = NULL;
      guint16 oct1 = 0;
      guint8 amNum=0;
      guint8 ulNum=0;      
      guint8 dlNum=0;
      guint8 erabNum=0;
      guint8 listIe =0;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Trcp Srcp Intra Handover Ind");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;


	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(tree, hf_u8ErabnotAdmittedP, tvb, offset, 1, PC_BYTE_ORDER);
	offset++;
	
	proto_tree_add_item(tree, hf_u8CriticalDiagnosP, tvb, offset, 1, PC_BYTE_ORDER);
	offset++;
	
	proto_tree_add_item(tree, hf_u16TargetCellMid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	/*for(i=0;i<2;i++)
	{
		proto_tree_add_item(tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
	}*/

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_E_RABS_ADMITTED_LIST");
	X2AP_E_RABS_ADMITTED_LIST_tree= proto_item_add_subtree(pi,ett_X2AP_E_RABS_ADMITTED_LIST);
	{
             amNum = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(X2AP_E_RABS_ADMITTED_LIST_tree, hf_u8Num, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;

		/*for(i=0;i<3;i++)
		{
			proto_tree_add_item(X2AP_E_RABS_ADMITTED_LIST_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
			offset++;
		}*/

            if(amNum>0 && amNum<X2AP_MAX_NO_OF_ERABS)
            {
                    for(i=0;i<amNum;i++)
                    {
            			sprintf(ValStr, "E RAB ADMITTED ITEM %d", i+1);
        			pi = proto_tree_add_text(X2AP_E_RABS_ADMITTED_LIST_tree,tvb,0,0,ValStr);
        			X2AP_E_RAB_ADMITTED_ITEM_tree= proto_item_add_subtree(pi,ett_X2AP_E_RAB_ADMITTED_ITEM);

        			proto_tree_add_item(X2AP_E_RAB_ADMITTED_ITEM_tree, hf_u8ULGtpTunnelEndpointP, tvb, offset, 1, PC_BYTE_ORDER);
        			offset++;

        			proto_tree_add_item(X2AP_E_RAB_ADMITTED_ITEM_tree, hf_u8DLGtpTunnelEndpointP, tvb, offset, 1, PC_BYTE_ORDER);
        			offset++;

        			proto_tree_add_item(X2AP_E_RAB_ADMITTED_ITEM_tree, hf_u8ErabId, tvb, offset, 1, PC_BYTE_ORDER);
        			offset++;

        			/*for(j=0;j<3;j++)
        			{
        				proto_tree_add_item(X2AP_E_RAB_ADMITTED_ITEM_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
        				offset++;
        			}*/
        			
        			pi = proto_tree_add_text(X2AP_E_RAB_ADMITTED_ITEM_tree,tvb,0,0,"Ul_X2AP_GTPTUNNEL_ENDPOINT");
        			UL_X2AP_GTPTUNNEL_ENDPOINT_tree= proto_item_add_subtree(pi,ett_Ul_X2AP_GTPTUNNEL_ENDPOINT);
        			{
        				proto_tree_add_item(UL_X2AP_GTPTUNNEL_ENDPOINT_tree, hf_u32TransAddr, tvb, offset, 4, PC_BYTE_ORDER);
        				offset+=4;
        				
        				pi = proto_tree_add_text(UL_X2AP_GTPTUNNEL_ENDPOINT_tree,tvb,0,0,"X2AP_GTP_TEID");
        				X2AP_GTP_TEID_tree= proto_item_add_subtree(pi,ett_X2AP_GTP_TEID);
        				{
                                       ulNum = tvb_get_guint8(tvb, offset);
        					proto_tree_add_item(X2AP_GTP_TEID_tree, hf_u8Num, tvb, offset, 1, PC_BYTE_ORDER);
        					offset++;

        					/*for(k=0;k<3;k++)
        					{
        						proto_tree_add_item(X2AP_GTP_TEID_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
        						offset++;
        					}*/
        					if(ulNum>0 && ulNum<4)
                                        {
                                             for(k=0;k<ulNum;k++)
                					{
                						proto_tree_add_item(X2AP_GTP_TEID_tree, hf_u8GtpTeid, tvb, offset, 1, PC_BYTE_ORDER);
                						offset++;
                					}
                                             for(k=ulNum;k<4;k++)
                                             {
                                                    offset+=1;
                                             }
                                        }
        					else
                                        {
                                                offset+=4;
                                        }               
        						
        				}
        			}

        			pi = proto_tree_add_text(X2AP_E_RAB_ADMITTED_ITEM_tree,tvb,0,0,"Dl_X2AP_GTPTUNNEL_ENDPOINT");
        			DL_X2AP_GTPTUNNEL_ENDPOINT_tree= proto_item_add_subtree(pi,ett_Dl_X2AP_GTPTUNNEL_ENDPOINT);
        			{
        				proto_tree_add_item(DL_X2AP_GTPTUNNEL_ENDPOINT_tree, hf_u32TransAddr, tvb, offset, 4, PC_BYTE_ORDER);
        				offset+=4;
        				
        				pi = proto_tree_add_text(DL_X2AP_GTPTUNNEL_ENDPOINT_tree,tvb,0,0,"X2AP_GTP_TEID");
        				X2AP_GTP_TEID_tree= proto_item_add_subtree(pi,ett_X2AP_GTP_TEID);
        				{
                                      dlNum = tvb_get_guint8(tvb, offset);
        					proto_tree_add_item(X2AP_GTP_TEID_tree, hf_u8Num, tvb, offset, 1, PC_BYTE_ORDER);
        					offset++;

        					/*for(k=0;k<3;k++)
        					{
        						proto_tree_add_item(X2AP_GTP_TEID_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
        						offset++;
        					}*/
        					if(dlNum>0 && dlNum<4 )
                                      {                                            
                                            for(k=0;k<dlNum;k++)
                                            {
                                                proto_tree_add_item(X2AP_GTP_TEID_tree, hf_u8GtpTeid, tvb, offset, 1, PC_BYTE_ORDER);
                                                offset++;
                                            }
                                            for(k=dlNum;k<4;k++)
                                            {
                                                 offset++;
                                            }
                                      }               
                                      else
                                      {
                                            offset+=4;
                                      }

        				}
        			}	
        			memset(ValStr,0, 50);
		    }
                for(i= amNum; i<X2AP_MAX_NO_OF_ERABS; i++)
                {
                    offset+=21;
                }
            }
            else
            {
                offset+=(X2AP_MAX_NO_OF_ERABS*21);
            }
	}


	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_E_RAB_LIST");
	X2AP_E_RAB_LIST_tree= proto_item_add_subtree(pi,ett_X2AP_E_RAB_LIST);
	{
            erabNum = tvb_get_guint8(tvb,offset);
		proto_tree_add_item(X2AP_E_RAB_LIST_tree, hf_u8Num, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;

		/*for(i=0;i<3;i++)
		{
			proto_tree_add_item(X2AP_E_RAB_LIST_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
			offset++;
		}*/
        if(erabNum>0 && erabNum<X2AP_MAX_NO_OF_ERABS)
        {
             for(i=0;i<erabNum;i++)
    		{
    			sprintf(ValStr, "E RAB ITEM %d", i+1);
    			pi = proto_tree_add_text(X2AP_E_RAB_LIST_tree,tvb,0,0,ValStr);
    			X2AP_E_RAB_ITEM_tree= proto_item_add_subtree(pi,ett_X2AP_E_RAB_ITEM);

    			proto_tree_add_item(X2AP_E_RAB_ITEM_tree, hf_u8ErabId, tvb, offset, 1, PC_BYTE_ORDER);
    			offset++;

    			/*for(j=0;j<3;j++)
    			{
    				proto_tree_add_item(X2AP_E_RAB_ITEM_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
    				offset++;
    			}*/
    			
    			pi = proto_tree_add_text(X2AP_E_RAB_ITEM_tree,tvb,0,0,"X2AP_CAUSE_S");
    			X2AP_CAUSE_S_tree= proto_item_add_subtree(pi,ett_X2AP_CAUSE_S);
    			{
    				CauseGroupSelect = tvb_get_ntohs(tvb,offset);
    				proto_tree_add_item(X2AP_CAUSE_S_tree, hf_emCauseGroupSelect, tvb, offset, 4, PC_BYTE_ORDER);
    				offset+=4;
    				
    				pi = proto_tree_add_text(X2AP_CAUSE_S_tree,tvb,0,0,"CauseGroup");
    				CauseGroup_tree= proto_item_add_subtree(pi,ett_CauseGroup);
    				switch(CauseGroupSelect)
    				{
    					case 0:
    						proto_tree_add_item(CauseGroup_tree, hf_emCauseRadioNetworkLayer, tvb, offset, 4, PC_BYTE_ORDER);
    						offset+=4;
    						break;

    					case 1:
    						proto_tree_add_item(CauseGroup_tree, hf_emCauseTransportLayer, tvb, offset, 4, PC_BYTE_ORDER);
    						offset+=4;
    						break;

    					case 2:
    						proto_tree_add_item(CauseGroup_tree, hf_emCauseProtocol, tvb, offset, 4, PC_BYTE_ORDER);
    						offset+=4;
    						break;

    					case 3:
    						proto_tree_add_item(CauseGroup_tree, hf_emCauseMiscellaneous, tvb, offset, 4, PC_BYTE_ORDER);
    						offset+=4;
    						break;
    				}
    			}	
    			memset(ValStr,0, 50);
    		}
             for(i=erabNum;i<X2AP_MAX_NO_OF_ERABS;i++)
             {
                offset +=9;
             }
        }
        else
        {
            offset += (X2AP_MAX_NO_OF_ERABS*9);
        }
	}


	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_TRANSPARENT_CONTAINER");
	X2AP_TRANSPARENT_CONTAINER_tree= proto_item_add_subtree(pi,ett_X2AP_TRANSPARENT_CONTAINER);
	{
		proto_tree_add_item(X2AP_TRANSPARENT_CONTAINER_tree, hf_u16BufferLen, tvb, offset, 2, PC_BYTE_ORDER);
		offset+=2;

		//pi = proto_tree_add_text(X2AP_TRANSPARENT_CONTAINER_tree,tvb,0,0,"rrc");
    	//rrc_tree = proto_item_add_subtree(pi,ett_rrc);
		//for(i=0;i<X2AP_MAX_RRC_CONTEXT;i++)
		//{
			dataPtr = tvb_get_ptr(tvb, offset, X2AP_MAX_RRC_CONTEXT);
			//next_tvb = tvb_new_subset(tvb, offset, X2AP_MAX_RRC_CONTEXT, X2AP_MAX_RRC_CONTEXT);
			proto_tree_add_bytes(X2AP_TRANSPARENT_CONTAINER_tree, hf_rrcdata, tvb, offset, X2AP_MAX_RRC_CONTEXT, dataPtr);
			offset+=X2AP_MAX_RRC_CONTEXT;
		//}

	}


	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_Criticality_DIAGONSTICS");
	X2AP_Criticality_DIAGONSTICS_tree= proto_item_add_subtree(pi,ett_X2AP_Criticality_DIAGONSTICS);
	{
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCodeP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8TriggeringMessageP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCriticalityP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8IeCriticalityDiagnosticsP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCode, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;

		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_emTriggeringMessage, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
		
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_emProcedureCriticality, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
		
		pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_IE_CRITICALTY_DIAGONSTICS");
		X2AP_IE_CRITICALTY_DIAGONSTICS_tree= proto_item_add_subtree(pi,ett_X2AP_IE_CRITICALTY_DIAGONSTICS);
		{
                    listIe = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(X2AP_IE_CRITICALTY_DIAGONSTICS_tree, hf_u8Elem, tvb, offset, 1, PC_BYTE_ORDER);
			offset++;

                   if(listIe>0 &&listIe<X2AP_MAX_NO_OF_ERRORS)
                   {
                          for(i=0;i<listIe;i++)
        			{
        				sprintf(ValStr, "CRITICALTY DIAGONSTICS IE LIST %d", i+1);
        				pi = proto_tree_add_text(X2AP_IE_CRITICALTY_DIAGONSTICS_tree,tvb,0,0,ValStr);
        				X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree= proto_item_add_subtree(pi,ett_X2AP_CRITICALTY_DIAGONSTICS_IE_LIST);
        				{
        					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_emProcedureCriticality, tvb, offset, 4, PC_BYTE_ORDER);
        					offset+=4;

        					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_u16IeId, tvb, offset, 2, PC_BYTE_ORDER);
        					offset+=2;

        					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_emTypeOfError, tvb, offset, 4, PC_BYTE_ORDER);
        					offset+=4;
        				}
        				memset(ValStr,0, 50);
        			}
                          for(i=listIe;i<X2AP_MAX_NO_OF_ERRORS;i++)
                          {
                                offset+=10;
                          }
                   }
                   else
                   {
                        offset+=(X2AP_MAX_NO_OF_ERRORS*10);
                   }
			
		}

	}

free(ValStr);
ValStr = NULL;    
}


static void dissect_x2ap_intra_ho_prepare_fail_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	int i=0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
	proto_tree* X2AP_CAUSE_S_tree = NULL;
	proto_tree* CauseGroup_tree = NULL;
	proto_tree* X2AP_Criticality_DIAGONSTICS_tree = NULL;
	proto_tree* X2AP_IE_CRITICALTY_DIAGONSTICS_tree = NULL;
	proto_tree* X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree = NULL;
	guint16 CauseGroupSelect = 0;
      guint16 oct1 = 0;
    guint8 errorNum=0;
	gchar *ValStr = (gchar*)malloc(50);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "x2ap intra ho prepare fail msg");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;
	
	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(tree, hf_u8CriticalDiagnosP, tvb, offset, 1, PC_BYTE_ORDER);
	offset++;
			
	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_CAUSE_S");
	X2AP_CAUSE_S_tree= proto_item_add_subtree(pi,ett_X2AP_CAUSE_S);
	{
		CauseGroupSelect = tvb_get_ntohs(tvb,offset);
		proto_tree_add_item(X2AP_CAUSE_S_tree, hf_emCauseGroupSelect, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
				
		pi = proto_tree_add_text(X2AP_CAUSE_S_tree,tvb,0,0,"CauseGroup");
		CauseGroup_tree= proto_item_add_subtree(pi,ett_CauseGroup);
		switch(CauseGroupSelect)
		{
			case 0:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseRadioNetworkLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 1:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseTransportLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 2:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseProtocol, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 3:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseMiscellaneous, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;
		}
	}		
			


	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_Criticality_DIAGONSTICS");
	X2AP_Criticality_DIAGONSTICS_tree= proto_item_add_subtree(pi,ett_X2AP_Criticality_DIAGONSTICS);
	{
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCodeP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8TriggeringMessageP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCriticalityP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8IeCriticalityDiagnosticsP, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_u8ProcedureCode, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;

		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_emTriggeringMessage, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
		
		proto_tree_add_item(X2AP_Criticality_DIAGONSTICS_tree, hf_emProcedureCriticality, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
		
		pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_IE_CRITICALTY_DIAGONSTICS");
		X2AP_IE_CRITICALTY_DIAGONSTICS_tree= proto_item_add_subtree(pi,ett_X2AP_IE_CRITICALTY_DIAGONSTICS);
		{
                   errorNum = tvb_get_guint8(tvb,offset);
			proto_tree_add_item(X2AP_IE_CRITICALTY_DIAGONSTICS_tree, hf_u8Elem, tvb, offset, 1, PC_BYTE_ORDER);
			offset++;
                if(errorNum>0 &&  errorNum<X2AP_MAX_NO_OF_ERABS)
                {
			for(i=0;i<errorNum;i++)/*zhangj 2011-11-14 modify for omcrct_optimise1*/
			{
				sprintf(ValStr, "CRITICALTY DIAGONSTICS IE LIST %d", i+1);
				pi = proto_tree_add_text(X2AP_IE_CRITICALTY_DIAGONSTICS_tree,tvb,0,0,ValStr);
				X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree= proto_item_add_subtree(pi,ett_X2AP_CRITICALTY_DIAGONSTICS_IE_LIST);
				{
					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_emProcedureCriticality, tvb, offset, 4, PC_BYTE_ORDER);
					offset+=4;

					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_u16IeId, tvb, offset, 2, PC_BYTE_ORDER);
					offset+=2;

					proto_tree_add_item(X2AP_CRITICALTY_DIAGONSTICS_IE_LIST_tree, hf_emTypeOfError, tvb, offset, 4, PC_BYTE_ORDER);
					offset+=4;
				}
				memset(ValStr,0, 50);
			}
                    for(i=errorNum;i<X2AP_MAX_NO_OF_ERABS;i++)
                    {
                        offset+=10;
                    }
		    }
                else
                {
                    offset+=(10*X2AP_MAX_NO_OF_ERABS);
                }
		}

	}
	free(ValStr);
	ValStr = NULL;

    
}



static void dissect_srcp_trcp_sn_status_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	int i = 0;
	int j = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
	proto_tree* X2AP_E_RAB_STATUS_TRANSFER_LIST_tree = NULL;
	proto_tree* X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree = NULL;
	proto_tree* UL_X2AP_COUNT_VALUE_tree = NULL;
	proto_tree* DL_X2AP_COUNT_VALUE_tree = NULL;
	gchar *ValStr = (gchar*)malloc(50);	
      guint8 rabNum=0;
	//tvbuff_t* next_tvb;
	const guint8* dataPtr;
      guint16 oct1 = 0;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Srcp Trcp Sn Status Req");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;


	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_E_RAB_STATUS_TRANSFER_LIST");
	X2AP_E_RAB_STATUS_TRANSFER_LIST_tree= proto_item_add_subtree(pi,ett_X2AP_E_RAB_STATUS_TRANSFER_LIST);
	{
            rabNum = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(X2AP_E_RAB_STATUS_TRANSFER_LIST_tree, hf_u8Num, tvb, offset, 1, PC_BYTE_ORDER);
		offset++;

		/*for(i=0;i<3;i++)
		{
			proto_tree_add_item(X2AP_E_RAB_STATUS_TRANSFER_LIST_tree, hf_padding, tvb, offset, 1, PC_BYTE_ORDER);
			offset++;
		}*/
            if(rabNum>0&&rabNum<X2AP_MAX_NO_OF_ERABS)
            {
        		for(i=0;i<rabNum;i++)
        		{
        			sprintf(ValStr, "E RAB STATUS TRANSFER ITEM %d", i+1);
        			pi = proto_tree_add_text(X2AP_E_RAB_STATUS_TRANSFER_LIST_tree,tvb,0,0,ValStr);
        			X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree= proto_item_add_subtree(pi,ett_X2AP_E_RAB_STATUS_TRANSFER_ITEM);

        			proto_tree_add_item(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree, hf_u8ReceiveStatusofULPDCPSDUsP, tvb, offset, 1, PC_BYTE_ORDER);
        			offset++;

        			proto_tree_add_item(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree, hf_u8ErabId, tvb, offset, 1, PC_BYTE_ORDER);
        			offset++;

        			/*for(j=0;j<X2AP_ULPDCP_SDU_STATUS;j++)
        			{
        				proto_tree_add_item(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree, hf_u8ReceiveStatusofULPDCPSDUs, tvb, offset, 1, PC_BYTE_ORDER);
        				offset++;
        			}*/

        			if(NULL == (dataPtr = tvb_get_ptr(tvb, offset, X2AP_ULPDCP_SDU_STATUS)))
        			{
        				free((guint8 *)dataPtr);
        				return;
        			}
        			//next_tvb = tvb_new_subset(tvb, offset, X2AP_ULPDCP_SDU_STATUS, X2AP_ULPDCP_SDU_STATUS);
        			proto_tree_add_bytes(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree, hf_u8ReceiveStatusofULPDCPSDUs, tvb, offset, X2AP_ULPDCP_SDU_STATUS, dataPtr);
        			offset+=X2AP_ULPDCP_SDU_STATUS;
        			
        			pi = proto_tree_add_text(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree,tvb,0,0,"UL_X2AP_COUNT_VALUE");
        			UL_X2AP_COUNT_VALUE_tree= proto_item_add_subtree(pi,ett_UL_X2AP_COUNT_VALUE);
        			{
        				proto_tree_add_item(UL_X2AP_COUNT_VALUE_tree, hf_u16PdcpSN, tvb, offset, 2, PC_BYTE_ORDER);
        				offset+=2;

        				proto_tree_add_item(UL_X2AP_COUNT_VALUE_tree, hf_u32Hfn, tvb, offset, 4, PC_BYTE_ORDER);
        				offset+=4;
        				
        			}

        			pi = proto_tree_add_text(X2AP_E_RAB_STATUS_TRANSFER_ITEM_tree,tvb,0,0,"DL_X2AP_COUNT_VALUE");
        			DL_X2AP_COUNT_VALUE_tree= proto_item_add_subtree(pi,ett_DL_X2AP_COUNT_VALUE);
        			{
        				proto_tree_add_item(DL_X2AP_COUNT_VALUE_tree, hf_u16PdcpSN, tvb, offset, 2, PC_BYTE_ORDER);
        				offset+=2;

        				proto_tree_add_item(DL_X2AP_COUNT_VALUE_tree, hf_u32Hfn, tvb, offset, 4, PC_BYTE_ORDER);
        				offset+=4;
        				
        			}			
        			memset(ValStr,0, 50);
        		}
                for(i=rabNum;i<X2AP_MAX_NO_OF_ERABS;i++)
                {
                    offset+=X2AP_ULPDCP_SDU_STATUS+14;
                }
		}
            else
            {
                 offset+=(X2AP_MAX_NO_OF_ERABS*(X2AP_ULPDCP_SDU_STATUS+14));
            }
	}
 	free(ValStr);
	ValStr = NULL;   

}

static void dissect_trcp_srcp_handover_complete_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
      guint16 oct1 = 0;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Trcp Srcp Handover Complete Ind");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;


	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

}

static void dissect_stcp_trcp_sn_status_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;


	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Stcp Trcp Sn Status Ind");

    

}

static void dissect_stcp_trcp_handover_cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
	proto_tree* X2AP_CAUSE_S_tree = NULL;
	proto_tree* CauseGroup_tree = NULL;
	guint16 CauseGroupSelect = 0;
      guint16 oct1 = 0;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Stcp Trcp Handover Cancel");

	
	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(tree, hf_u8NewUeidP, tvb, offset, 1, PC_BYTE_ORDER);
	offset++;
			
	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_CAUSE_S");
	X2AP_CAUSE_S_tree= proto_item_add_subtree(pi,ett_X2AP_CAUSE_S);
	{
		CauseGroupSelect = tvb_get_ntohs(tvb,offset);
		proto_tree_add_item(X2AP_CAUSE_S_tree, hf_emCauseGroupSelect, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
				
		pi = proto_tree_add_text(X2AP_CAUSE_S_tree,tvb,0,0,"CauseGroup");
		CauseGroup_tree= proto_item_add_subtree(pi,ett_CauseGroup);
		switch(CauseGroupSelect)
		{
			case 0:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseRadioNetworkLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 1:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseTransportLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 2:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseProtocol, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 3:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseMiscellaneous, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;
		}
	}		
			

}


static void dissect_thirdrcp_srcp_handover_cancel_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
	proto_tree* X2AP_CAUSE_S_tree = NULL;
	proto_tree* CauseGroup_tree = NULL;
	guint16 CauseGroupSelect = 0;
      guint16 oct1 = 0;
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "THIRDRCP_SRCP_HANDOVER_CANCEL_IND");

	
	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(tree, hf_u8NewUeidP, tvb, offset, 1, PC_BYTE_ORDER);
	offset++;
			
	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_CAUSE_S");
	X2AP_CAUSE_S_tree= proto_item_add_subtree(pi,ett_X2AP_CAUSE_S);
	{
		CauseGroupSelect = tvb_get_ntohs(tvb,offset);
		proto_tree_add_item(X2AP_CAUSE_S_tree, hf_emCauseGroupSelect, tvb, offset, 4, PC_BYTE_ORDER);
		offset+=4;
				
		pi = proto_tree_add_text(X2AP_CAUSE_S_tree,tvb,0,0,"CauseGroup");
		CauseGroup_tree= proto_item_add_subtree(pi,ett_CauseGroup);
		switch(CauseGroupSelect)
		{
			case 0:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseRadioNetworkLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 1:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseTransportLayer, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 2:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseProtocol, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;

			case 3:
				proto_tree_add_item(CauseGroup_tree, hf_emCauseMiscellaneous, tvb, offset, 4, PC_BYTE_ORDER);
				offset+=4;
				break;
		}
	}		
			

}


static void dissect_thirdrcp_srcp_ue_context_release_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
      guint16 oct1 = 0;
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "THIRDRCP_SRCP_UE_CONTEXT_RELEASE_IND");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

}



static void dissect_thirdrcp_trcp_ue_context_release_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
	proto_item* pi=NULL;
	proto_tree* X2AP_MESSAGE_TYPE_tree = NULL;
      guint16 oct1 = 0;
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "THIRDRCP_TRCP_UE_CONTEXT_RELEASE_IND");

	pi = proto_tree_add_text(tree,tvb,0,0,"X2AP_MESSAGE_TYPE");
	X2AP_MESSAGE_TYPE_tree= proto_item_add_subtree(pi,ett_X2AP_MESSAGE_TYPE);

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emMsgType, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_emProcedureCode, tvb, offset, 4, PC_BYTE_ORDER);
	offset+=4;

	oct1 = tvb_get_ntohs(tvb,offset);
	if (check_col(pinfo->cinfo, COL_Ue_ID))
	{col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16OldUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

	proto_tree_add_item(X2AP_MESSAGE_TYPE_tree, hf_u16NewUeid, tvb, offset, 2, PC_BYTE_ORDER);
	offset+=2;

}

static void dissect_rrc_rrc_ctrl_sap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*rrc_rrc_ctrl_item = NULL;
	proto_tree	*rrc_rrc_ctrl_tree = NULL;
	
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRC RRC CTRL SAP");

    rrc_rrc_ctrl_item = proto_tree_add_item(tree, proto_rrc_rrc_ctrl_sap, tvb, 0, -1, PC_BYTE_ORDER);
    rrc_rrc_ctrl_tree = proto_item_add_subtree(rrc_rrc_ctrl_item, ett_rrc_rrc_ctrl_sap);

    
	switch(pinfo->pseudo_header->omc.tr_content.all_tr.msgType)
	{
		case 1: //Trcp Srcp Intra Handover Ind
			if(pinfo->pseudo_header->omc.tr_content.all_tr.MsgLen==2032)
		    	dissect_trcp_srcp_intra_handover_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			else
				dissect_x2ap_intra_ho_prepare_fail_msg(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;

		case 2: //Srcp Trcp Sn Status Req
			dissect_srcp_trcp_sn_status_req(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;

		case 3: //Trcp Srcp Handover Complete Ind
			dissect_trcp_srcp_handover_complete_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;

		case 4: //Stcp Trcp Sn Status Ind
			dissect_stcp_trcp_sn_status_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;

		case 5: //Stcp Trcp Handover Cancel
			dissect_stcp_trcp_handover_cancel(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;
			
		case 6: //THIRDRCP_SRCP_HANDOVER_CANCEL_IND
			dissect_thirdrcp_srcp_handover_cancel_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;
			
		case 7: //THIRDRCP_SRCP_UE_CONTEXT_RELEASE_IND
			dissect_thirdrcp_srcp_ue_context_release_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;
			
		case 8: //THIRDRCP_TRCP_UE_CONTEXT_RELEASE_IND
			dissect_thirdrcp_trcp_ue_context_release_ind(tvb, pinfo, rrc_rrc_ctrl_tree);
			break;
		default:
			break;
	}
	

    return;

}


void
proto_register_rrc_rrc_ctrl_sap(void)
{
    static hf_register_info hf[] = {

		{ &hf_padding,
      		{ "padding8", "rrc_rrc_ctrl_sap.padding8",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.padding8", HFILL }},

		{ &hf_emProcedureCode,
      		{ "emProcedureCode", "rrc_rrc_ctrl_sap.emProcedureCode",
        		FT_UINT32, BASE_DEC, emProcedureCode_val, 0,
        			"rrc_rrc_ctrl_sap.emProcedureCode", HFILL }},

		{ &hf_emMsgType,
      		{ "emMsgType", "rrc_rrc_ctrl_sap.emMsgType",
        		FT_UINT32, BASE_DEC, emMsgType_val, 0,
        			"rrc_rrc_ctrl_sap.emMsgType", HFILL }},

		{ &hf_u16OldUeid,
      		{ "u16OldUeid", "rrc_rrc_ctrl_sap.u16OldUeid",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16OldUeid", HFILL }},

		{ &hf_u16NewUeid,
      		{ "u16NewUeid", "rrc_rrc_ctrl_sap.u16NewUeid",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16NewUeid", HFILL }},

		{ &hf_u16TargetCellMid,
      		{ "u16TargetCellMid", "rrc_rrc_ctrl_sap.u16TargetCellMid",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16TargetCellMid", HFILL }},

		{ &hf_u8Num,
      		{ "u8Num", "rrc_rrc_ctrl_sap.u8Num",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8Num", HFILL }},

		{ &hf_u8ErabId,
      		{ "u8ErabId", "rrc_rrc_ctrl_sap.u8ErabId",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ErabId", HFILL }},

		{ &hf_u32TransAddr,
      		{ "u32TransAddr", "rrc_rrc_ctrl_sap.u32TransAddr",
        		FT_UINT32, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u32TransAddr", HFILL }},

		{ &hf_u8GtpTeid,
      		{ "u8GtpTeid", "rrc_rrc_ctrl_sap.u8GtpTeid",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8GtpTeid", HFILL }},

		{ &hf_emCauseGroupSelect,
      		{ "emCauseGroupSelect", "rrc_rrc_ctrl_sap.emCauseGroupSelect",
        		FT_UINT32, BASE_DEC, emCauseGroupSelect_vals, 0,
        			"rrc_rrc_ctrl_sap.emCauseGroupSelect", HFILL }},

		{ &hf_emCauseRadioNetworkLayer,
      		{ "emCauseRadioNetworkLayer", "rrc_rrc_ctrl_sap.emCauseRadioNetworkLayer",
        		FT_UINT32, BASE_DEC, emCauseRadioNetworkLayer_vals, 0,
        			"rrc_rrc_ctrl_sap.emCauseRadioNetworkLayer", HFILL }},

		{ &hf_emCauseTransportLayer,
      		{ "emCauseTransportLayer", "rrc_rrc_ctrl_sap.CauseTransportLayering",
        		FT_UINT32, BASE_DEC, emCauseTransportLayer_vals, 0,
        			"rrc_rrc_ctrl_sap.emCauseTransportLayer", HFILL }},

		{ &hf_emCauseProtocol,
      		{ "emCauseProtocol", "rrc_rrc_ctrl_sap.emCauseProtocol",
        		FT_UINT32, BASE_DEC, emCauseProtocol_vals, 0,
        			"rrc_rrc_ctrl_sap.emCauseProtocol", HFILL }},

		{ &hf_emCauseMiscellaneous,
      		{ "emCauseMiscellaneous", "rrc_rrc_ctrl_sap.emCauseMiscellaneous",
        		FT_UINT32, BASE_DEC, emCauseMiscellaneous_vals, 0,
        			"rrc_rrc_ctrl_sap.emCauseMiscellaneous", HFILL }},

		{ &hf_u16BufferLen,
      		{ "u16BufferLen", "rrc_rrc_ctrl_sap.u16BufferLen",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16BufferLen", HFILL }},

		{ &hf_rrcdata,
      		{ "rrcdata", "rrc_rrc_ctrl_sap.rrcdata",
        		FT_BYTES, BASE_HEX, NULL, 0,
        			"rrc_rrc_ctrl_sap.rrcdata", HFILL }},

		{ &hf_u8ProcedureCode,
      		{ "u8ProcedureCode", "rrc_rrc_ctrl_sap.u8ProcedureCode",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ProcedureCode", HFILL }},

		{ &hf_emTriggeringMessage,
      		{ "emTriggeringMessage", "rrc_rrc_ctrl_sap.emTriggeringMessage",
        		FT_UINT32, BASE_DEC, emMsgType_val, 0,
        			"rrc_rrc_ctrl_sap.emTriggeringMessage", HFILL }},

		{ &hf_emProcedureCriticality,
      		{ "emProcedureCriticality", "rrc_rrc_ctrl_sap.emProcedureCriticality",
        		FT_UINT32, BASE_DEC, emProcedureCriticality_val, 0,
        			"rrc_rrc_ctrl_sap.emProcedureCriticality", HFILL }},

		{ &hf_u8Elem,
      		{ "u8Elem", "rrc_rrc_ctrl_sap.u8Elem",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8Elem", HFILL }},

		{ &hf_u16IeId,
      		{ "u16IeId", "rrc_rrc_ctrl_sap.u16IeId",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16IeId", HFILL }},

		{ &hf_emTypeOfError,
      		{ "emTypeOfError", "rrc_rrc_ctrl_sap.emTypeOfError",
        		FT_UINT32, BASE_DEC, emTypeOfError_val, 0,
        			"rrc_rrc_ctrl_sap.emTypeOfError", HFILL }},

		/*{ &hf_u8ReceiveStatusofULPDCPSDUs,
      		{ "u8ReceiveStatusofULPDCPSDUs", "rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUs",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUs", HFILL }},*/

		{ &hf_u8ReceiveStatusofULPDCPSDUs,
      		{ "u8ReceiveStatusofULPDCPSDUs", "rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUs",
        		FT_BYTES, BASE_HEX, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUs", HFILL }},

		{ &hf_u16PdcpSN,
      		{ "u16PdcpSN", "rrc_rrc_ctrl_sap.u16PdcpSN",
        		FT_UINT16, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u16PdcpSN", HFILL }},

		{ &hf_u32Hfn,
      		{ "u32Hfn", "rrc_rrc_ctrl_sap.u32Hfn",
        		FT_UINT32, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u32Hfn", HFILL }},

		{ &hf_u8ErabnotAdmittedP,
      		{ "u8ErabnotAdmittedP", "rrc_rrc_ctrl_sap.u8ErabnotAdmittedP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ErabnotAdmittedP", HFILL }},

		{ &hf_u8CriticalDiagnosP,
      		{ "u8CriticalDiagnosP", "rrc_rrc_ctrl_sap.u8CriticalDiagnosP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8CriticalDiagnosP", HFILL }},

		{ &hf_u8ULGtpTunnelEndpointP,
      		{ "u8ULGtpTunnelEndpointP", "rrc_rrc_ctrl_sap.u8ULGtpTunnelEndpointP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ULGtpTunnelEndpointP", HFILL }},

		{ &hf_u8DLGtpTunnelEndpointP,
      		{ "u8DLGtpTunnelEndpointP", "rrc_rrc_ctrl_sap.u8DLGtpTunnelEndpointP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8DLGtpTunnelEndpointP", HFILL }},

		{ &hf_u8ProcedureCodeP,
      		{ "u8ProcedureCodeP", "rrc_rrc_ctrl_sap.u8ProcedureCodeP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ProcedureCodeP", HFILL }},

		{ &hf_u8TriggeringMessageP,
      		{ "u8TriggeringMessageP", "rrc_rrc_ctrl_sap.u8TriggeringMessageP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8TriggeringMessageP", HFILL }},

		{ &hf_u8ProcedureCriticalityP,
      		{ "u8ProcedureCriticalityP", "rrc_rrc_ctrl_sap.u8ProcedureCriticalityP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ProcedureCriticalityP", HFILL }},

		{ &hf_u8IeCriticalityDiagnosticsP,
      		{ "u8IeCriticalityDiagnosticsP", "rrc_rrc_ctrl_sap.u8IeCriticalityDiagnosticsP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8IeCriticalityDiagnosticsP", HFILL }},

		{ &hf_u8ReceiveStatusofULPDCPSDUsP,
      		{ "u8ReceiveStatusofULPDCPSDUsP", "rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUsP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8ReceiveStatusofULPDCPSDUsP", HFILL }},

		{ &hf_u8NewUeidP,
      		{ "u8NewUeidP", "rrc_rrc_ctrl_sap.u8NewUeidP",
        		FT_UINT8, BASE_DEC, NULL, 0,
        			"rrc_rrc_ctrl_sap.u8NewUeidP", HFILL }},
		
		
	};
    
    gint* ett[] = {
        &ett_rrc_rrc_ctrl_sap,
		&ett_X2AP_Criticality_DIAGONSTICS,
		&ett_rrc,
		&ett_X2AP_TRANSPARENT_CONTAINER,
		&ett_CauseGroup,
		&ett_X2AP_CAUSE_S,
		&ett_X2AP_E_RAB_ITEM,
		&ett_X2AP_E_RAB_LIST,
		&ett_Dl_X2AP_GTPTUNNEL_ENDPOINT,
		&ett_X2AP_GTP_TEID,
		&ett_Ul_X2AP_GTPTUNNEL_ENDPOINT,
		&ett_X2AP_E_RAB_ADMITTED_ITEM,
		&ett_X2AP_E_RABS_ADMITTED_LIST,
		&ett_X2AP_MESSAGE_TYPE,
		&ett_X2AP_E_RAB_STATUS_TRANSFER_ITEM,
		&ett_UL_X2AP_COUNT_VALUE,
		&ett_X2AP_E_RAB_STATUS_TRANSFER_LIST,
		&ett_DL_X2AP_COUNT_VALUE,
		&ett_X2AP_CRITICALTY_DIAGONSTICS_IE_LIST,
		&ett_X2AP_IE_CRITICALTY_DIAGONSTICS,
        
};
    
    proto_rrc_rrc_ctrl_sap = proto_register_protocol(rrc_rrc_ctrl_proto_name, rrc_rrc_ctrl_proto_name_short, "rrc_rrc_ctrl");
    
	register_dissector("rrc_rrc_ctrl_sap", dissect_rrc_rrc_ctrl_sap, proto_rrc_rrc_ctrl_sap);
	
    proto_register_field_array(proto_rrc_rrc_ctrl_sap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

	
	
}


void
proto_reg_handoff_rrc_rrc_ctrl_sap(void)
{
    rrc_rrc_ctrl_handle = find_dissector("rrc_rrc_ctrl_sap");
}





