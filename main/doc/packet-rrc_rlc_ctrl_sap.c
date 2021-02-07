
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <prefs.h>
#include "omc_msg_process.h"



static int proto_rrc_rlc_ctrl_sap = -1;
static int hf_mu8DrxFlag = -1;
static int hf_mu8K = -1;
static int hf_mu8PhrExstFlag = -1;
static int hf_mu8IsTtiBunding = -1;
static int hf_mu8CqiFormatInd = -1;
static int hf_mu8RbIdTrunkFlag = -1;
static int hf_mu8GapType = -1;
static int hf_mu8LchPriority = -1;
static int hf_mu32RlcMode = -1;
static int hf_mu16PdschSimResSwitchCyc = -1;
static int hf_mu8SrbList = -1;
static int hf_mu32UlGbrRateH = -1;
static int hf_mu16PeriodicBsrTimer = -1;
static int hf_mu16N1Pucch3 = -1;
static int hf_mu8IsTpcAccumlate = -1;
static int hf_mu8PmiRiReportFlag = -1;
static int hf_mu8TddAckFdBackMode = -1;
static int hf_mu8TransMode = -1;
static int hf_mu16RbToReleaseNum = -1;
static int hf_mu32PollPdu = -1;
static int hf_mu16N1Pucch0 = -1;
static int hf_mu32SnFieldLen = -1;
static int hf_mu8RbIdforReEstb = -1;
static int hf_mu8RiCfgIndexPresent = -1;
static int hf_mu8DrbRlsRbId = -1;
static int hf_p0NomnlPuschPsst = -1;
static int hf_mu8OnDuratonTimer = -1;
static int hf_mu32UlAMBRH = -1;
static int hf_mu16DataLen = -1;
static int hf_mu8UlQci = -1;
static int hf_prohibitPhrTimer = -1;
static int hf_mi16P0UePuschPsst = -1;
static int hf_mu8MaxInSyncTimes = -1;
static int hf_mu8ErabNum = -1;
static int hf_mu8PaddingSrb = -1;
static int hf_mu8DataBuf = -1;
static int hf_mu8SrsHoppingBandwidth = -1;
static int hf_mu8SpsProcNum = -1;
static int hf_mu16URbToModifyNum = -1;
static int hf_muPadding1 = -1;
static int hf_mu16CqiPmiCfgIdx = -1;
static int hf_mu8DsrTranMax = -1;
static int hf_mu32UlHfn = -1;
static int hf_mu8StatusReportRequired = -1;
static int hf_mu16N1PucchAnRep = -1;
static int hf_UeIdList = -1;
static int hf_mu8SrCfgIndex = -1;
static int hf_mu8SimLoadSwitch = -1;
static int hf_mu8Duration = -1;
static int hf_mu8CKup = -1;
static int hf_mu16ConfigFlag = -1;
static int hf_mu8IsDefaultCfg = -1;
static int hf_mu8ProfilePresent = -1;
static int hf_mu8SrsBandwidth = -1;
static int hf_mu8PaddingPucch = -1;
static int hf_mu32DlAMBRL = -1;
static int hf_mu32IntegrityProtAlgorithm = -1;
static int hf_mu8ShDrxExstFlag = -1;
static int hf_mu32TeidUlForward = -1;
static int hf_mu8IK = -1;
static int hf_mu16LDrxCyclStartOffsetVal = -1;
static int hf_mu8ErabId = -1;
static int hf_mu8ProfileInstance = -1;
static int hf_mu8p0PersisExstFlag = -1;
static int hf_mu8ExistFlag = -1;
static int hf_mu16TpcPuschRnti = -1;
static int hf_mu8CqiMaskFlag = -1;
static int hf_mu8DlQci = -1;
static int hf_mu8CqiRptModeAperiod = -1;
static int hf_mu32UlGbrRateL = -1;
static int hf_mu8CqiMask = -1;
static int hf_mu16RbListNum = -1;
static int hf_mu8PaddingDrbRls = -1;
static int hf_mu8HcRequired = -1;
static int hf_mu16RetxBsrTimer = -1;
static int hf_mu8DlPathlossChange = -1;
static int hf_mu8SrProhibitTimer = -1;
static int hf_mu8Qci = -1;
static int hf_mu8SpsCRNTIExstFlag = -1;
static int hf_mu8DrxRetransTimer = -1;
static int hf_mu16DlPdcpSn = -1;
static int hf_mu16SimRNTI = -1;
static int hf_mu8LchGroupExstFlag = -1;
static int hf_mu8TddAckFdbckModeExstFlag = -1;
static int hf_mu8DefaultConfigPresent = -1;
static int hf_mu8ShDrxCyclTimer = -1;
static int hf_mu8CellIndex = -1;
static int hf_mi16P0NomnlPuschPsst = -1;
static int hf_mu32TeidDlForward = -1;
static int hf_mu8DlSpsIntval = -1;
static int hf_mu16RbToReestabNum = -1;
static int hf_mu8UlSpsIntval = -1;
static int hf_mu8Result = -1;
static int hf_mu8ImplicitReleaseAfter = -1;
static int hf_mu16UlPBR = -1;
static int hf_mu8SrFlag = -1;
static int hf_mu8SimLoadType = -1;
static int hf_mu16MaxCID = -1;
static int hf_mu32CodeBokSubsetExstFlag = -1;
static int hf_mu8DrxExstFlag = -1;
static int hf_mu8padding = -1;
static int hf_mu16RbToAddNum = -1;
static int hf_phrCfgExstFlag = -1;
static int hf_mu16BitRatePerPriority = -1;
static int hf_mu8UeVersion = -1;
static int hf_mu8PeriodicBSRTimerFlag = -1;
static int hf_mu16UeId = -1;
static int hf_mu8RbIdforRelease = -1;
static int hf_mu16N1PucchAnPersistentList = -1;
static int hf_mu16SimUeIdx = -1;
static int hf_mu32LchGroupExstFlag = -1;
static int hf_mu8TrunkPriority = -1;
static int hf_mu8Cri = -1;
static int hf_mu8PmiRIReport = -1;
static int hf_mu32DrbReleaseListNum = -1;
static int hf_mu16SrsCfgIndex = -1;
static int hf_mu8LchGroup = -1;
static int hf_mu8LchId = -1;
static int hf_mu16DrbAddModifyListNum = -1;
static int hf_mu8IntegrityRequired = -1;
static int hf_mu8TransmissionComb = -1;
static int hf_mu8Flag = -1;
static int hf_mu16TmpUeIndex = -1;
static int hf_mu32DlGbrRateH = -1;
static int hf_mu32RlcDirection = -1;
static int hf_mu32IpFamily = -1;
static int hf_mu32DlGbrRateL = -1;
static int hf_mu16NumberOfn1Pucch = -1;
static int hf_mu8DeltaMcsEnable = -1;
static int hf_mu8SrbId = -1;
static int hf_mu8SpsExstFlag = -1;
static int hf_mu16CRnti = -1;
static int hf_mu32UeNum = -1;
static int hf_Padding = -1;
static int hf_mu16CodeBookSubset = -1;
static int hf_mu8IdleTransNumBFImplctRelease = -1;
static int hf_mu16PdcchSimResSwitchCyc = -1;
static int hf_p0UePuschPsst = -1;
static int hf_mu16BucketSizeDuration = -1;
static int hf_mu32DrbNum = -1;
static int hf_mu32CipheringAlgorithm = -1;
static int hf_mu16DlSpsIntval = -1;
static int hf_mu16ShDrxCycl = -1;
static int hf_mu8PdcchSimLoadProp = -1;
static int hf_mu16LDrxCyclStartOffsetType = -1;
static int hf_mi8P0UePuschPersistent = -1;
static int hf_mu8SrConfigIndex = -1;
static int hf_mu8MacCfgExstFlag = -1;
static int hf_mu8FreqDomainPosition = -1;
static int hf_mu16UlBSD = -1;
static int hf_ms16PucchSinrTarget = -1;
static int hf_mu8PdschSimLoadProp = -1;
static int hf_mu8DrbId = -1;
static int hf_mu8SecurityCtxFlag = -1;
static int hf_mu32TeidSelf = -1;
static int hf_mu8Paddingsps = -1;
static int hf_mu32UlMaxRateL = -1;
static int hf_mu8RcpData = -1;
static int hf_mu32UlMaxRateH = -1;
static int hf_mu16ErabId = -1;
static int hf_mu8DeltaMcsEnabled = -1;
static int hf_mu8AccumulationEnabled = -1;
static int hf_mu16N1Pucch2 = -1;
static int hf_mu16N1Pucch1 = -1;
static int hf_mu16DrxInactvTimer = -1;
static int hf_mu8NeedCnf = -1;
static int hf_mu8DrbReleaseList = -1;
static int hf_mu8SrProhibitTimerFlag = -1;
static int hf_mu8TpcPucchRntiIdx = -1;
static int hf_mu8Padding1 = -1;
static int hf_mu8LchIdExistFlag = -1;
static int hf_mu32UlAMBRL = -1;
static int hf_mu16ulSubframeOffsetOfn1Pucch = -1;
static int hf_mu8GbrType = -1;
static int hf_mu8CipheringRequired = -1;
static int hf_mu8CqiRptFlag = -1;
static int hf_mu32IpAddr = -1;
static int hf_mu32TaTimerVal = -1;
static int hf_mu8GapOffset = -1;
static int hf_mu8MaxHARQTxFlag = -1;
static int hf_mu8SimLoadFlag = -1;
static int hf_mu16SrbListNum = -1;
static int hf_mu32DiscardTimerLen = -1;
static int hf_mu32AgwTeid = -1;
static int hf_mu16UeNum = -1;
static int hf_mu8TpcPuschRntiIdx = -1;
static int hf_mu8RbId = -1;
static int hf_mu8DlSpsExstFlag = -1;
static int hf_mu8RbList = -1;
static int hf_mu8DedicatedRaPid = -1;
static int hf_mu8UeCategory = -1;
static int hf_mu32TReordering = -1;
static int hf_mu32UmPdcpSnSize = -1;
static int hf_mu8UlSpsExstFlag = -1;
static int hf_mu8IntCheckResult = -1;
static int hf_mu8SimAckNack = -1;
static int hf_mu16UlSpsIntval = -1;
static int hf_mu32MaxRetxThreshold = -1;
static int hf_mu8TwoIntervalCfg = -1;
static int hf_mu8TpcCfgExstFlag = -1;
static int hf_mu8CycShift = -1;
static int hf_mu16Result = -1;
static int hf_mu32DlHfn = -1;
static int hf_mu8NomPdschRsEpreOffset = -1;
static int hf_mu8IsPucch3A = -1;
static int hf_mu16Fms = -1;
static int hf_mu16SpsProcNum = -1;
static int hf_mu8Padding = -1;
static int hf_mu8Mode = -1;
static int hf_dlPassLossChange = -1;
static int hf_mu16RiCfgIdx = -1;
static int hf_padding = -1;
static int hf_mu8P0PersistentConfigFlag = -1;
static int hf_mu8Bitmap = -1;
static int hf_mu8MaxOutSyncTimes = -1;
static int hf_mi8P0UePusch = -1;
static int hf_mu8Factor = -1;
static int hf_mu16UeIndex = -1;
static int hf_mu16Flag = -1;
static int hf_mu8CfgExist = -1;
static int hf_mu8CKcp = -1;
static int hf_mu8DiscardTimerRequired = -1;
static int hf_mu32PollByte = -1;
static int hf_periodicPhrTimer = -1;
static int hf_mu8IsPusch3A = -1;
static int hf_mu8RepetitionInd = -1;
static int hf_mu16SpsCrnti = -1;
static int hf_mu8PSRSOffset = -1;
static int hf_mu32DlMaxRateH = -1;
static int hf_mu8Padding4 = -1;
static int hf_mu32DlMaxRateL = -1;
static int hf_mu16DrbListNum = -1;
static int hf_mu16T310TimerPeriod = -1;
static int hf_mu8FilterCoefficient = -1;
static int hf_mu8MaxHarqTxNum = -1;
static int hf_mu8Location = -1;
static int hf_mu16SrPucchResourceIndex = -1;
static int hf_mu8ServiceType = -1;
static int hf_mu16TpcPucchRnti = -1;
static int hf_mu32TPollRetransmit = -1;
static int hf_mu32TStatusProhibit = -1;
static int hf_mi8P0UePucch = -1;
static int hf_mu32DlAMBRH = -1;
static int hf_mu8DrbReleaseNum = -1;
static int hf_ms16PuschSinrTarget = -1;
static int hf_mu8UeTxAntSelect = -1;
static int hf_padding1 = -1;
static int hf_mi16P0NominalPuschPersistent = -1;
static int hf_result = -1;
static int hf_u16CellUeIndex= -1;
static int hf_u32TStatusProhibit = -1;
static int hf_u32TPollRetransmit=-1;
static int hf_u32PollPdu  =-1;
static int hf_u32PollByte = -1;
static int hf_u32MaxRetxThreshold = -1;
static int hf_u8RbIdforReEstb = -1;




static gint ett_rrc_rlc_ctrl_sap = -1;
static gint ett_RcpMacMacMainCfgType = -1;
static gint ett_RcpGtpuErabReCfgInfoType = -1;
static gint ett_RcpGtpuErabReCfgInfoTypeList = -1;
static gint ett_RcpMacPucchCfgType = -1;
static gint ett_RcpMacSrbToAddlstType = -1;
static gint ett_RcpMacSrbToAddlstTypeList = -1;
static gint ett_RcpMacCqiFormatIndPeriodicType = -1;
static gint ett_RcpMacP0PersistentType = -1;
static gint ett_IPADDR = -1;
static gint ett_RcpMacAcknackRepetitionType = -1;
static gint ett_RcpMacUlspsCfgType = -1;
static gint ett_RcpUpMacMeasCfgType = -1;
static gint ett_RcpMacDrxCfgType = -1;
static gint ett_RcpMacLdrxCyclStartOffsetType = -1;
static gint ett_RcpMacSpsCfgType = -1;
static gint ett_RcpMacP0CfgType = -1;
static gint ett_RcpMacLchCfgType = -1;
static gint ett_RcpMacSchedulingRequestCfgType = -1;
static gint ett_RcpMacIfCqiRptPeriodicType = -1;
static gint ett_RcpMacUlsrsCfgType = -1;
static gint ett_RcpPdcpHeaderCompressionConfigInfoType = -1;
static gint ett_RcpPdcpDrbCfgListType = -1;
static gint ett_RcpPdcpDrbCfgListTypeList = -1;
static gint ett_RcpPdcpDiscardTimerConfigInfoType = -1;
static gint ett_RcpMacShortDrxType = -1;
static gint ett_RcpMacTpcCfgType = -1;
static gint ett_RcpMacDrbToRlsType = -1;
static gint ett_RohcProfiles = -1;
static gint ett_RohcProfilesList = -1;
static gint ett_RcpRlcRbAddOrModifyListType = -1;
static gint ett_RcpRlcRbAddOrModifyListTypeList = -1;
static gint ett_RcpMacCqiRptPeriodType = -1;
static gint ett_RcpGtpuErabCfgInfoType = -1;
static gint ett_RcpGtpuErabCfgInfoTypeList = -1;
static gint ett_RcpMacAntennaInfoType = -1;
static gint ett_RcpMacPhrConfigurationType = -1;
static gint ett_RcpPdcpIntegrityConfigInfoType = -1;
static gint ett_RcpRlcAmCfgType = -1;
static gint ett_RcpPdcpCipheringConfigInfoType = -1;
static gint ett_RcpPdcpRbSnStatusListType = -1;
static gint ett_RcpPdcpRbSnStatusListTypeList = -1;
static gint ett_RcpMacDlspsCfgType = -1;
static gint ett_RcpRlcUmRxCfgType = -1;
static gint ett_u_2 = -1;
static gint ett_u_1 = -1;
static gint ett_RcpMacDrbToAddlstType = -1;
static gint ett_RcpMacDrbToAddlstTypeList = -1;
static gint ett_RcpRlcUmBiCfgType = -1;
static gint ett_RcpRlcUmTxCfgType = -1;

proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacMacMainCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpGtpuErabReCfgInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacPucchCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSrbToAddlstType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacCqiFormatIndPeriodicType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacP0PersistentType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_IPADDR(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacAcknackRepetitionType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacUlspsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpUpMacMeasCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacLdrxCyclStartOffsetType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSpsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacP0CfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacLchCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSchedulingRequestCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacIfCqiRptPeriodicType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacUlsrsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpHeaderCompressionConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpDrbCfgListType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpDiscardTimerConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacShortDrxType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacTpcCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrbToRlsType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RohcProfiles(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcRbAddOrModifyListType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacCqiRptPeriodType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpGtpuErabCfgInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacAntennaInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacPhrConfigurationType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpIntegrityConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcAmCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpCipheringConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpRbSnStatusListType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDlspsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmRxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_u_2(proto_tree *tree, tvbuff_t *tvb, int *offset,guint32 rlcMode,guint32 rlcDir);
proto_item *rrc_rlc_ctrl_proto_tree_add_u_1(proto_tree *tree, tvbuff_t *tvb, int *offset,guint32 rlcMode);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrbToAddlstType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmBiCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);
proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmTxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset);


static const char *rrc_rlc_ctrl_proto_name = "RRC RLC CTRL SAP";
static const char *rrc_rlc_ctrl_proto_name_short = "rrc rlc ctrl";

dissector_handle_t rrc_rlc_ctrl_handle=NULL;


const value_string rrc_rlc_ctrl_msg_strings[] = {    
{60, "RCP UP RLC HANDOVER CONFIG REQ"},
{61, "UP RCP RLC HANDOVER CONFIG CNF"},
{62, "RCP UP RLC RRC CONNECTION CONFIG REQ"},
{63, "UP RCP RLC RRC CONNECTION CONFIG CNF"},
{64, "RCP UP RLC REESTABLISHMENT REQ"},
{65, "UP RCP RLC REESTABLISHMENT CNF"},
{66, "RCP UP RLC RRC CONNECTION RECONFIG REQ"},
{67, "UP RCP RLC RRC CONNECTION RECONFIG CNF"},
{68, "RCP UP RLC RELEASE REQ"},
{69, "UP RCP RLC RELEASE CNF"},
{70, "UP RCP RLC MAX RETRANS IND"},

{0, NULL }
};



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacMacMainCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacMacMainCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacMacMainCfgType");
    RcpMacMacMainCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacMacMainCfgType);


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu8MaxHARQTxFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu8PeriodicBSRTimerFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu8MaxHarqTxNum, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu8IsTtiBunding, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu16PeriodicBsrTimer, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacMacMainCfgType_tree, hf_mu16RetxBsrTimer, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpGtpuErabReCfgInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpGtpuErabReCfgInfoType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpGtpuErabReCfgInfoType");
    RcpGtpuErabReCfgInfoType_tree = proto_item_add_subtree(pi,ett_RcpGtpuErabReCfgInfoType);


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu16ErabId, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu8Flag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu32TeidSelf, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabReCfgInfoType_tree, tvb, offset);


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu32AgwTeid, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabReCfgInfoType_tree, tvb, offset);


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu32TeidUlForward, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpGtpuErabReCfgInfoType_tree, hf_mu32TeidDlForward, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabReCfgInfoType_tree, tvb, offset);


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabReCfgInfoType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacPucchCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacPucchCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacPucchCfgType");
    RcpMacPucchCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacPucchCfgType);


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu8TddAckFdbckModeExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu8TddAckFdBackMode, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu8SrCfgIndex, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu8PaddingPucch, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    rrc_rlc_ctrl_proto_tree_add_RcpMacAcknackRepetitionType(RcpMacPucchCfgType_tree, tvb, offset);


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu16N1Pucch0, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu16N1Pucch1, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu16N1Pucch2, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacPucchCfgType_tree, hf_mu16N1Pucch3, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSrbToAddlstType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacSrbToAddlstType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacSrbToAddlstType");
    RcpMacSrbToAddlstType_tree = proto_item_add_subtree(pi,ett_RcpMacSrbToAddlstType);


    proto_tree_add_item(RcpMacSrbToAddlstType_tree, hf_mu8IsDefaultCfg, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSrbToAddlstType_tree, hf_mu8LchId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSrbToAddlstType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSrbToAddlstType_tree, hf_mu8PaddingSrb, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    rrc_rlc_ctrl_proto_tree_add_RcpMacLchCfgType(RcpMacSrbToAddlstType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacCqiFormatIndPeriodicType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacCqiFormatIndPeriodicType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacCqiFormatIndPeriodicType");
    RcpMacCqiFormatIndPeriodicType_tree = proto_item_add_subtree(pi,ett_RcpMacCqiFormatIndPeriodicType);


    proto_tree_add_item(RcpMacCqiFormatIndPeriodicType_tree, hf_mu8CqiFormatInd, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiFormatIndPeriodicType_tree, hf_mu8K, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacCqiFormatIndPeriodicType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacP0PersistentType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacP0PersistentType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacP0PersistentType");
    RcpMacP0PersistentType_tree = proto_item_add_subtree(pi,ett_RcpMacP0PersistentType);


    proto_tree_add_item(RcpMacP0PersistentType_tree, hf_mu8P0PersistentConfigFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0PersistentType_tree, hf_mi8P0UePuschPersistent, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0PersistentType_tree, hf_mi16P0NominalPuschPersistent, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_IPADDR(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*IPADDR_tree = NULL;
    const guint8 *dataPtr;

    pi = proto_tree_add_text(tree,tvb,0,0,"IPADDR");
    IPADDR_tree = proto_item_add_subtree(pi,ett_IPADDR);


    proto_tree_add_item(IPADDR_tree, hf_mu32IpFamily, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    dataPtr = tvb_get_ptr(tvb, *offset, 16);
    proto_tree_add_bytes(IPADDR_tree, hf_mu32IpAddr, tvb, *offset, 16, dataPtr);
    (*offset)+=16;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacAcknackRepetitionType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacAcknackRepetitionType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacAcknackRepetitionType");
    RcpMacAcknackRepetitionType_tree = proto_item_add_subtree(pi,ett_RcpMacAcknackRepetitionType);


    proto_tree_add_item(RcpMacAcknackRepetitionType_tree, hf_mu8RepetitionInd, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacAcknackRepetitionType_tree, hf_mu8Factor, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacAcknackRepetitionType_tree, hf_mu16N1PucchAnRep, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacUlspsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacUlspsCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacUlspsCfgType");
    RcpMacUlspsCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacUlspsCfgType);


    proto_tree_add_item(RcpMacUlspsCfgType_tree, hf_mu16ConfigFlag, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacUlspsCfgType_tree, hf_mu16UlSpsIntval, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacUlspsCfgType_tree, hf_mu8IdleTransNumBFImplctRelease, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlspsCfgType_tree, hf_mu8TwoIntervalCfg, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacUlspsCfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    rrc_rlc_ctrl_proto_tree_add_RcpMacP0PersistentType(RcpMacUlspsCfgType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpUpMacMeasCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpUpMacMeasCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpUpMacMeasCfgType");
    RcpUpMacMeasCfgType_tree = proto_item_add_subtree(pi,ett_RcpUpMacMeasCfgType);


    proto_tree_add_item(RcpUpMacMeasCfgType_tree, hf_mu8ExistFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpUpMacMeasCfgType_tree, hf_mu8GapType, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpUpMacMeasCfgType_tree, hf_mu8GapOffset, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpUpMacMeasCfgType_tree, hf_padding, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacDrxCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacDrxCfgType");
    RcpMacDrxCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacDrxCfgType);


    proto_tree_add_item(RcpMacDrxCfgType_tree, hf_mu8DrxFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrxCfgType_tree, hf_mu8OnDuratonTimer, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrxCfgType_tree, hf_mu16DrxInactvTimer, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpMacDrxCfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    proto_tree_add_item(RcpMacDrxCfgType_tree, hf_mu8DrxRetransTimer, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    rrc_rlc_ctrl_proto_tree_add_RcpMacLdrxCyclStartOffsetType(RcpMacDrxCfgType_tree, tvb, offset);


    rrc_rlc_ctrl_proto_tree_add_RcpMacShortDrxType(RcpMacDrxCfgType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacLdrxCyclStartOffsetType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacLdrxCyclStartOffsetType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacLdrxCyclStartOffsetType");
    RcpMacLdrxCyclStartOffsetType_tree = proto_item_add_subtree(pi,ett_RcpMacLdrxCyclStartOffsetType);


    proto_tree_add_item(RcpMacLdrxCyclStartOffsetType_tree, hf_mu16LDrxCyclStartOffsetType, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacLdrxCyclStartOffsetType_tree, hf_mu16LDrxCyclStartOffsetVal, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSpsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacSpsCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacSpsCfgType");
    RcpMacSpsCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacSpsCfgType);


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8LchId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8SpsCRNTIExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8DlSpsExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8UlSpsExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8p0PersisExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu16SpsCrnti, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacSpsCfgType_tree, hf_mu8ImplicitReleaseAfter, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpMacSpsCfgType_tree, hf_Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    rrc_rlc_ctrl_proto_tree_add_RcpMacDlspsCfgType(RcpMacSpsCfgType_tree, tvb, offset);


    rrc_rlc_ctrl_proto_tree_add_RcpMacUlspsCfgType(RcpMacSpsCfgType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacP0CfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacP0CfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacP0CfgType");
    RcpMacP0CfgType_tree = proto_item_add_subtree(pi,ett_RcpMacP0CfgType);


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mi8P0UePusch, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mu8DeltaMcsEnabled, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mu8AccumulationEnabled, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mi8P0UePucch, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mu8PSRSOffset, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacP0CfgType_tree, hf_mu8FilterCoefficient, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacP0CfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacLchCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacLchCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacLchCfgType");
    RcpMacLchCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacLchCfgType);


    proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu32LchGroupExstFlag, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu8LchGroup, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu8LchPriority, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu16BitRatePerPriority, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu16BucketSizeDuration, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacLchCfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacSchedulingRequestCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacSchedulingRequestCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacSchedulingRequestCfgType");
    RcpMacSchedulingRequestCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacSchedulingRequestCfgType);


    proto_tree_add_item(RcpMacSchedulingRequestCfgType_tree, hf_mu8SrFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpMacSchedulingRequestCfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    proto_tree_add_item(RcpMacSchedulingRequestCfgType_tree, hf_mu16SrPucchResourceIndex, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacSchedulingRequestCfgType_tree, hf_mu8SrConfigIndex, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacSchedulingRequestCfgType_tree, hf_mu8DsrTranMax, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacIfCqiRptPeriodicType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacIfCqiRptPeriodicType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacIfCqiRptPeriodicType");
    RcpMacIfCqiRptPeriodicType_tree = proto_item_add_subtree(pi,ett_RcpMacIfCqiRptPeriodicType);


    proto_tree_add_item(RcpMacIfCqiRptPeriodicType_tree, hf_mu16CqiPmiCfgIdx, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacIfCqiRptPeriodicType_tree, hf_mu16RiCfgIdx, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacIfCqiRptPeriodicType_tree, hf_mu8SimAckNack, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacIfCqiRptPeriodicType_tree, hf_mu8RiCfgIndexPresent, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacIfCqiRptPeriodicType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    rrc_rlc_ctrl_proto_tree_add_RcpMacCqiFormatIndPeriodicType(RcpMacIfCqiRptPeriodicType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacUlsrsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacUlsrsCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacUlsrsCfgType");
    RcpMacUlsrsCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacUlsrsCfgType);


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8CfgExist, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8SrsBandwidth, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8FreqDomainPosition, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8SrsHoppingBandwidth, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8Duration, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8TransmissionComb, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu16SrsCfgIndex, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8CycShift, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpMacUlsrsCfgType_tree, hf_mu8padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpHeaderCompressionConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpHeaderCompressionConfigInfoType_tree = NULL;
    int i;
    proto_tree* mstProfilesList_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpHeaderCompressionConfigInfoType");
    RcpPdcpHeaderCompressionConfigInfoType_tree = proto_item_add_subtree(pi,ett_RcpPdcpHeaderCompressionConfigInfoType);


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpPdcpHeaderCompressionConfigInfoType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    proto_tree_add_item(RcpPdcpHeaderCompressionConfigInfoType_tree, hf_mu16MaxCID, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    pi = proto_tree_add_text(RcpPdcpHeaderCompressionConfigInfoType_tree, tvb, 0, 0, "RohcProfiles List");
    mstProfilesList_tree = proto_item_add_subtree(pi, ett_RohcProfilesList);

    for(i=0; i<10; i++)
    {
        rrc_rlc_ctrl_proto_tree_add_RohcProfiles(mstProfilesList_tree, tvb, offset);
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpDrbCfgListType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpDrbCfgListType_tree = NULL;
    guint32 rlcMode = 0;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpDrbCfgListType");
    RcpPdcpDrbCfgListType_tree = proto_item_add_subtree(pi,ett_RcpPdcpDrbCfgListType);


    proto_tree_add_item(RcpPdcpDrbCfgListType_tree, hf_mu8DiscardTimerRequired, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpPdcpDrbCfgListType_tree, hf_mu8HcRequired, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpPdcpDrbCfgListType_tree, hf_mu8DrbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpPdcpDrbCfgListType_tree, hf_mu8Qci, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;

    rlcMode = tvb_get_ntohl(tvb,*offset);
    proto_tree_add_item(RcpPdcpDrbCfgListType_tree, hf_mu32RlcMode, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_u_1(RcpPdcpDrbCfgListType_tree, tvb, offset,rlcMode);


    rrc_rlc_ctrl_proto_tree_add_RcpPdcpDiscardTimerConfigInfoType(RcpPdcpDrbCfgListType_tree, tvb, offset);


    rrc_rlc_ctrl_proto_tree_add_RcpPdcpHeaderCompressionConfigInfoType(RcpPdcpDrbCfgListType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpDiscardTimerConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpDiscardTimerConfigInfoType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpDiscardTimerConfigInfoType");
    RcpPdcpDiscardTimerConfigInfoType_tree = proto_item_add_subtree(pi,ett_RcpPdcpDiscardTimerConfigInfoType);


    proto_tree_add_item(RcpPdcpDiscardTimerConfigInfoType_tree, hf_mu32DiscardTimerLen, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacShortDrxType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacShortDrxType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacShortDrxType");
    RcpMacShortDrxType_tree = proto_item_add_subtree(pi,ett_RcpMacShortDrxType);


    proto_tree_add_item(RcpMacShortDrxType_tree, hf_mu8ShDrxExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacShortDrxType_tree, hf_mu8ShDrxCyclTimer, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacShortDrxType_tree, hf_mu16ShDrxCycl, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacTpcCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacTpcCfgType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacTpcCfgType");
    RcpMacTpcCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacTpcCfgType);


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu16TpcPucchRnti, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu16TpcPuschRnti, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8IsTpcAccumlate, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8DeltaMcsEnable, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8TpcPucchRntiIdx, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8IsPucch3A, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8TpcPuschRntiIdx, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8IsPusch3A, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_ms16PucchSinrTarget, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacTpcCfgType_tree, hf_ms16PuschSinrTarget, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacTpcCfgType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrbToRlsType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacDrbToRlsType_tree = NULL;
    const guint8 *dataPtr;
    int i;
    guint8 drbNum = 0;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacDrbToRlsType");
    RcpMacDrbToRlsType_tree = proto_item_add_subtree(pi,ett_RcpMacDrbToRlsType);


    drbNum = tvb_get_guint8(tvb,*offset);
    proto_tree_add_item(RcpMacDrbToRlsType_tree, hf_mu8DrbReleaseNum, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    if(drbNum>0 && drbNum<8)
    {
        dataPtr = tvb_get_ptr(tvb, *offset, drbNum);
        proto_tree_add_bytes(RcpMacDrbToRlsType_tree, hf_mu8DrbRlsRbId, tvb, *offset, drbNum, dataPtr);
        (*offset)+=drbNum;
    }


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpMacDrbToRlsType_tree, hf_mu8PaddingDrbRls, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RohcProfiles(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RohcProfiles_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RohcProfiles");
    RohcProfiles_tree = proto_item_add_subtree(pi,ett_RohcProfiles);


    proto_tree_add_item(RohcProfiles_tree, hf_mu8ProfilePresent, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RohcProfiles_tree, hf_mu8ProfileInstance, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RohcProfiles_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcRbAddOrModifyListType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{// 36 bytes
    proto_item* pi = NULL;
    proto_tree	*RcpRlcRbAddOrModifyListType_tree = NULL;
//    int i;
    guint32 rlcDir = 0;
    guint32 rlcMode = 0;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpRlcRbAddOrModifyListType");
    RcpRlcRbAddOrModifyListType_tree = proto_item_add_subtree(pi,ett_RcpRlcRbAddOrModifyListType);


    proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu8RbId, tvb, *offset, 1, 1);
    (*offset)+=1;


    proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu8DefaultConfigPresent, tvb, *offset, 1, 1);
    (*offset)+=1;

#if 0
    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }
#endif
 	proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu8Qci, tvb, *offset, 1, 1);
	(*offset)+=1;
	proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu8Padding, tvb, *offset, 1, 1);
	(*offset)+=1;

	
    rlcMode = tvb_get_ntohl(tvb,*offset);
    proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu32RlcMode, tvb, *offset, 4, 1);
    (*offset)+=4;

    rlcDir = tvb_get_ntohl(tvb,*offset);
    proto_tree_add_item(RcpRlcRbAddOrModifyListType_tree, hf_mu32RlcDirection, tvb, *offset, 4, 1);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_u_2(RcpRlcRbAddOrModifyListType_tree, tvb, offset,rlcMode,rlcDir);// 24 bytes


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacCqiRptPeriodType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacCqiRptPeriodType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacCqiRptPeriodType");
    RcpMacCqiRptPeriodType_tree = proto_item_add_subtree(pi,ett_RcpMacCqiRptPeriodType);


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8CqiRptModeAperiod, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8NomPdschRsEpreOffset, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8CqiRptFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    rrc_rlc_ctrl_proto_tree_add_RcpMacIfCqiRptPeriodicType(RcpMacCqiRptPeriodType_tree, tvb, offset);


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8CqiMaskFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8CqiMask, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8PmiRiReportFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacCqiRptPeriodType_tree, hf_mu8PmiRIReport, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpGtpuErabCfgInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpGtpuErabCfgInfoType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpGtpuErabCfgInfoType");
    RcpGtpuErabCfgInfoType_tree = proto_item_add_subtree(pi,ett_RcpGtpuErabCfgInfoType);


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu16ErabId, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu8Flag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu32TeidSelf, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabCfgInfoType_tree, tvb, offset);


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu32AgwTeid, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabCfgInfoType_tree, tvb, offset);


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu32TeidUlForward, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpGtpuErabCfgInfoType_tree, hf_mu32TeidDlForward, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabCfgInfoType_tree, tvb, offset);


    rrc_rlc_ctrl_proto_tree_add_IPADDR(RcpGtpuErabCfgInfoType_tree, tvb, offset);


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacAntennaInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacAntennaInfoType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacAntennaInfoType");
    RcpMacAntennaInfoType_tree = proto_item_add_subtree(pi,ett_RcpMacAntennaInfoType);


    proto_tree_add_item(RcpMacAntennaInfoType_tree, hf_mu32CodeBokSubsetExstFlag, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacAntennaInfoType_tree, hf_mu8TransMode, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacAntennaInfoType_tree, hf_mu8UeTxAntSelect, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacAntennaInfoType_tree, hf_mu16CodeBookSubset, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacPhrConfigurationType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacPhrConfigurationType_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacPhrConfigurationType");
    RcpMacPhrConfigurationType_tree = proto_item_add_subtree(pi,ett_RcpMacPhrConfigurationType);


    proto_tree_add_item(RcpMacPhrConfigurationType_tree, hf_mu8PhrExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacPhrConfigurationType_tree, hf_mu8DlPathlossChange, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(RcpMacPhrConfigurationType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpIntegrityConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpIntegrityConfigInfoType_tree = NULL;
    const guint8 *dataPtr;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpIntegrityConfigInfoType");
    RcpPdcpIntegrityConfigInfoType_tree = proto_item_add_subtree(pi,ett_RcpPdcpIntegrityConfigInfoType);


    proto_tree_add_item(RcpPdcpIntegrityConfigInfoType_tree, hf_mu32IntegrityProtAlgorithm, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    dataPtr = tvb_get_ptr(tvb, *offset, 16);
    proto_tree_add_bytes(RcpPdcpIntegrityConfigInfoType_tree, hf_mu8IK, tvb, *offset, 16, dataPtr);
    (*offset)+=16;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcAmCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{// 24 bytes
    proto_item* pi = NULL;
    proto_tree	*RcpRlcAmCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpRlcAmCfgType");
    RcpRlcAmCfgType_tree = proto_item_add_subtree(pi,ett_RcpRlcAmCfgType);


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32TReordering, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32TStatusProhibit, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32TPollRetransmit, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32PollPdu, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32PollByte, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcAmCfgType_tree, hf_mu32MaxRetxThreshold, tvb, *offset, 4, 1);
    (*offset)+=4;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpCipheringConfigInfoType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpCipheringConfigInfoType_tree = NULL;
    const guint8 *dataPtr;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpCipheringConfigInfoType");
    RcpPdcpCipheringConfigInfoType_tree = proto_item_add_subtree(pi,ett_RcpPdcpCipheringConfigInfoType);


    proto_tree_add_item(RcpPdcpCipheringConfigInfoType_tree, hf_mu32CipheringAlgorithm, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    dataPtr = tvb_get_ptr(tvb, *offset, 16);
    proto_tree_add_bytes(RcpPdcpCipheringConfigInfoType_tree, hf_mu8CKcp, tvb, *offset, 16, dataPtr);
    (*offset)+=16;


    dataPtr = tvb_get_ptr(tvb, *offset, 16);
    proto_tree_add_bytes(RcpPdcpCipheringConfigInfoType_tree, hf_mu8CKup, tvb, *offset, 16, dataPtr);
    (*offset)+=16;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpPdcpRbSnStatusListType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpPdcpRbSnStatusListType_tree = NULL;
    int i;
    const guint8 *dataPtr;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpPdcpRbSnStatusListType");
    RcpPdcpRbSnStatusListType_tree = proto_item_add_subtree(pi,ett_RcpPdcpRbSnStatusListType);


    proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    for(i=0;i<3;i++)
    {
        proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
        (*offset)+=1;
    }


    dataPtr = tvb_get_ptr(tvb, *offset, 512);
    proto_tree_add_bytes(RcpPdcpRbSnStatusListType_tree, hf_mu8Bitmap, tvb, *offset, 512, dataPtr);
    (*offset)+=512;


    proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu16Fms, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu16DlPdcpSn, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu32UlHfn, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpPdcpRbSnStatusListType_tree, hf_mu32DlHfn, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDlspsCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacDlspsCfgType_tree = NULL;
    const guint8 *dataPtr;
    guint16 spsProcNum =0;
    guint16 numberOfn1Pucch = 0;
    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacDlspsCfgType");
    RcpMacDlspsCfgType_tree = proto_item_add_subtree(pi,ett_RcpMacDlspsCfgType);


    proto_tree_add_item(RcpMacDlspsCfgType_tree, hf_mu16ConfigFlag, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacDlspsCfgType_tree, hf_mu16DlSpsIntval, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;

    spsProcNum=tvb_get_ntohs( tvb, *offset);
    proto_tree_add_item(RcpMacDlspsCfgType_tree, hf_mu16SpsProcNum, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;

    numberOfn1Pucch=tvb_get_ntohs( tvb, *offset);
    proto_tree_add_item(RcpMacDlspsCfgType_tree, hf_mu16NumberOfn1Pucch, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;

    if(spsProcNum>0 && spsProcNum<8)
    {
        dataPtr = tvb_get_ptr(tvb, *offset, spsProcNum);
        proto_tree_add_bytes(RcpMacDlspsCfgType_tree, hf_mu16N1PucchAnPersistentList, tvb, *offset, spsProcNum, dataPtr);
    }
    (*offset)+=8;

    if(numberOfn1Pucch>0 && numberOfn1Pucch<8)
    {
        dataPtr = tvb_get_ptr(tvb, *offset, numberOfn1Pucch);
        proto_tree_add_bytes(RcpMacDlspsCfgType_tree, hf_mu16ulSubframeOffsetOfn1Pucch, tvb, *offset, numberOfn1Pucch, dataPtr);
    }
    (*offset)+=8;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmRxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{// 8 bytes
    proto_item* pi = NULL;
    proto_tree	*RcpRlcUmRxCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpRlcUmRxCfgType");
    RcpRlcUmRxCfgType_tree = proto_item_add_subtree(pi,ett_RcpRlcUmRxCfgType);


    proto_tree_add_item(RcpRlcUmRxCfgType_tree, hf_mu32TReordering, tvb, *offset, 4, 1);
    (*offset)+=4;
    proto_tree_add_item(RcpRlcUmRxCfgType_tree, hf_mu32SnFieldLen, tvb, *offset, 4, 1);
    (*offset)+=4;


//    proto_tree_add_item(RcpRlcUmRxCfgType_tree, hf_u32TStatusProhibit, tvb, *offset, 4, 1);
//    (*offset)+=4;
//    proto_tree_add_item(RcpRlcUmRxCfgType_tree, hf_u32TPollRetransmit, tvb, *offset, 4, 1);
//    (*offset)+=4;

    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_u_2(proto_tree *tree, tvbuff_t *tvb, int *offset,guint32 rlcMode,guint32 rlcDir)
{// 24 bytes
    proto_item* pi = NULL;
    proto_tree	*u_2_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"u 2");
    u_2_tree = proto_item_add_subtree(pi,ett_u_2);

/*20120713_ysq_delete begin*/
#if 0
    rrc_rlc_ctrl_proto_tree_add_RcpRlcAmCfgType(u_2_tree, tvb, offset);
#endif
/*20120713_ysq_delete end*/

    switch(rlcMode)
    {
        case 0:
            switch(rlcDir)
            {
                case 1:
                    rrc_rlc_ctrl_proto_tree_add_RcpRlcUmRxCfgType(u_2_tree, tvb, offset);//8bytes
                    (*offset)+=16;//union要偏移最大字节24Bytes，在此补充16 bytes
                    break;

                case 2:
                    rrc_rlc_ctrl_proto_tree_add_RcpRlcUmTxCfgType(u_2_tree, tvb, offset);// 4 bytes
                    (*offset)+=20;//union要偏移最大字节24Bytes，在此补充20 bytes
                    break;

                case 3:
                    rrc_rlc_ctrl_proto_tree_add_RcpRlcUmBiCfgType(u_2_tree, tvb, offset);//8bytes
                    (*offset)+=16;//union要偏移最大字节24Bytes，在此补充16 bytes
                    break;
                    
                default:
                    proto_tree_add_text(u_2_tree,tvb,0,0,"RLC MODE=0,but RLC DIR is not 1-3!");
                    (*offset)+=24; //union要偏移最大字节24Bytes，在此补充24 bytes
                    break;
            }
            break;

        case 1:
            rrc_rlc_ctrl_proto_tree_add_RcpRlcAmCfgType(u_2_tree, tvb, offset);// 24 bytes
            break;

        default:
            proto_tree_add_text(u_2_tree,tvb,0,0,"RLC MODE is not 0 or 1!");
            (*offset)+=24; //union要偏移最大字节24Bytes，在此补充24 bytes
            break;
    }

    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_u_1(proto_tree *tree, tvbuff_t *tvb, int *offset,guint32 rlcMode)
{
    proto_item* pi = NULL;
    proto_tree	*u_1_tree = NULL;
    int i;

    pi = proto_tree_add_text(tree,tvb,0,0,"u 1");
    u_1_tree = proto_item_add_subtree(pi,ett_u_1);


    switch(rlcMode)
    {
        case 1:
            proto_tree_add_item(u_1_tree, hf_mu8StatusReportRequired, tvb, *offset, 1, PC_BYTE_ORDER);
            (*offset)+=1;
        


            for(i=0;i<3;i++)
            {
                proto_tree_add_item(u_1_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
                (*offset)+=1;
            }            
            break;

        case 2:
            proto_tree_add_item(u_1_tree, hf_mu32UmPdcpSnSize, tvb, *offset, 4, PC_BYTE_ORDER);
            (*offset)+=4;
            break;

        default:
            (*offset)+=4;
            break;
    }

    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpMacDrbToAddlstType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_item* pi = NULL;
    proto_tree	*RcpMacDrbToAddlstType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpMacDrbToAddlstType");
    RcpMacDrbToAddlstType_tree = proto_item_add_subtree(pi,ett_RcpMacDrbToAddlstType);


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8LchIdExistFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8LchId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8RbId, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8RbIdTrunkFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8GbrType, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8ServiceType, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8DlQci, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8UlQci, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32DlGbrRateH, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32DlGbrRateL, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32DlMaxRateH, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32DlMaxRateL, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32UlGbrRateH, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32UlGbrRateL, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32UlMaxRateH, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu32UlMaxRateL, tvb, *offset, 4, PC_BYTE_ORDER);
    (*offset)+=4;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8LchGroupExstFlag, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8LchGroup, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8LchPriority, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu8Padding, tvb, *offset, 1, PC_BYTE_ORDER);
    (*offset)+=1;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu16UlPBR, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    proto_tree_add_item(RcpMacDrbToAddlstType_tree, hf_mu16UlBSD, tvb, *offset, 2, PC_BYTE_ORDER);
    (*offset)+=2;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmBiCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{ // 8 bytes
    proto_item* pi = NULL;
    proto_tree	*RcpRlcUmBiCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpRlcUmBiCfgType");
    RcpRlcUmBiCfgType_tree = proto_item_add_subtree(pi,ett_RcpRlcUmBiCfgType);


    proto_tree_add_item(RcpRlcUmBiCfgType_tree, hf_mu32SnFieldLen, tvb, *offset, 4, 1);
    (*offset)+=4;


    proto_tree_add_item(RcpRlcUmBiCfgType_tree, hf_mu32TReordering, tvb, *offset, 4, 1);
    (*offset)+=4;


    return pi;
}



proto_item *rrc_rlc_ctrl_proto_tree_add_RcpRlcUmTxCfgType(proto_tree *tree, tvbuff_t *tvb, int *offset)
{ // 4 bytes
    proto_item* pi = NULL;
    proto_tree	*RcpRlcUmTxCfgType_tree = NULL;

    pi = proto_tree_add_text(tree,tvb,0,0,"RcpRlcUmTxCfgType");
    RcpRlcUmTxCfgType_tree = proto_item_add_subtree(pi,ett_RcpRlcUmTxCfgType);


    proto_tree_add_item(RcpRlcUmTxCfgType_tree, hf_mu32SnFieldLen, tvb, *offset, 4, 1);
    (*offset)+=4;


    return pi;
}



static void dissect_rcp_up_rlc_handover_config_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int i;
    proto_item* pi = NULL;
    proto_tree* mstRbToAddListList_tree = NULL;
    guint16 rbToAddNum = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC HANDOVER CONFIG REQ");

    proto_tree_add_item(tree, hf_mu16UeIndex, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;

   oct1 = tvb_get_ntohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;

    rbToAddNum= tvb_get_ntohs(tvb,offset);
    proto_tree_add_item(tree, hf_mu16RbToAddNum, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(tree, hf_mu8Padding, tvb, offset, 1, PC_BYTE_ORDER);
        offset+=1;
    }

    if(rbToAddNum>0 && rbToAddNum<10)
    {
        pi = proto_tree_add_text(tree, tvb, 0, 0, "RcpRlcRbAddOrModifyListType List");
        mstRbToAddListList_tree = proto_item_add_subtree(pi, ett_RcpRlcRbAddOrModifyListTypeList);

        for(i=0; i<rbToAddNum; i++)
        {
            rrc_rlc_ctrl_proto_tree_add_RcpRlcRbAddOrModifyListType(mstRbToAddListList_tree, tvb, &offset);// 36 bytes
        }
        for(i=rbToAddNum;i<10;i++)
        {
            offset+=36;
        }

    }
    else
    {
        offset+=(10*36);
    }

    return;	
}



static void dissect_up_rcp_rlc_handover_config_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC HANDOVER CONFIG CNF");

   oct1 = tvb_get_ntohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;


    proto_tree_add_item(tree, hf_mu16Result, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;


    return;	
}



static void dissect_rcp_up_rlc_rrc_connection_config_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int i;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC RRC CONNECTION CONFIG REQ");

    proto_tree_add_item(tree, hf_u16CellUeIndex, tvb, offset, 2, 1);
    offset+=2;

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    proto_tree_add_item(tree, hf_mu8RbId, tvb, offset, 1, 1);
    offset+=1;


    proto_tree_add_item(tree, hf_mu8DefaultConfigPresent, tvb, offset, 1, 1);
    offset+=1;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(tree, hf_mu8Padding, tvb, offset, 1, 1);
        offset+=1;
    }


    rrc_rlc_ctrl_proto_tree_add_RcpRlcAmCfgType(tree, tvb, &offset);


    return;	
}



static void dissect_up_rcp_rlc_rrc_connection_config_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC RRC CONNECTION CONFIG CNF");

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    proto_tree_add_item(tree, hf_mu16Result, tvb, offset, 2, 1);
    offset+=2;


    return;	
}



static void dissect_rcp_up_rlc_reestablishment_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
//    const guint8 *dataPtr;
    guint16 rbToReestabNum=0;
    guint16 oct1 = 0;
	int i;
	
    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC REESTABLISHMENT REQ");

    proto_tree_add_item(tree, hf_u16CellUeIndex, tvb, offset, 2, 1);
    offset+=2;

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;

    rbToReestabNum=tvb_get_letohs(tvb,offset);
    proto_tree_add_item(tree, hf_mu16RbToReestabNum, tvb, offset, 2, 1);
    offset+=2;

//    if(rbToReestabNum>0 && rbToReestabNum<10)
//    {
//        dataPtr = tvb_get_ptr(tvb, offset, rbToReestabNum);
//        proto_tree_add_bytes(tree, hf_mu8RbIdforReEstb, tvb, offset, rbToReestabNum, dataPtr);
//    }
//    offset+=10;
//
	for (i=0;i<3;i++) {

	    proto_tree_add_item(tree, hf_u8RbIdforReEstb, tvb, offset, 1, 1);
	    offset+=1;
	}
	for(i=0;i<3;i++) {

		proto_tree_add_item(tree, hf_mu8padding, tvb, offset, 1, 1);
		offset+=1;

	}


    return;	
}



static void dissect_up_rcp_rlc_reestablishment_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC REESTABLISHMENT CNF");

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    proto_tree_add_item(tree, hf_mu16Result, tvb, offset, 2, 1);
    offset+=2;


    return;	
}



static void dissect_rcp_up_rlc_rrc_connection_reconfig_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int i;
    proto_item* pi = NULL;
    proto_tree* mstRbToAddOrModifyListList_tree = NULL;
//    const guint8 *dataPtr;
    guint16 rbAddNum = 0;
    guint16 rbRelNum = 0;
    guint16 rbModNum = 0;
    guint16 oct1 = 0;
	
    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC RRC CONNECTION RECONFIG REQ");

	

    proto_tree_add_item(tree, hf_u16CellUeIndex, tvb, offset, 2, 1);
    offset+=2;

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    rbAddNum = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_mu16RbToAddNum, tvb, offset, 2, 1);
    offset+=2;


    rbRelNum = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_mu16RbToReleaseNum, tvb, offset, 2, 1);
    offset+=2;

    rbModNum = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_mu16URbToModifyNum, tvb, offset, 2, 1);
    offset+=2;


    for(i=0;i<2;i++)
    {
        proto_tree_add_item(tree, hf_mu8Padding, tvb, offset, 1, 1);
        offset+=1;
    }

	pi = proto_tree_add_text(tree, tvb, 0, 0, "RcpRlcRbAddOrModifyListType List");
	mstRbToAddOrModifyListList_tree = proto_item_add_subtree(pi, ett_RcpRlcRbAddOrModifyListTypeList);

	for(i=0; i<3; i++)
	{
		rrc_rlc_ctrl_proto_tree_add_RcpRlcRbAddOrModifyListType(mstRbToAddOrModifyListList_tree, tvb, &offset);// 36 bytes
	}



//以上OK_YSQ_20120713

//    if((rbAddNum+rbModNum)>0 &&(rbAddNum+rbModNum)<=10 )
//    {
//        pi = proto_tree_add_text(tree, tvb, 0, 0, "RcpRlcRbAddOrModifyListType List");
//        mstRbToAddOrModifyListList_tree = proto_item_add_subtree(pi, ett_RcpRlcRbAddOrModifyListTypeList);
//
//        for(i=0; i<(rbAddNum+rbModNum); i++)
//        {
//      		rrc_rlc_ctrl_proto_tree_add_RcpRlcRbAddOrModifyListType(mstRbToAddOrModifyListList_tree, tvb, &offset);// 36 bytes
//        }
//        
//        for(i=(rbAddNum+rbModNum);i<10;i++)
//        {
//            offset+=36;
//        }
//    }
//    else
//    {
//        offset+=36*10;
//    }

//    if(rbRelNum>0 && rbRelNum<10)
//    {        
//        dataPtr = tvb_get_ptr(tvb, offset, rbRelNum);
//        proto_tree_add_bytes(tree, hf_mu8RbIdforRelease, tvb, offset, 10, dataPtr);
//    }
//    offset+=10;

	for(i=0;i<3;i++)
    {
        proto_tree_add_item(tree, hf_mu8RbIdforRelease, tvb, offset, 1, 1);
        offset+=1;
		
	}


	proto_tree_add_item(tree, hf_mu8Padding1, tvb, offset, 1, PC_BYTE_ORDER);
	offset+=1;
    
//    for(i=0;i<2;i++)
//    {
//        proto_tree_add_item(tree, hf_mu8Padding1, tvb, offset, 1, PC_BYTE_ORDER);
//        offset+=1;
//    }
    return;	
}



static void dissect_up_rcp_rlc_rrc_connection_reconfig_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC RRC CONNECTION RECONFIG CNF");

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    proto_tree_add_item(tree, hf_mu16Result, tvb, offset, 2, 1);
    offset+=2;


    return;	
}



static void dissect_rcp_up_rlc_release_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC RELEASE REQ");

    proto_tree_add_item(tree, hf_mu16UeIndex, tvb, offset, 2, 1);
    offset+=2;

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    return;	
}



static void dissect_up_rcp_rlc_release_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC RELEASE CNF");

   oct1 = tvb_get_letohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, 1);
    offset+=2;


    proto_tree_add_item(tree, hf_mu16Result, tvb, offset, 2, 1);
    offset+=2;


    return;	
}



static void dissect_up_rcp_rlc_max_retrans_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint16 oct1 = 0;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC MAX RETRANS IND");

   oct1 = tvb_get_ntohs(tvb,offset);
   if (check_col(pinfo->cinfo, COL_Ue_ID))
   {col_append_fstr(pinfo->cinfo, COL_Ue_ID, " %d ", oct1);}
    proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 2, PC_BYTE_ORDER);
    offset+=2;


    proto_tree_add_item(tree, hf_mu8RbId, tvb, offset, 1, PC_BYTE_ORDER);
    offset+=1;


    proto_tree_add_item(tree, hf_mu8Padding, tvb, offset, 1, PC_BYTE_ORDER);
    offset+=1;


    return;	
}


static void dissect_rcp_up_rlc_buffer_release_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
//	int i;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "RCP UP RLC BUFFER RELEASE REQ");

	proto_tree_add_item(tree, hf_mu16UeIndex, tvb, offset, 1, FALSE);
	offset+=2;

	proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 1, FALSE);
	offset+=2;


	return;

}



static void dissect_up_rcp_rlc_buffer_release_cnf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int	offset = 0;
//	int i;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "UP RCP RLC BUFFER RELEASE CNF");

	proto_tree_add_item(tree, hf_mu16UeId, tvb, offset, 1, FALSE);
	offset+=2;

	proto_tree_add_item(tree, hf_result, tvb, offset, 1, FALSE);
	offset+=2;


	return;

}



static void dissect_rrc_rlc_ctrl_sap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*rrc_rlc_ctrl_item = NULL;
    proto_tree	*rrc_rlc_ctrl_tree = NULL;
	
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RRC RLC CTRL SAP");

    rrc_rlc_ctrl_item = proto_tree_add_item(tree, proto_rrc_rlc_ctrl_sap, tvb, 0, -1, PC_BYTE_ORDER);
    rrc_rlc_ctrl_tree = proto_item_add_subtree(rrc_rlc_ctrl_item, ett_rrc_rlc_ctrl_sap);

    switch(pinfo->pseudo_header->omc.tr_content.all_tr.msgType)
    {
		case RCP_UP_RLC_RRC_CONNECTION_CONFIG_REQ:
			dissect_rcp_up_rlc_rrc_connection_config_req(tvb, pinfo, rrc_rlc_ctrl_tree);
			break;


		case UP_RCP_RLC_RRC_CONNECTION_CONFIG_CNF:
			dissect_up_rcp_rlc_rrc_connection_config_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
			break;

		case RCP_UP_RLC_REESTABLISHMENT_REQ:
		  dissect_rcp_up_rlc_reestablishment_req(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;
		

		case UP_RCP_RLC_REESTABLISHMENT_CNF:
		  dissect_up_rcp_rlc_reestablishment_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;

		  
		case RCP_UP_RLC_RRC_CONNECTION_RECONFIG_REQ:
		  dissect_rcp_up_rlc_rrc_connection_reconfig_req(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;
		

		case UP_RCP_RLC_RRC_CONNECTION_RECONFIG_CNF:
		  dissect_up_rcp_rlc_rrc_connection_reconfig_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;
		
		case RCP_UP_RLC_RELEASE_REQ:
		  dissect_rcp_up_rlc_release_req(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;
		

		case UP_RCP_RLC_RELEASE_CNF:
		  dissect_up_rcp_rlc_release_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
		  break;

  		case UP_RCP_RLC_MAX_RETRANS_IND:
  			dissect_up_rcp_rlc_max_retrans_ind(tvb, pinfo, rrc_rlc_ctrl_tree);
  			break;



		  
        case RCP_UP_RLC_HANDOVER_CONFIG_REQ:
            dissect_rcp_up_rlc_handover_config_req(tvb, pinfo, rrc_rlc_ctrl_tree);
            break;


        case UP_RCP_RLC_HANDOVER_CONFIG_CNF:
            dissect_up_rcp_rlc_handover_config_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
            break;

//
//
//
//
//
//        case 66:
//            dissect_rcp_up_rlc_rrc_connection_reconfig_req(tvb, pinfo, rrc_rlc_ctrl_tree);
//            break;
//
//
//        case 67:
//            dissect_up_rcp_rlc_rrc_connection_reconfig_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
//            break;
//
//
//
//

//
//
//	 case 71: //RCP UP RLC BUFFER RELEASE REQ
//		dissect_rcp_up_rlc_buffer_release_req(tvb, pinfo, rrc_rlc_ctrl_tree);
//		break;
//
//
//	 case 72: //UP RCP RLC BUFFER RELEASE CNF
//		dissect_up_rcp_rlc_buffer_release_cnf(tvb, pinfo, rrc_rlc_ctrl_tree);
//		break;

        default:
            break;
    }

    return;
}


void
proto_register_rrc_rlc_ctrl_sap(void)
{
    static hf_register_info hf[] = {

        { &hf_mu8DrxFlag ,
      	{ "mu8DrxFlag", "rrc_rlc_ctrl_sap.mu8DrxFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrxFlag", HFILL }},


        { &hf_mu8K ,
      	{ "mu8K", "rrc_rlc_ctrl_sap.mu8K",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8K", HFILL }},


        { &hf_mu8PhrExstFlag ,
      	{ "mu8PhrExstFlag", "rrc_rlc_ctrl_sap.mu8PhrExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PhrExstFlag", HFILL }},


        { &hf_mu8IsTtiBunding ,
      	{ "mu8IsTtiBunding", "rrc_rlc_ctrl_sap.mu8IsTtiBunding",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IsTtiBunding", HFILL }},


        { &hf_mu8CqiFormatInd ,
      	{ "mu8CqiFormatInd", "rrc_rlc_ctrl_sap.mu8CqiFormatInd",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CqiFormatInd", HFILL }},


        { &hf_mu8RbIdTrunkFlag ,
      	{ "mu8RbIdTrunkFlag", "rrc_rlc_ctrl_sap.mu8RbIdTrunkFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RbIdTrunkFlag", HFILL }},


        { &hf_mu8GapType ,
      	{ "mu8GapType", "rrc_rlc_ctrl_sap.mu8GapType",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8GapType", HFILL }},


        { &hf_mu8LchPriority ,
      	{ "mu8LchPriority", "rrc_rlc_ctrl_sap.mu8LchPriority",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8LchPriority", HFILL }},


        { &hf_mu32RlcMode ,
      	{ "mu32RlcMode", "rrc_rlc_ctrl_sap.mu32RlcMode",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32RlcMode", HFILL }},


        { &hf_mu16PdschSimResSwitchCyc ,
      	{ "mu16PdschSimResSwitchCyc", "rrc_rlc_ctrl_sap.mu16PdschSimResSwitchCyc",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16PdschSimResSwitchCyc", HFILL }},


        { &hf_mu8SrbList ,
      	{ "mu8SrbList", "rrc_rlc_ctrl_sap.mu8SrbList",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrbList", HFILL }},


        { &hf_mu32UlGbrRateH ,
      	{ "mu32UlGbrRateH", "rrc_rlc_ctrl_sap.mu32UlGbrRateH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlGbrRateH", HFILL }},


        { &hf_mu16PeriodicBsrTimer ,
      	{ "mu16PeriodicBsrTimer", "rrc_rlc_ctrl_sap.mu16PeriodicBsrTimer",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16PeriodicBsrTimer", HFILL }},


        { &hf_mu16N1Pucch3 ,
      	{ "mu16N1Pucch3", "rrc_rlc_ctrl_sap.mu16N1Pucch3",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1Pucch3", HFILL }},


        { &hf_mu8IsTpcAccumlate ,
      	{ "mu8IsTpcAccumlate", "rrc_rlc_ctrl_sap.mu8IsTpcAccumlate",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IsTpcAccumlate", HFILL }},


        { &hf_mu8PmiRiReportFlag ,
      	{ "mu8PmiRiReportFlag", "rrc_rlc_ctrl_sap.mu8PmiRiReportFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PmiRiReportFlag", HFILL }},


        { &hf_mu8TddAckFdBackMode ,
      	{ "mu8TddAckFdBackMode", "rrc_rlc_ctrl_sap.mu8TddAckFdBackMode",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TddAckFdBackMode", HFILL }},


        { &hf_mu8TransMode ,
      	{ "mu8TransMode", "rrc_rlc_ctrl_sap.mu8TransMode",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TransMode", HFILL }},


        { &hf_mu16RbToReleaseNum ,
      	{ "mu16RbToReleaseNum", "rrc_rlc_ctrl_sap.mu16RbToReleaseNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RbToReleaseNum", HFILL }},


        { &hf_mu32PollPdu ,
      	{ "mu32PollPdu", "rrc_rlc_ctrl_sap.mu32PollPdu",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32PollPdu", HFILL }},


        { &hf_mu16N1Pucch0 ,
      	{ "mu16N1Pucch0", "rrc_rlc_ctrl_sap.mu16N1Pucch0",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1Pucch0", HFILL }},


        { &hf_mu32SnFieldLen ,
      	{ "mu32SnFieldLen", "rrc_rlc_ctrl_sap.mu32SnFieldLen",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32SnFieldLen", HFILL }},


        { &hf_mu8RbIdforReEstb ,
      	{ "mu8RbIdforReEstb", "rrc_rlc_ctrl_sap.mu8RbIdforReEstb",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RbIdforReEstb", HFILL }},


        { &hf_mu8RiCfgIndexPresent ,
      	{ "mu8RiCfgIndexPresent", "rrc_rlc_ctrl_sap.mu8RiCfgIndexPresent",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RiCfgIndexPresent", HFILL }},


        { &hf_mu8DrbRlsRbId ,
      	{ "mu8DrbRlsRbId", "rrc_rlc_ctrl_sap.mu8DrbRlsRbId",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrbRlsRbId", HFILL }},


        { &hf_p0NomnlPuschPsst ,
      	{ "p0NomnlPuschPsst", "rrc_rlc_ctrl_sap.p0NomnlPuschPsst",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.p0NomnlPuschPsst", HFILL }},


        { &hf_mu8OnDuratonTimer ,
      	{ "mu8OnDuratonTimer", "rrc_rlc_ctrl_sap.mu8OnDuratonTimer",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8OnDuratonTimer", HFILL }},


        { &hf_mu32UlAMBRH ,
      	{ "mu32UlAMBRH", "rrc_rlc_ctrl_sap.mu32UlAMBRH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlAMBRH", HFILL }},


        { &hf_mu16DataLen ,
      	{ "mu16DataLen", "rrc_rlc_ctrl_sap.mu16DataLen",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DataLen", HFILL }},


        { &hf_mu8UlQci ,
      	{ "mu8UlQci", "rrc_rlc_ctrl_sap.mu8UlQci",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UlQci", HFILL }},


        { &hf_prohibitPhrTimer ,
      	{ "prohibitPhrTimer", "rrc_rlc_ctrl_sap.prohibitPhrTimer",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.prohibitPhrTimer", HFILL }},


        { &hf_mi16P0UePuschPsst ,
      	{ "mi16P0UePuschPsst", "rrc_rlc_ctrl_sap.mi16P0UePuschPsst",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi16P0UePuschPsst", HFILL }},


        { &hf_mu8MaxInSyncTimes ,
      	{ "mu8MaxInSyncTimes", "rrc_rlc_ctrl_sap.mu8MaxInSyncTimes",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8MaxInSyncTimes", HFILL }},


        { &hf_mu8ErabNum ,
      	{ "mu8ErabNum", "rrc_rlc_ctrl_sap.mu8ErabNum",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ErabNum", HFILL }},


        { &hf_mu8PaddingSrb ,
      	{ "mu8PaddingSrb", "rrc_rlc_ctrl_sap.mu8PaddingSrb",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PaddingSrb", HFILL }},


        { &hf_mu8DataBuf ,
      	{ "mu8DataBuf", "rrc_rlc_ctrl_sap.mu8DataBuf",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DataBuf", HFILL }},


        { &hf_mu8SrsHoppingBandwidth ,
      	{ "mu8SrsHoppingBandwidth", "rrc_rlc_ctrl_sap.mu8SrsHoppingBandwidth",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrsHoppingBandwidth", HFILL }},


        { &hf_mu8SpsProcNum ,
      	{ "mu8SpsProcNum", "rrc_rlc_ctrl_sap.mu8SpsProcNum",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SpsProcNum", HFILL }},


        { &hf_mu16URbToModifyNum ,
      	{ "mu16URbToModifyNum", "rrc_rlc_ctrl_sap.mu16URbToModifyNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16URbToModifyNum", HFILL }},


        { &hf_muPadding1 ,
      	{ "muPadding1", "rrc_rlc_ctrl_sap.muPadding1",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.muPadding1", HFILL }},


        { &hf_mu16CqiPmiCfgIdx ,
      	{ "mu16CqiPmiCfgIdx", "rrc_rlc_ctrl_sap.mu16CqiPmiCfgIdx",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16CqiPmiCfgIdx", HFILL }},


        { &hf_mu8DsrTranMax ,
      	{ "mu8DsrTranMax", "rrc_rlc_ctrl_sap.mu8DsrTranMax",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DsrTranMax", HFILL }},


        { &hf_mu32UlHfn ,
      	{ "mu32UlHfn", "rrc_rlc_ctrl_sap.mu32UlHfn",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlHfn", HFILL }},


        { &hf_mu8StatusReportRequired ,
      	{ "mu8StatusReportRequired", "rrc_rlc_ctrl_sap.mu8StatusReportRequired",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8StatusReportRequired", HFILL }},


        { &hf_mu16N1PucchAnRep ,
      	{ "mu16N1PucchAnRep", "rrc_rlc_ctrl_sap.mu16N1PucchAnRep",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1PucchAnRep", HFILL }},


        { &hf_UeIdList ,
      	{ "UeIdList", "rrc_rlc_ctrl_sap.UeIdList",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.UeIdList", HFILL }},


        { &hf_mu8SrCfgIndex ,
      	{ "mu8SrCfgIndex", "rrc_rlc_ctrl_sap.mu8SrCfgIndex",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrCfgIndex", HFILL }},


        { &hf_mu8SimLoadSwitch ,
      	{ "mu8SimLoadSwitch", "rrc_rlc_ctrl_sap.mu8SimLoadSwitch",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SimLoadSwitch", HFILL }},


        { &hf_mu8Duration ,
      	{ "mu8Duration", "rrc_rlc_ctrl_sap.mu8Duration",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Duration", HFILL }},


        { &hf_mu8CKup ,
      	{ "mu8CKup", "rrc_rlc_ctrl_sap.mu8CKup",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CKup", HFILL }},


        { &hf_mu16ConfigFlag ,
      	{ "mu16ConfigFlag", "rrc_rlc_ctrl_sap.mu16ConfigFlag",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16ConfigFlag", HFILL }},


        { &hf_mu8IsDefaultCfg ,
      	{ "mu8IsDefaultCfg", "rrc_rlc_ctrl_sap.mu8IsDefaultCfg",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IsDefaultCfg", HFILL }},


        { &hf_mu8ProfilePresent ,
      	{ "mu8ProfilePresent", "rrc_rlc_ctrl_sap.mu8ProfilePresent",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ProfilePresent", HFILL }},


        { &hf_mu8SrsBandwidth ,
      	{ "mu8SrsBandwidth", "rrc_rlc_ctrl_sap.mu8SrsBandwidth",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrsBandwidth", HFILL }},


        { &hf_mu8PaddingPucch ,
      	{ "mu8PaddingPucch", "rrc_rlc_ctrl_sap.mu8PaddingPucch",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PaddingPucch", HFILL }},


        { &hf_mu32DlAMBRL ,
      	{ "mu32DlAMBRL", "rrc_rlc_ctrl_sap.mu32DlAMBRL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlAMBRL", HFILL }},


        { &hf_mu32IntegrityProtAlgorithm ,
      	{ "mu32IntegrityProtAlgorithm", "rrc_rlc_ctrl_sap.mu32IntegrityProtAlgorithm",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32IntegrityProtAlgorithm", HFILL }},


        { &hf_mu8ShDrxExstFlag ,
      	{ "mu8ShDrxExstFlag", "rrc_rlc_ctrl_sap.mu8ShDrxExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ShDrxExstFlag", HFILL }},


        { &hf_mu32TeidUlForward ,
      	{ "mu32TeidUlForward", "rrc_rlc_ctrl_sap.mu32TeidUlForward",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TeidUlForward", HFILL }},


        { &hf_mu8IK ,
      	{ "mu8IK", "rrc_rlc_ctrl_sap.mu8IK",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IK", HFILL }},


        { &hf_mu16LDrxCyclStartOffsetVal ,
      	{ "mu16LDrxCyclStartOffsetVal", "rrc_rlc_ctrl_sap.mu16LDrxCyclStartOffsetVal",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16LDrxCyclStartOffsetVal", HFILL }},


        { &hf_mu8ErabId ,
      	{ "mu8ErabId", "rrc_rlc_ctrl_sap.mu8ErabId",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ErabId", HFILL }},


        { &hf_mu8ProfileInstance ,
      	{ "mu8ProfileInstance", "rrc_rlc_ctrl_sap.mu8ProfileInstance",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ProfileInstance", HFILL }},


        { &hf_mu8p0PersisExstFlag ,
      	{ "mu8p0PersisExstFlag", "rrc_rlc_ctrl_sap.mu8p0PersisExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8p0PersisExstFlag", HFILL }},


        { &hf_mu8ExistFlag ,
      	{ "mu8ExistFlag", "rrc_rlc_ctrl_sap.mu8ExistFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ExistFlag", HFILL }},


        { &hf_mu16TpcPuschRnti ,
      	{ "mu16TpcPuschRnti", "rrc_rlc_ctrl_sap.mu16TpcPuschRnti",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16TpcPuschRnti", HFILL }},


        { &hf_mu8CqiMaskFlag ,
      	{ "mu8CqiMaskFlag", "rrc_rlc_ctrl_sap.mu8CqiMaskFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CqiMaskFlag", HFILL }},


        { &hf_mu8DlQci ,
      	{ "mu8DlQci", "rrc_rlc_ctrl_sap.mu8DlQci",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DlQci", HFILL }},


        { &hf_mu8CqiRptModeAperiod ,
      	{ "mu8CqiRptModeAperiod", "rrc_rlc_ctrl_sap.mu8CqiRptModeAperiod",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CqiRptModeAperiod", HFILL }},


        { &hf_mu32UlGbrRateL ,
      	{ "mu32UlGbrRateL", "rrc_rlc_ctrl_sap.mu32UlGbrRateL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlGbrRateL", HFILL }},


        { &hf_mu8CqiMask ,
      	{ "mu8CqiMask", "rrc_rlc_ctrl_sap.mu8CqiMask",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CqiMask", HFILL }},


        { &hf_mu16RbListNum ,
      	{ "mu16RbListNum", "rrc_rlc_ctrl_sap.mu16RbListNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RbListNum", HFILL }},


        { &hf_mu8PaddingDrbRls ,
      	{ "mu8PaddingDrbRls", "rrc_rlc_ctrl_sap.mu8PaddingDrbRls",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PaddingDrbRls", HFILL }},


        { &hf_mu8HcRequired ,
      	{ "mu8HcRequired", "rrc_rlc_ctrl_sap.mu8HcRequired",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8HcRequired", HFILL }},


        { &hf_mu16RetxBsrTimer ,
      	{ "mu16RetxBsrTimer", "rrc_rlc_ctrl_sap.mu16RetxBsrTimer",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RetxBsrTimer", HFILL }},


        { &hf_mu8DlPathlossChange ,
      	{ "mu8DlPathlossChange", "rrc_rlc_ctrl_sap.mu8DlPathlossChange",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DlPathlossChange", HFILL }},


        { &hf_mu8SrProhibitTimer ,
      	{ "mu8SrProhibitTimer", "rrc_rlc_ctrl_sap.mu8SrProhibitTimer",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrProhibitTimer", HFILL }},


        { &hf_mu8Qci ,
      	{ "mu8Qci", "rrc_rlc_ctrl_sap.mu8Qci",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Qci", HFILL }},


        { &hf_mu8SpsCRNTIExstFlag ,
      	{ "mu8SpsCRNTIExstFlag", "rrc_rlc_ctrl_sap.mu8SpsCRNTIExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SpsCRNTIExstFlag", HFILL }},


        { &hf_mu8DrxRetransTimer ,
      	{ "mu8DrxRetransTimer", "rrc_rlc_ctrl_sap.mu8DrxRetransTimer",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrxRetransTimer", HFILL }},


        { &hf_mu16DlPdcpSn ,
      	{ "mu16DlPdcpSn", "rrc_rlc_ctrl_sap.mu16DlPdcpSn",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DlPdcpSn", HFILL }},


        { &hf_mu16SimRNTI ,
      	{ "mu16SimRNTI", "rrc_rlc_ctrl_sap.mu16SimRNTI",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SimRNTI", HFILL }},


        { &hf_mu8LchGroupExstFlag ,
      	{ "mu8LchGroupExstFlag", "rrc_rlc_ctrl_sap.mu8LchGroupExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8LchGroupExstFlag", HFILL }},


        { &hf_mu8TddAckFdbckModeExstFlag ,
      	{ "mu8TddAckFdbckModeExstFlag", "rrc_rlc_ctrl_sap.mu8TddAckFdbckModeExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TddAckFdbckModeExstFlag", HFILL }},


        { &hf_mu8DefaultConfigPresent ,
      	{ "mu8DefaultConfigPresent", "rrc_rlc_ctrl_sap.mu8DefaultConfigPresent",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DefaultConfigPresent", HFILL }},


        { &hf_mu8ShDrxCyclTimer ,
      	{ "mu8ShDrxCyclTimer", "rrc_rlc_ctrl_sap.mu8ShDrxCyclTimer",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ShDrxCyclTimer", HFILL }},


        { &hf_mu8CellIndex ,
      	{ "mu8CellIndex", "rrc_rlc_ctrl_sap.mu8CellIndex",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CellIndex", HFILL }},


        { &hf_mi16P0NomnlPuschPsst ,
      	{ "mi16P0NomnlPuschPsst", "rrc_rlc_ctrl_sap.mi16P0NomnlPuschPsst",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi16P0NomnlPuschPsst", HFILL }},


        { &hf_mu32TeidDlForward ,
      	{ "mu32TeidDlForward", "rrc_rlc_ctrl_sap.mu32TeidDlForward",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TeidDlForward", HFILL }},


        { &hf_mu8DlSpsIntval ,
      	{ "mu8DlSpsIntval", "rrc_rlc_ctrl_sap.mu8DlSpsIntval",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DlSpsIntval", HFILL }},


        { &hf_mu16RbToReestabNum ,
      	{ "mu16RbToReestabNum", "rrc_rlc_ctrl_sap.mu16RbToReestabNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RbToReestabNum", HFILL }},


        { &hf_mu8UlSpsIntval ,
      	{ "mu8UlSpsIntval", "rrc_rlc_ctrl_sap.mu8UlSpsIntval",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UlSpsIntval", HFILL }},


        { &hf_mu8Result ,
      	{ "mu8Result", "rrc_rlc_ctrl_sap.mu8Result",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Result", HFILL }},


        { &hf_mu8ImplicitReleaseAfter ,
      	{ "mu8ImplicitReleaseAfter", "rrc_rlc_ctrl_sap.mu8ImplicitReleaseAfter",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ImplicitReleaseAfter", HFILL }},


        { &hf_mu16UlPBR ,
      	{ "mu16UlPBR", "rrc_rlc_ctrl_sap.mu16UlPBR",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UlPBR", HFILL }},


        { &hf_mu8SrFlag ,
      	{ "mu8SrFlag", "rrc_rlc_ctrl_sap.mu8SrFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrFlag", HFILL }},


        { &hf_mu8SimLoadType ,
      	{ "mu8SimLoadType", "rrc_rlc_ctrl_sap.mu8SimLoadType",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SimLoadType", HFILL }},


        { &hf_mu16MaxCID ,
      	{ "mu16MaxCID", "rrc_rlc_ctrl_sap.mu16MaxCID",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16MaxCID", HFILL }},


        { &hf_mu32CodeBokSubsetExstFlag ,
      	{ "mu32CodeBokSubsetExstFlag", "rrc_rlc_ctrl_sap.mu32CodeBokSubsetExstFlag",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32CodeBokSubsetExstFlag", HFILL }},


        { &hf_mu8DrxExstFlag ,
      	{ "mu8DrxExstFlag", "rrc_rlc_ctrl_sap.mu8DrxExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrxExstFlag", HFILL }},


        { &hf_mu8padding ,
      	{ "mu8padding", "rrc_rlc_ctrl_sap.mu8padding",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8padding", HFILL }},


        { &hf_mu16RbToAddNum ,
      	{ "mu16RbToAddNum", "rrc_rlc_ctrl_sap.mu16RbToAddNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RbToAddNum", HFILL }},


        { &hf_phrCfgExstFlag ,
      	{ "phrCfgExstFlag", "rrc_rlc_ctrl_sap.phrCfgExstFlag",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.phrCfgExstFlag", HFILL }},


        { &hf_mu16BitRatePerPriority ,
      	{ "mu16BitRatePerPriority", "rrc_rlc_ctrl_sap.mu16BitRatePerPriority",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16BitRatePerPriority", HFILL }},


        { &hf_mu8UeVersion ,
      	{ "mu8UeVersion", "rrc_rlc_ctrl_sap.mu8UeVersion",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UeVersion", HFILL }},


        { &hf_mu8PeriodicBSRTimerFlag ,
      	{ "mu8PeriodicBSRTimerFlag", "rrc_rlc_ctrl_sap.mu8PeriodicBSRTimerFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PeriodicBSRTimerFlag", HFILL }},


        { &hf_mu16UeId ,
      	{ "mu16UeId", "rrc_rlc_ctrl_sap.mu16UeId",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UeId", HFILL }},


        { &hf_mu8RbIdforRelease ,
      	{ "mu8RbIdforRelease", "rrc_rlc_ctrl_sap.mu8RbIdforRelease",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RbIdforRelease", HFILL }},


        { &hf_mu16N1PucchAnPersistentList ,
      	{ "mu16N1PucchAnPersistentList", "rrc_rlc_ctrl_sap.mu16N1PucchAnPersistentList",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1PucchAnPersistentList", HFILL }},


        { &hf_mu16SimUeIdx ,
      	{ "mu16SimUeIdx", "rrc_rlc_ctrl_sap.mu16SimUeIdx",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SimUeIdx", HFILL }},


        { &hf_mu32LchGroupExstFlag ,
      	{ "mu32LchGroupExstFlag", "rrc_rlc_ctrl_sap.mu32LchGroupExstFlag",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32LchGroupExstFlag", HFILL }},

        { &hf_mu8TrunkPriority ,
      	{ "mu8TrunkPriority", "rrc_rlc_ctrl_sap.mu8TrunkPriority",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TrunkPriority", HFILL }},

        { &hf_mu8Cri ,
      	{ "mu8Cri", "rrc_rlc_ctrl_sap.mu8Cri",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Cri", HFILL }},


        { &hf_mu8PmiRIReport ,
      	{ "mu8PmiRIReport", "rrc_rlc_ctrl_sap.mu8PmiRIReport",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PmiRIReport", HFILL }},


        { &hf_mu32DrbReleaseListNum ,
      	{ "mu32DrbReleaseListNum", "rrc_rlc_ctrl_sap.mu32DrbReleaseListNum",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DrbReleaseListNum", HFILL }},


        { &hf_mu16SrsCfgIndex ,
      	{ "mu16SrsCfgIndex", "rrc_rlc_ctrl_sap.mu16SrsCfgIndex",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SrsCfgIndex", HFILL }},


        { &hf_mu8LchGroup ,
      	{ "mu8LchGroup", "rrc_rlc_ctrl_sap.mu8LchGroup",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8LchGroup", HFILL }},


        { &hf_mu8LchId ,
      	{ "mu8LchId", "rrc_rlc_ctrl_sap.mu8LchId",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8LchId", HFILL }},


        { &hf_mu16DrbAddModifyListNum ,
      	{ "mu16DrbAddModifyListNum", "rrc_rlc_ctrl_sap.mu16DrbAddModifyListNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DrbAddModifyListNum", HFILL }},


        { &hf_mu8IntegrityRequired ,
      	{ "mu8IntegrityRequired", "rrc_rlc_ctrl_sap.mu8IntegrityRequired",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IntegrityRequired", HFILL }},


        { &hf_mu8TransmissionComb ,
      	{ "mu8TransmissionComb", "rrc_rlc_ctrl_sap.mu8TransmissionComb",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TransmissionComb", HFILL }},


        { &hf_mu8Flag ,
      	{ "mu8Flag", "rrc_rlc_ctrl_sap.mu8Flag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Flag", HFILL }},


        { &hf_mu16TmpUeIndex ,
      	{ "mu16TmpUeIndex", "rrc_rlc_ctrl_sap.mu16TmpUeIndex",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16TmpUeIndex", HFILL }},


        { &hf_mu32DlGbrRateH ,
      	{ "mu32DlGbrRateH", "rrc_rlc_ctrl_sap.mu32DlGbrRateH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlGbrRateH", HFILL }},


        { &hf_mu32RlcDirection ,
      	{ "mu32RlcDirection", "rrc_rlc_ctrl_sap.mu32RlcDirection",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32RlcDirection", HFILL }},


        { &hf_mu32IpFamily ,
      	{ "mu32IpFamily", "rrc_rlc_ctrl_sap.mu32IpFamily",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32IpFamily", HFILL }},


        { &hf_mu32DlGbrRateL ,
      	{ "mu32DlGbrRateL", "rrc_rlc_ctrl_sap.mu32DlGbrRateL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlGbrRateL", HFILL }},


        { &hf_mu16NumberOfn1Pucch ,
      	{ "mu16NumberOfn1Pucch", "rrc_rlc_ctrl_sap.mu16NumberOfn1Pucch",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16NumberOfn1Pucch", HFILL }},


        { &hf_mu8DeltaMcsEnable ,
      	{ "mu8DeltaMcsEnable", "rrc_rlc_ctrl_sap.mu8DeltaMcsEnable",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DeltaMcsEnable", HFILL }},


        { &hf_mu8SrbId ,
      	{ "mu8SrbId", "rrc_rlc_ctrl_sap.mu8SrbId",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrbId", HFILL }},


        { &hf_mu8SpsExstFlag ,
      	{ "mu8SpsExstFlag", "rrc_rlc_ctrl_sap.mu8SpsExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SpsExstFlag", HFILL }},


        { &hf_mu16CRnti ,
      	{ "mu16CRnti", "rrc_rlc_ctrl_sap.mu16CRnti",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16CRnti", HFILL }},


        { &hf_mu32UeNum ,
      	{ "mu32UeNum", "rrc_rlc_ctrl_sap.mu32UeNum",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UeNum", HFILL }},


        { &hf_Padding ,
      	{ "Padding", "rrc_rlc_ctrl_sap.Padding",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.Padding", HFILL }},


        { &hf_mu16CodeBookSubset ,
      	{ "mu16CodeBookSubset", "rrc_rlc_ctrl_sap.mu16CodeBookSubset",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16CodeBookSubset", HFILL }},


        { &hf_mu8IdleTransNumBFImplctRelease ,
      	{ "mu8IdleTransNumBFImplctRelease", "rrc_rlc_ctrl_sap.mu8IdleTransNumBFImplctRelease",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IdleTransNumBFImplctRelease", HFILL }},


        { &hf_mu16PdcchSimResSwitchCyc ,
      	{ "mu16PdcchSimResSwitchCyc", "rrc_rlc_ctrl_sap.mu16PdcchSimResSwitchCyc",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16PdcchSimResSwitchCyc", HFILL }},


        { &hf_p0UePuschPsst ,
      	{ "p0UePuschPsst", "rrc_rlc_ctrl_sap.p0UePuschPsst",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.p0UePuschPsst", HFILL }},


        { &hf_mu16BucketSizeDuration ,
      	{ "mu16BucketSizeDuration", "rrc_rlc_ctrl_sap.mu16BucketSizeDuration",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16BucketSizeDuration", HFILL }},


        { &hf_mu32DrbNum ,
      	{ "mu32DrbNum", "rrc_rlc_ctrl_sap.mu32DrbNum",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DrbNum", HFILL }},


        { &hf_mu32CipheringAlgorithm ,
      	{ "mu32CipheringAlgorithm", "rrc_rlc_ctrl_sap.mu32CipheringAlgorithm",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32CipheringAlgorithm", HFILL }},


        { &hf_mu16DlSpsIntval ,
      	{ "mu16DlSpsIntval", "rrc_rlc_ctrl_sap.mu16DlSpsIntval",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DlSpsIntval", HFILL }},


        { &hf_mu16ShDrxCycl ,
      	{ "mu16ShDrxCycl", "rrc_rlc_ctrl_sap.mu16ShDrxCycl",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16ShDrxCycl", HFILL }},


        { &hf_mu8PdcchSimLoadProp ,
      	{ "mu8PdcchSimLoadProp", "rrc_rlc_ctrl_sap.mu8PdcchSimLoadProp",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PdcchSimLoadProp", HFILL }},


        { &hf_mu16LDrxCyclStartOffsetType ,
      	{ "mu16LDrxCyclStartOffsetType", "rrc_rlc_ctrl_sap.mu16LDrxCyclStartOffsetType",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16LDrxCyclStartOffsetType", HFILL }},


        { &hf_mi8P0UePuschPersistent ,
      	{ "mi8P0UePuschPersistent", "rrc_rlc_ctrl_sap.mi8P0UePuschPersistent",
            FT_INT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi8P0UePuschPersistent", HFILL }},


        { &hf_mu8SrConfigIndex ,
      	{ "mu8SrConfigIndex", "rrc_rlc_ctrl_sap.mu8SrConfigIndex",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrConfigIndex", HFILL }},


        { &hf_mu8MacCfgExstFlag ,
      	{ "mu8MacCfgExstFlag", "rrc_rlc_ctrl_sap.mu8MacCfgExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8MacCfgExstFlag", HFILL }},


        { &hf_mu8FreqDomainPosition ,
      	{ "mu8FreqDomainPosition", "rrc_rlc_ctrl_sap.mu8FreqDomainPosition",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8FreqDomainPosition", HFILL }},


        { &hf_mu16UlBSD ,
      	{ "mu16UlBSD", "rrc_rlc_ctrl_sap.mu16UlBSD",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UlBSD", HFILL }},


        { &hf_ms16PucchSinrTarget ,
      	{ "ms16PucchSinrTarget", "rrc_rlc_ctrl_sap.ms16PucchSinrTarget",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.ms16PucchSinrTarget", HFILL }},


        { &hf_mu8PdschSimLoadProp ,
      	{ "mu8PdschSimLoadProp", "rrc_rlc_ctrl_sap.mu8PdschSimLoadProp",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PdschSimLoadProp", HFILL }},


        { &hf_mu8DrbId ,
      	{ "mu8DrbId", "rrc_rlc_ctrl_sap.mu8DrbId",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrbId", HFILL }},


        { &hf_mu8SecurityCtxFlag ,
      	{ "mu8SecurityCtxFlag", "rrc_rlc_ctrl_sap.mu8SecurityCtxFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SecurityCtxFlag", HFILL }},
        { &hf_mu32TeidSelf ,
      	{ "mu32TeidSelf", "rrc_rlc_ctrl_sap.mu32TeidSelf",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TeidSelf", HFILL }},


        { &hf_mu8Paddingsps ,
      	{ "mu8Paddingsps", "rrc_rlc_ctrl_sap.mu8Paddingsps",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Paddingsps", HFILL }},


        { &hf_mu32UlMaxRateL ,
      	{ "mu32UlMaxRateL", "rrc_rlc_ctrl_sap.mu32UlMaxRateL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlMaxRateL", HFILL }},


        { &hf_mu8RcpData ,
      	{ "mu8RcpData", "rrc_rlc_ctrl_sap.mu8RcpData",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RcpData", HFILL }},


        { &hf_mu32UlMaxRateH ,
      	{ "mu32UlMaxRateH", "rrc_rlc_ctrl_sap.mu32UlMaxRateH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlMaxRateH", HFILL }},


        { &hf_mu16ErabId ,
      	{ "mu16ErabId", "rrc_rlc_ctrl_sap.mu16ErabId",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16ErabId", HFILL }},


        { &hf_mu8DeltaMcsEnabled ,
      	{ "mu8DeltaMcsEnabled", "rrc_rlc_ctrl_sap.mu8DeltaMcsEnabled",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DeltaMcsEnabled", HFILL }},


        { &hf_mu8AccumulationEnabled ,
      	{ "mu8AccumulationEnabled", "rrc_rlc_ctrl_sap.mu8AccumulationEnabled",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8AccumulationEnabled", HFILL }},


        { &hf_mu16N1Pucch2 ,
      	{ "mu16N1Pucch2", "rrc_rlc_ctrl_sap.mu16N1Pucch2",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1Pucch2", HFILL }},


        { &hf_mu16N1Pucch1 ,
      	{ "mu16N1Pucch1", "rrc_rlc_ctrl_sap.mu16N1Pucch1",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16N1Pucch1", HFILL }},


        { &hf_mu16DrxInactvTimer ,
      	{ "mu16DrxInactvTimer", "rrc_rlc_ctrl_sap.mu16DrxInactvTimer",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DrxInactvTimer", HFILL }},


        { &hf_mu8NeedCnf ,
      	{ "mu8NeedCnf", "rrc_rlc_ctrl_sap.mu8NeedCnf",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8NeedCnf", HFILL }},


        { &hf_mu8DrbReleaseList ,
      	{ "mu8DrbReleaseList", "rrc_rlc_ctrl_sap.mu8DrbReleaseList",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrbReleaseList", HFILL }},


        { &hf_mu8SrProhibitTimerFlag ,
      	{ "mu8SrProhibitTimerFlag", "rrc_rlc_ctrl_sap.mu8SrProhibitTimerFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SrProhibitTimerFlag", HFILL }},


        { &hf_mu8TpcPucchRntiIdx ,
      	{ "mu8TpcPucchRntiIdx", "rrc_rlc_ctrl_sap.mu8TpcPucchRntiIdx",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TpcPucchRntiIdx", HFILL }},


        { &hf_mu8Padding1 ,
      	{ "mu8Padding1", "rrc_rlc_ctrl_sap.mu8Padding1",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Padding1", HFILL }},


        { &hf_mu8LchIdExistFlag ,
      	{ "mu8LchIdExistFlag", "rrc_rlc_ctrl_sap.mu8LchIdExistFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8LchIdExistFlag", HFILL }},


        { &hf_mu32UlAMBRL ,
      	{ "mu32UlAMBRL", "rrc_rlc_ctrl_sap.mu32UlAMBRL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UlAMBRL", HFILL }},


        { &hf_mu16ulSubframeOffsetOfn1Pucch ,
      	{ "mu16ulSubframeOffsetOfn1Pucch", "rrc_rlc_ctrl_sap.mu16ulSubframeOffsetOfn1Pucch",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16ulSubframeOffsetOfn1Pucch", HFILL }},


        { &hf_mu8GbrType ,
      	{ "mu8GbrType", "rrc_rlc_ctrl_sap.mu8GbrType",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8GbrType", HFILL }},


        { &hf_mu8CipheringRequired ,
      	{ "mu8CipheringRequired", "rrc_rlc_ctrl_sap.mu8CipheringRequired",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CipheringRequired", HFILL }},


        { &hf_mu8CqiRptFlag ,
      	{ "mu8CqiRptFlag", "rrc_rlc_ctrl_sap.mu8CqiRptFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CqiRptFlag", HFILL }},


        { &hf_mu32IpAddr ,
      	{ "mu32IpAddr", "rrc_rlc_ctrl_sap.mu32IpAddr",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32IpAddr", HFILL }},


        { &hf_mu32TaTimerVal ,
      	{ "mu32TaTimerVal", "rrc_rlc_ctrl_sap.mu32TaTimerVal",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TaTimerVal", HFILL }},


        { &hf_mu8GapOffset ,
      	{ "mu8GapOffset", "rrc_rlc_ctrl_sap.mu8GapOffset",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8GapOffset", HFILL }},


        { &hf_mu8MaxHARQTxFlag ,
      	{ "mu8MaxHARQTxFlag", "rrc_rlc_ctrl_sap.mu8MaxHARQTxFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8MaxHARQTxFlag", HFILL }},
        { &hf_mu8SimLoadFlag ,
      	{ "mu8SimLoadFlag", "rrc_rlc_ctrl_sap.mu8SimLoadFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SimLoadFlag", HFILL }},


        { &hf_mu16SrbListNum ,
      	{ "mu16SrbListNum", "rrc_rlc_ctrl_sap.mu16SrbListNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SrbListNum", HFILL }},


        { &hf_mu32DiscardTimerLen ,
      	{ "mu32DiscardTimerLen", "rrc_rlc_ctrl_sap.mu32DiscardTimerLen",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DiscardTimerLen", HFILL }},


        { &hf_mu32AgwTeid ,
      	{ "mu32AgwTeid", "rrc_rlc_ctrl_sap.mu32AgwTeid",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32AgwTeid", HFILL }},


        { &hf_mu16UeNum ,
      	{ "mu16UeNum", "rrc_rlc_ctrl_sap.mu16UeNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UeNum", HFILL }},


        { &hf_mu8TpcPuschRntiIdx ,
      	{ "mu8TpcPuschRntiIdx", "rrc_rlc_ctrl_sap.mu8TpcPuschRntiIdx",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TpcPuschRntiIdx", HFILL }},


        { &hf_mu8RbId ,
      	{ "mu8RbId", "rrc_rlc_ctrl_sap.mu8RbId",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RbId", HFILL }},


        { &hf_mu8DlSpsExstFlag ,
      	{ "mu8DlSpsExstFlag", "rrc_rlc_ctrl_sap.mu8DlSpsExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DlSpsExstFlag", HFILL }},


        { &hf_mu8RbList ,
      	{ "mu8RbList", "rrc_rlc_ctrl_sap.mu8RbList",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RbList", HFILL }},


        { &hf_mu8DedicatedRaPid ,
      	{ "mu8DedicatedRaPid", "rrc_rlc_ctrl_sap.mu8DedicatedRaPid",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DedicatedRaPid", HFILL }},


        { &hf_mu8UeCategory ,
      	{ "mu8UeCategory", "rrc_rlc_ctrl_sap.mu8UeCategory",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UeCategory", HFILL }},


        { &hf_mu32TReordering ,
      	{ "mu32TReordering", "rrc_rlc_ctrl_sap.mu32TReordering",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TReordering", HFILL }},


        { &hf_mu32UmPdcpSnSize ,
      	{ "mu32UmPdcpSnSize", "rrc_rlc_ctrl_sap.mu32UmPdcpSnSize",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32UmPdcpSnSize", HFILL }},


        { &hf_mu8UlSpsExstFlag ,
      	{ "mu8UlSpsExstFlag", "rrc_rlc_ctrl_sap.mu8UlSpsExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UlSpsExstFlag", HFILL }},
        { &hf_mu8IntCheckResult ,
      	{ "mu8IntCheckResult", "rrc_rlc_ctrl_sap.mu8IntCheckResult",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IntCheckResult", HFILL }},


        { &hf_mu8SimAckNack ,
      	{ "mu8SimAckNack", "rrc_rlc_ctrl_sap.mu8SimAckNack",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8SimAckNack", HFILL }},


        { &hf_mu16UlSpsIntval ,
      	{ "mu16UlSpsIntval", "rrc_rlc_ctrl_sap.mu16UlSpsIntval",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UlSpsIntval", HFILL }},


        { &hf_mu32MaxRetxThreshold ,
      	{ "mu32MaxRetxThreshold", "rrc_rlc_ctrl_sap.mu32MaxRetxThreshold",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32MaxRetxThreshold", HFILL }},


        { &hf_mu8TwoIntervalCfg ,
      	{ "mu8TwoIntervalCfg", "rrc_rlc_ctrl_sap.mu8TwoIntervalCfg",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TwoIntervalCfg", HFILL }},


        { &hf_mu8TpcCfgExstFlag ,
      	{ "mu8TpcCfgExstFlag", "rrc_rlc_ctrl_sap.mu8TpcCfgExstFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8TpcCfgExstFlag", HFILL }},


        { &hf_mu8CycShift ,
      	{ "mu8CycShift", "rrc_rlc_ctrl_sap.mu8CycShift",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CycShift", HFILL }},


        { &hf_mu16Result ,
      	{ "mu16Result", "rrc_rlc_ctrl_sap.mu16Result",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16Result", HFILL }},


        { &hf_mu32DlHfn ,
      	{ "mu32DlHfn", "rrc_rlc_ctrl_sap.mu32DlHfn",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlHfn", HFILL }},


        { &hf_mu8NomPdschRsEpreOffset ,
      	{ "mu8NomPdschRsEpreOffset", "rrc_rlc_ctrl_sap.mu8NomPdschRsEpreOffset",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8NomPdschRsEpreOffset", HFILL }},


        { &hf_mu8IsPucch3A ,
      	{ "mu8IsPucch3A", "rrc_rlc_ctrl_sap.mu8IsPucch3A",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IsPucch3A", HFILL }},


        { &hf_mu16Fms ,
      	{ "mu16Fms", "rrc_rlc_ctrl_sap.mu16Fms",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16Fms", HFILL }},


        { &hf_mu16SpsProcNum ,
      	{ "mu16SpsProcNum", "rrc_rlc_ctrl_sap.mu16SpsProcNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SpsProcNum", HFILL }},


        { &hf_mu8Padding ,
      	{ "mu8Padding", "rrc_rlc_ctrl_sap.mu8Padding",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Padding", HFILL }},


        { &hf_mu8Mode ,
      	{ "mu8Mode", "rrc_rlc_ctrl_sap.mu8Mode",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Mode", HFILL }},


        { &hf_dlPassLossChange ,
      	{ "dlPassLossChange", "rrc_rlc_ctrl_sap.dlPassLossChange",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.dlPassLossChange", HFILL }},


        { &hf_mu16RiCfgIdx ,
      	{ "mu16RiCfgIdx", "rrc_rlc_ctrl_sap.mu16RiCfgIdx",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16RiCfgIdx", HFILL }},


        { &hf_padding ,
      	{ "padding", "rrc_rlc_ctrl_sap.padding",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.padding", HFILL }},


        { &hf_mu8P0PersistentConfigFlag ,
      	{ "mu8P0PersistentConfigFlag", "rrc_rlc_ctrl_sap.mu8P0PersistentConfigFlag",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8P0PersistentConfigFlag", HFILL }},


        { &hf_mu8Bitmap ,
      	{ "mu8Bitmap", "rrc_rlc_ctrl_sap.mu8Bitmap",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Bitmap", HFILL }},


        { &hf_mu8MaxOutSyncTimes ,
      	{ "mu8MaxOutSyncTimes", "rrc_rlc_ctrl_sap.mu8MaxOutSyncTimes",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8MaxOutSyncTimes", HFILL }},


        { &hf_mi8P0UePusch ,
      	{ "mi8P0UePusch", "rrc_rlc_ctrl_sap.mi8P0UePusch",
            FT_INT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi8P0UePusch", HFILL }},


        { &hf_mu8Factor ,
      	{ "mu8Factor", "rrc_rlc_ctrl_sap.mu8Factor",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Factor", HFILL }},


        { &hf_mu16UeIndex ,
      	{ "mu16UeIndex", "rrc_rlc_ctrl_sap.mu16UeIndex",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16UeIndex", HFILL }},


        { &hf_mu16Flag ,
      	{ "mu16Flag", "rrc_rlc_ctrl_sap.mu16Flag",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16Flag", HFILL }},


        { &hf_mu8CfgExist ,
      	{ "mu8CfgExist", "rrc_rlc_ctrl_sap.mu8CfgExist",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CfgExist", HFILL }},


        { &hf_mu8CKcp ,
      	{ "mu8CKcp", "rrc_rlc_ctrl_sap.mu8CKcp",
            FT_BYTES, BASE_HEX, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8CKcp", HFILL }},


        { &hf_mu8DiscardTimerRequired ,
      	{ "mu8DiscardTimerRequired", "rrc_rlc_ctrl_sap.mu8DiscardTimerRequired",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DiscardTimerRequired", HFILL }},


        { &hf_mu32PollByte ,
      	{ "mu32PollByte", "rrc_rlc_ctrl_sap.mu32PollByte",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32PollByte", HFILL }},


        { &hf_periodicPhrTimer ,
      	{ "periodicPhrTimer", "rrc_rlc_ctrl_sap.periodicPhrTimer",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.periodicPhrTimer", HFILL }},


        { &hf_mu8IsPusch3A ,
      	{ "mu8IsPusch3A", "rrc_rlc_ctrl_sap.mu8IsPusch3A",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8IsPusch3A", HFILL }},


        { &hf_mu8RepetitionInd ,
      	{ "mu8RepetitionInd", "rrc_rlc_ctrl_sap.mu8RepetitionInd",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8RepetitionInd", HFILL }},


        { &hf_mu16SpsCrnti ,
      	{ "mu16SpsCrnti", "rrc_rlc_ctrl_sap.mu16SpsCrnti",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SpsCrnti", HFILL }},


        { &hf_mu8PSRSOffset ,
      	{ "mu8PSRSOffset", "rrc_rlc_ctrl_sap.mu8PSRSOffset",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8PSRSOffset", HFILL }},


        { &hf_mu32DlMaxRateH ,
      	{ "mu32DlMaxRateH", "rrc_rlc_ctrl_sap.mu32DlMaxRateH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlMaxRateH", HFILL }},


        { &hf_mu8Padding4 ,
      	{ "mu8Padding4", "rrc_rlc_ctrl_sap.mu8Padding4",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Padding4", HFILL }},


        { &hf_mu32DlMaxRateL ,
      	{ "mu32DlMaxRateL", "rrc_rlc_ctrl_sap.mu32DlMaxRateL",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlMaxRateL", HFILL }},


        { &hf_mu16DrbListNum ,
      	{ "mu16DrbListNum", "rrc_rlc_ctrl_sap.mu16DrbListNum",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16DrbListNum", HFILL }},


        { &hf_mu16T310TimerPeriod ,
      	{ "mu16T310TimerPeriod", "rrc_rlc_ctrl_sap.mu16T310TimerPeriod",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16T310TimerPeriod", HFILL }},


        { &hf_mu8FilterCoefficient ,
      	{ "mu8FilterCoefficient", "rrc_rlc_ctrl_sap.mu8FilterCoefficient",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8FilterCoefficient", HFILL }},


        { &hf_mu8MaxHarqTxNum ,
      	{ "mu8MaxHarqTxNum", "rrc_rlc_ctrl_sap.mu8MaxHarqTxNum",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8MaxHarqTxNum", HFILL }},


        { &hf_mu8Location ,
      	{ "mu8Location", "rrc_rlc_ctrl_sap.mu8Location",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8Location", HFILL }},


        { &hf_mu16SrPucchResourceIndex ,
      	{ "mu16SrPucchResourceIndex", "rrc_rlc_ctrl_sap.mu16SrPucchResourceIndex",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16SrPucchResourceIndex", HFILL }},


        { &hf_mu8ServiceType ,
      	{ "mu8ServiceType", "rrc_rlc_ctrl_sap.mu8ServiceType",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8ServiceType", HFILL }},


        { &hf_mu16TpcPucchRnti ,
      	{ "mu16TpcPucchRnti", "rrc_rlc_ctrl_sap.mu16TpcPucchRnti",
            FT_UINT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu16TpcPucchRnti", HFILL }},


        { &hf_mu32TPollRetransmit ,
      	{ "mu32TPollRetransmit", "rrc_rlc_ctrl_sap.mu32TPollRetransmit",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TPollRetransmit", HFILL }},


        { &hf_mu32TStatusProhibit ,
      	{ "mu32TStatusProhibit", "rrc_rlc_ctrl_sap.mu32TStatusProhibit",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32TStatusProhibit", HFILL }},


        { &hf_mi8P0UePucch ,
      	{ "mi8P0UePucch", "rrc_rlc_ctrl_sap.mi8P0UePucch",
            FT_INT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi8P0UePucch", HFILL }},


        { &hf_mu32DlAMBRH ,
      	{ "mu32DlAMBRH", "rrc_rlc_ctrl_sap.mu32DlAMBRH",
            FT_UINT32, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu32DlAMBRH", HFILL }},


        { &hf_mu8DrbReleaseNum ,
      	{ "mu8DrbReleaseNum", "rrc_rlc_ctrl_sap.mu8DrbReleaseNum",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8DrbReleaseNum", HFILL }},


        { &hf_ms16PuschSinrTarget ,
      	{ "ms16PuschSinrTarget", "rrc_rlc_ctrl_sap.ms16PuschSinrTarget",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.ms16PuschSinrTarget", HFILL }},


        { &hf_mu8UeTxAntSelect ,
      	{ "mu8UeTxAntSelect", "rrc_rlc_ctrl_sap.mu8UeTxAntSelect",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mu8UeTxAntSelect", HFILL }},


        { &hf_padding1 ,
      	{ "padding1", "rrc_rlc_ctrl_sap.padding1",
            FT_UINT8, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.padding1", HFILL }},


        { &hf_mi16P0NominalPuschPersistent ,
      	{ "mi16P0NominalPuschPersistent", "rrc_rlc_ctrl_sap.mi16P0NominalPuschPersistent",
            FT_INT16, BASE_DEC, NULL, 0,
            "rrc_rlc_ctrl_sap.mi16P0NominalPuschPersistent", HFILL }},


	{ &hf_result,
  		{ "result", "rrc_rlc_ctrl_sap.result",
    		FT_UINT16, BASE_DEC, NULL, 0,
    			"rrc_rlc_ctrl_sap.result", HFILL }},
			
		{ &hf_u16CellUeIndex ,
		{ "u16CellUeIndex", "rrc_rlc_ctrl_sap.u16CellUeIndex",
			FT_INT16, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u16CellUeIndex", HFILL }},
			
		{ &hf_u32TStatusProhibit ,
		{ "u32TStatusProhibit", "rrc_rlc_ctrl_sap.u32TStatusProhibit",
			FT_UINT32, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u32TStatusProhibit", HFILL }},
			
		{ &hf_u32TPollRetransmit ,
		{ "u32TPollRetransmit", "rrc_rlc_ctrl_sap.u32TPollRetransmit",
			FT_UINT32, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u32TPollRetransmit", HFILL }},
		
		{ &hf_u32PollPdu ,
		{ "u32PollPdu", "rrc_rlc_ctrl_sap.u32PollPdu",
			FT_UINT32, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u32PollPdu", HFILL }},

		{ &hf_u32PollByte ,
		{ "u32PollByte", "rrc_rlc_ctrl_sap.u32PollByte",
			FT_UINT32, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u32PollByte", HFILL }},

		{ &hf_u32MaxRetxThreshold ,
		{ "u32MaxRetxThreshold", "rrc_rlc_ctrl_sap.u32MaxRetxThreshold",
			FT_UINT32, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u32MaxRetxThreshold", HFILL }},

		
		{ &hf_u8RbIdforReEstb ,
		{ "u8RbIdforReEstb", "rrc_rlc_ctrl_sap.u8RbIdforReEstb",
			FT_UINT8, BASE_DEC, NULL, 0,
			"rrc_rlc_ctrl_sap.u8RbIdforReEstb", HFILL }},

    };
    
    gint* ett[] = {
       &ett_rrc_rlc_ctrl_sap,
       &ett_RcpMacMacMainCfgType,
       &ett_RcpGtpuErabReCfgInfoType,
       &ett_RcpGtpuErabReCfgInfoTypeList,
       &ett_RcpMacPucchCfgType,
       &ett_RcpMacSrbToAddlstType,
       &ett_RcpMacSrbToAddlstTypeList,
       &ett_RcpMacCqiFormatIndPeriodicType,
       &ett_RcpMacP0PersistentType,
       &ett_IPADDR,
       &ett_RcpMacAcknackRepetitionType,
       &ett_RcpMacUlspsCfgType,
       &ett_RcpUpMacMeasCfgType,
       &ett_RcpMacDrxCfgType,
       &ett_RcpMacLdrxCyclStartOffsetType,
       &ett_RcpMacSpsCfgType,
       &ett_RcpMacP0CfgType,
       &ett_RcpMacLchCfgType,
       &ett_RcpMacSchedulingRequestCfgType,
       &ett_RcpMacIfCqiRptPeriodicType,
       &ett_RcpMacUlsrsCfgType,
       &ett_RcpPdcpHeaderCompressionConfigInfoType,
       &ett_RcpPdcpDrbCfgListType,
       &ett_RcpPdcpDrbCfgListTypeList,
       &ett_RcpPdcpDiscardTimerConfigInfoType,
       &ett_RcpMacShortDrxType,
       &ett_RcpMacTpcCfgType,
       &ett_RcpMacDrbToRlsType,
       &ett_RohcProfiles,
       &ett_RohcProfilesList,
       &ett_RcpRlcRbAddOrModifyListType,
       &ett_RcpRlcRbAddOrModifyListTypeList,
       &ett_RcpMacCqiRptPeriodType,
       &ett_RcpGtpuErabCfgInfoType,
       &ett_RcpGtpuErabCfgInfoTypeList,
       &ett_RcpMacAntennaInfoType,
       &ett_RcpMacPhrConfigurationType,
       &ett_RcpPdcpIntegrityConfigInfoType,
       &ett_RcpRlcAmCfgType,
       &ett_RcpPdcpCipheringConfigInfoType,
       &ett_RcpPdcpRbSnStatusListType,
       &ett_RcpPdcpRbSnStatusListTypeList,
       &ett_RcpMacDlspsCfgType,
       &ett_RcpRlcUmRxCfgType,
       &ett_u_2,
       &ett_u_1,
       &ett_RcpMacDrbToAddlstType,
       &ett_RcpMacDrbToAddlstTypeList,
       &ett_RcpRlcUmBiCfgType,
       &ett_RcpRlcUmTxCfgType,

    };
    
    proto_rrc_rlc_ctrl_sap = proto_register_protocol(rrc_rlc_ctrl_proto_name, rrc_rlc_ctrl_proto_name_short, "rrc_rlc_ctrl");
    
    register_dissector("rrc_rlc_ctrl_sap", dissect_rrc_rlc_ctrl_sap, proto_rrc_rlc_ctrl_sap);
	
    proto_register_field_array(proto_rrc_rlc_ctrl_sap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
}

void
proto_reg_handoff_rrc_rlc_ctrl_sap(void)
{
    rrc_rlc_ctrl_handle = find_dissector("rrc_rlc_ctrl_sap");
}

