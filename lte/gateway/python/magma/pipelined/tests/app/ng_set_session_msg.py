"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
import threading
import subprocess
from enum import Enum
from collections import namedtuple
from concurrent.futures import Future

from magma.subscriberdb.sid import SIDUtils
from magma.pipelined.policy_converters import flow_match_to_magma_match, \
            convert_ipv4_str_to_ip_proto
from lte.protos.policydb_pb2 import FlowMatch, FlowDescription, PolicyRule
from lte.protos.session_manager_pb2 import NodeID
from lte.protos.pipelined_pb2 import (
    SessionSet,
    SetGroupFAR,
    FwdParam,
    Action,
    OuterHeaderCreation,
    SetGroupPDR,
    PDI,
    Fsm_state,
    PdrState,
    ActivateFlowsRequest,
    DeactivateFlowsRequest,
    RuleModResult,
    RequestOriginType,
)

from magma.pipelined.ng_manager.session_state_manager_util import FARRuleEntry
QoSEnforceRuleEntry = namedtuple(
                         'QoSEnforceRuleEntry',
                         ['imsi', 'rule_id', 'ipv4_dst', 'allow', 'priority', 'hard_timeout', 'direction'])


class CreateSessionUtil:

    def __init__(self, subscriber_id:str, local_f_teid:int, session_version, node_id="192.168.220.1"):
        self._set_session = \
                  SessionSet(subscriber_id=subscriber_id, local_f_teid=local_f_teid,\
                             session_version=session_version,\
                             node_id=NodeID(node_id_type=NodeID.IPv4, node_id=node_id),\
                             state=Fsm_state(state=Fsm_state.CREATED))


    def CreateAddQERinPDR(self, qos_enforce_rule: QoSEnforceRuleEntry,
                          ue_ip_addr: str) -> ActivateFlowsRequest:
                                                    
        if qos_enforce_rule.allow == 'YES':
           allow = FlowDescription.PERMIT
        else:
           allow = FlowDescription.DENY

        ip_dst=None
        ip_src=None

        if qos_enforce_rule.ipv4_dst:
            ip_dst=convert_ipv4_str_to_ip_proto(qos_enforce_rule.ipv4_dst)
            ip_src=convert_ipv4_str_to_ip_proto(qos_enforce_rule.ipv4_dst)

        if qos_enforce_rule.direction == FlowMatch.UPLINK:
            flow_list =  [FlowDescription(match=FlowMatch(
                                          ip_dst=ip_dst,
                                          direction=qos_enforce_rule.direction),
                                          action=allow)]
        else:
            flow_list =  [FlowDescription(match=FlowMatch(
                                          ip_src=ip_src,
                                          direction=qos_enforce_rule.direction),
                                          action=allow)]


        qos_enforce_rule = ActivateFlowsRequest(
                                  sid=SIDUtils.to_pb(qos_enforce_rule.imsi),
                                  ip_addr=ue_ip_addr,
                                  dynamic_rules=[PolicyRule(
                                  id=qos_enforce_rule.rule_id,
                                  priority=qos_enforce_rule.priority,
                                  hard_timeout=qos_enforce_rule.hard_timeout,
                                  flow_list=flow_list
                                )],
                                request_origin=RequestOriginType(type=RequestOriginType.N4))
        return  qos_enforce_rule

    def CreateDelQERinPDR(self, qos_enforce_rule: QoSEnforceRuleEntry,
                          ue_ip_addr: str) -> DeactivateFlowsRequest:

        qos_enforce_rule = DeactivateFlowsRequest(
                                  sid=SIDUtils.to_pb(qos_enforce_rule.imsi),
                                  ip_addr=ue_ip_addr,
                                  rule_ids=[qos_enforce_rule.rule_id],
                                  request_origin=RequestOriginType(type=RequestOriginType.N4))

        return  qos_enforce_rule


    def CreateFARinPDR(self, o_teid:int=0, gnb_ip_addr:str='') -> FARRuleEntry:
        #Create the out-channel towards GNB
        if o_teid != 0:
            # For pdr_id=2 towards access
            return SetGroupFAR(far_action_to_apply=[Action.Value('FORW')],
                               fwd_parm=FwdParam(dest_iface=0, 
                                                 outr_head_cr=OuterHeaderCreation(
                                                              o_teid=o_teid, gnb_ipv4_adr=gnb_ip_addr)))

        return SetGroupFAR(far_action_to_apply=[Action.Value('FORW')])

    def CreatePDR(self, pdr_id:int, pdr_version:int, pdr_state,
                  precedence:int, local_f_teid:int, ue_ip_addr:str) -> SetGroupPDR:

        if local_f_teid != 0:
            return SetGroupPDR(pdr_id=pdr_id, pdr_version=pdr_version,
                               pdr_state=pdr_state,\
                               precedence=precedence,\
                               pdi=PDI(src_interface=0,\
                                       local_f_teid=local_f_teid,\
                                       ue_ip_adr=ue_ip_addr), \
                                       o_h_remo_desc=0)
        
        return SetGroupPDR(pdr_id=pdr_id, pdr_version=pdr_version,
                           pdr_state=pdr_state,\
                           precedence=precedence,\
                           pdi=PDI(src_interface=1, ue_ip_adr=ue_ip_addr))


    def CreateSessionMsg(self, imsi_val:str, pdr_entry: SetGroupPDR, far_entry: SetGroupFAR=None,
                         del_qos_enforce_rule: DeactivateFlowsRequest = None, 
                         add_qos_enforce_rule: ActivateFlowsRequest = None):

        if far_entry: 
            pdr_entry.set_gr_far.CopyFrom(far_entry)

        if del_qos_enforce_rule:
            pdr_entry.deactivate_flow_req.CopyFrom(del_qos_enforce_rule)

        if add_qos_enforce_rule:
            pdr_entry.activate_flow_req.CopyFrom(add_qos_enforce_rule)

        self._set_session.set_gr_pdr.extend([pdr_entry])

    def CreateSession(self, imsi_val:str, pdr_state:str="ADD", in_teid:int=0,
                      out_teid:int = 0, ue_ip_addr:str = "", gnb_ip_addr:str = "",
                      del_rule_id:str = '', add_rule_id:str = '', ipv4_dst:str = None, allow:str = "YES",
                      priority:int=10, hard_timeout:int=0):

        pdr_id = 1

        del_qer_enforcer = None
        uplink_qer_enforcer = None
        downlink_qer_enforcer = None
        uplink_pdr = None
        downlink_pdr = None

        if del_rule_id:
            del_qer_tuple = QoSEnforceRuleEntry(imsi_val, del_rule_id, None,
                                                   None, None, None, None)

            del_qer_enforcer = self.CreateDelQERinPDR(del_qer_tuple, ue_ip_addr)

        if add_rule_id:
            uplink_qer_tuple = QoSEnforceRuleEntry(imsi_val, add_rule_id, ipv4_dst,
                                                   allow, priority, hard_timeout,
                                                   FlowMatch.UPLINK)
            uplink_qer_enforcer = self.CreateAddQERinPDR(uplink_qer_tuple, ue_ip_addr)

            downlink_qer_tuple = QoSEnforceRuleEntry(imsi_val, add_rule_id, ipv4_dst,
                                                     allow, priority, hard_timeout,
                                                     FlowMatch.DOWNLINK)

            downlink_qer_enforcer = self.CreateAddQERinPDR(downlink_qer_tuple, ue_ip_addr)

        uplink_far = self.CreateFARinPDR(0, '')     
        downlink_far = self.CreateFARinPDR(out_teid, gnb_ip_addr)  

        if pdr_state == "ADD":
            uplink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('INSTALL'), 32, in_teid, ue_ip_addr)
            pdr_id = pdr_id + 1
            downlink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('INSTALL'), 32, 0, ue_ip_addr)
        elif pdr_state == "IDLE":
            uplink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('IDLE'), 32, in_teid, ue_ip_addr)
            pdr_id = pdr_id + 1
            downlink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('IDLE'), 32, 0, ue_ip_addr)
        else:
            uplink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('REMOVE'), 32, in_teid, ue_ip_addr)
            pdr_id = pdr_id + 1
            downlink_pdr = self.CreatePDR(pdr_id, 1, PdrState.Value('REMOVE'), 32, 0, ue_ip_addr)

        self.CreateSessionMsg(imsi_val, uplink_pdr, uplink_far, del_qer_enforcer, uplink_qer_enforcer) 
        self.CreateSessionMsg(imsi_val, downlink_pdr, downlink_far, del_qer_enforcer, downlink_qer_enforcer)
