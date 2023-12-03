# coding=utf-8
# 13SRAM 2TCAM
"""
    Date:    2023/05/11
"""

import os
import sys
import glob
import signal
import logging

# Add BF Python to search path, only in SDE 9.2
bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    os.environ['SDE_INSTALL'])

sys.path.append(glob.glob(bfrt_location)[0])

import bfrt_grpc.client as gc

PROGRAM_NAME = "double_pipe"

class StrMatchCtrl(object):
    def __init__(self):
        super(StrMatchCtrl, self).__init__()
        self.dev = None
        self.target = None
        self.interface = None
        self.bfrt_info = None
        self.data_file_handlers = {}
        logging.basicConfig(level=logging.INFO)
        self.log = logging.getLogger(PROGRAM_NAME)
        self.verify_priority = 0
        self.log.info('StrMatchCtrl init.....')

    def critical_error(self, msg):
        self.log.critical(msg)
        print msg
        logging.shutdown()
        self.close_all()
        # sys.exit(1)
        os.kill(os.getpid(), signal.SIGTERM)

    def setup(self,
              program,
              bfrt_ip,
              bfrt_port):
        self.dev = 0  
        self.target = gc.Target(self.dev, pipe_id=0xffff)  

        try:
            self.interface = gc.ClientInterface('{}:{}'.format(bfrt_ip, bfrt_port),
                                                client_id=0,
                                                device_id=self.dev)
        except RuntimeError as re:
            msg = re.args[0] % re.args[1]
            self.critical_error(msg)
        else:
            self.log.info('Connected to BFRT server {}:{}'.format(
                bfrt_ip, bfrt_port))


        try:
            self.interface.bind_pipeline_config(program)
        except gc.BfruntimeForwardingRpcException:
            self.critical_error('P4 program {} not found!'.format(program))
        try:
            self.bfrt_info = self.interface.bfrt_info_get(program)
        except gc.BfruntimeReadWriteRpcException:
            self.critical_error(
                'Error while setting ports in loopback mode. \
                If the switch has only 2 pipes, the folded pipeline cannot be enabled.'
            )


    def _close_grpc_conn(self):
        self.interface.channel.close()

    def _close_file_handlers(self):
        for handler in self.data_file_handlers.itervalues():
            handler.close()
        self.data_file_handlers.clear()

    def close_all(self):
        self._close_file_handlers()
        self._close_grpc_conn()

    def read_timestamp(self):
        # ======================read first packet timestamp=====================================
        first_filter_ingress_register = self.bfrt_info.table_get("pipeline_profile_filter.Ingress_filter.first_filter_ingress_time_reg")
        first_verify_ingress_register = self.bfrt_info.table_get("pipeline_profile_verifier.Ingress_verifier.first_verify_ingress_time_reg")
        first_verify_egress_register = self.bfrt_info.table_get("pipeline_profile_verifier.Egress_verifier.first_verify_egress_time_reg")
        
        first_filter_ingress_timestamp = first_filter_ingress_register.entry_get(
            self.target,
            [first_filter_ingress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})
        first_verify_ingress_timestamp = first_verify_ingress_register.entry_get(
            self.target,
            [first_verify_ingress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})
        first_verify_egress_timestamp = first_verify_egress_register.entry_get(
            self.target,
            [first_verify_egress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})

        first_filter_ingress_timestamp_data, _ = next(first_filter_ingress_timestamp)
        first_filter_ingress_timestamp_data_dict = first_filter_ingress_timestamp_data.to_dict()

        first_verify_ingress_timestamp_data, _ = next(first_verify_ingress_timestamp)
        first_verify_ingress_timestamp_data_dict = first_verify_ingress_timestamp_data.to_dict()

        first_verify_egress_timestamp_data, _ = next(first_verify_egress_timestamp)
        first_verify_egress_timestamp_data_dict = first_verify_egress_timestamp_data.to_dict()

        first_filter_ingress_timestamp_ns = first_filter_ingress_timestamp_data_dict['Ingress_filter.first_filter_ingress_time_reg.f1'][0]
        first_verify_ingress_timestamp_ns = first_verify_ingress_timestamp_data_dict['Ingress_verifier.first_verify_ingress_time_reg.f1'][0]
        first_verify_egress_timestamp_ns = first_verify_egress_timestamp_data_dict['Egress_verifier.first_verify_egress_time_reg.f1'][0]
        
        # ======================read last packet timestamp=====================================

        last_filter_ingress_register = self.bfrt_info.table_get("pipeline_profile_filter.Ingress_filter.last_filter_ingress_time_reg")
        last_verify_ingress_register = self.bfrt_info.table_get("pipeline_profile_verifier.Ingress_verifier.last_verify_ingress_time_reg")
        last_verify_egress_register = self.bfrt_info.table_get("pipeline_profile_verifier.Egress_verifier.last_verify_egress_time_reg")
        
        last_filter_ingress_timestamp = last_filter_ingress_register.entry_get(
            self.target,
            [last_filter_ingress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})
        last_verify_ingress_timestamp = last_verify_ingress_register.entry_get(
            self.target,
            [last_verify_ingress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})
        last_verify_egress_timestamp = last_verify_egress_register.entry_get(
            self.target,
            [last_verify_egress_register.make_key([gc.KeyTuple('$REGISTER_INDEX', 0)])],
            {"from_hw": True})

        last_filter_ingress_timestamp_data, _ = next(last_filter_ingress_timestamp)
        last_filter_ingress_timestamp_data_dict = last_filter_ingress_timestamp_data.to_dict()

        last_verify_ingress_timestamp_data, _ = next(last_verify_ingress_timestamp)
        last_verify_ingress_timestamp_data_dict = last_verify_ingress_timestamp_data.to_dict()

        last_verify_egress_timestamp_data, _ = next(last_verify_egress_timestamp)
        last_verify_egress_timestamp_data_dict = last_verify_egress_timestamp_data.to_dict()

        last_filter_ingress_timestamp_ns = last_filter_ingress_timestamp_data_dict['Ingress_filter.last_filter_ingress_time_reg.f1'][0]
        last_verify_ingress_timestamp_ns = last_verify_ingress_timestamp_data_dict['Ingress_verifier.last_verify_ingress_time_reg.f1'][0]
        last_verify_egress_timestamp_ns = last_verify_egress_timestamp_data_dict['Egress_verifier.last_verify_egress_time_reg.f1'][0]

        self.log.info('======================first packet timestamp=====================================')
        self.log.info('first filter ingress timestamp: {}(ns)'.format(first_filter_ingress_timestamp_ns))
        self.log.info('first verify ingress timestamp: {}(ns)'.format(first_verify_ingress_timestamp_ns))
        self.log.info('first verify egress timestamp: {}(ns)'.format(first_verify_egress_timestamp_ns))
        
        self.log.info('======================last packet timestamp=====================================')
        self.log.info('last filter ingress timestamp: {}(ns)'.format(last_filter_ingress_timestamp_ns))
        self.log.info('last verify ingress timestamp: {}(ns)'.format(last_verify_ingress_timestamp_ns))
        self.log.info('last verify egress timestamp: {}(ns)'.format(last_verify_egress_timestamp_ns))

        self.log.info('time is: {}'.format(str((int(last_verify_egress_timestamp_ns) - int(first_filter_ingress_timestamp_ns)))) )
        # self.log.info('last verify ingress - first filter ingress time(s): {}'.format(str((int(last_verify_ingress_timestamp_ns) - int(first_filter_ingress_timestamp_ns)) / 1e9)))
        # self.log.info('last verify ingress - first filter ingress time(ns): {}'.format(str((int(last_verify_ingress_timestamp_ns) - int(first_filter_ingress_timestamp_ns)))))
        
        # self.log.info('verify ingress - filter ingress time: {}s'.format(str((int(verify_ingress_timestamp_ns) - int(filter_ingress_timestamp_ns)) / 1e9)))
        # self.log.info('verify ingress - filter ingress time: {}ns'.format(str((int(verify_ingress_timestamp_ns) - int(filter_ingress_timestamp_ns)))))

        # self.log.info('verify egress - filter ingress time: {}s'.format(str((int(verify_egress_timestamp_ns) - int(filter_ingress_timestamp_ns)) / 1e9)))
        # self.log.info('verify egress - filter ingress time: {}ns'.format(str((int(verify_egress_timestamp_ns) - int(filter_ingress_timestamp_ns)))))

        # self.log.info('filter_ingress_timestamp: {}'.format(filter_ingress_timestamp_data_dict))
        # self.log.info('verify_ingress_timestamp: {}'.format(verify_ingress_timestamp_data_dict))
        # self.log.info('verify_egress_timestamp: {}'.format(verify_egress_timestamp_data_dict))
        

if __name__ == '__main__':
    a = StrMatchCtrl()
    try:
        a.setup(PROGRAM_NAME, "localhost", 50052)
        a.read_timestamp()
        a.close_all()
    except gc.BfruntimeReadWriteRpcException as e:
        print e
        a.close_all()
    except Exception as e:
        print e
        a.close_all()
