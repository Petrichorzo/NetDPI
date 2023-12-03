import os
import sys
import glob
import signal
import logging

from gen_ac_entries import ac_list
from gen_mask import sh_mask_dic

#bfrt_location = '{}/lib/python*/site-packages/tofino'.format(
    #os.environ['SDE_INSTALL'])

sys.path.append(glob.glob("/root/bf-sde-9.2.0/install/lib/python*/site-packages/tofino")[0])

PROGRAM_NAME = "double_pipe"
FILTER_DATA_FILE_NAME_PREFIX = "sh_mask_shift_{}.txt"
FILTER_TABLE_NAME_PREFIX = "pipeline_profile_filter.Ingress_filter.filter_win{}_{}"
FILTER_KEY_NAME_PREFIX = "hdr.patrns.p{}"
FILTER_ACTION_NAME_PREFIX = "or{}_{}"
FILTER_ACTION_PARAMS_NAME1 = "mask_high1"
FILTER_ACTION_PARAMS_NAME2 = "mask_low1"
SETMAP_TABLE_NAME_PREFIX = "pipeline_profile_filter.Ingress_filter.set_map{}"
TABLE_NUM_PER_STAGE = 15
FILTER_STAGE_NUM = 8
PIPEID = 0
import bfrt_grpc.client as gc

def _get_setmap_data():
    data_dict = {}
    file_path = os.path.join(".", "/root/bf-sde-9.2.0/filter/backend/smap.txt")
    with open(file_path, "r") as f:
        for line in f.readlines():
            line = line.strip()
            tmp = line.split(",")
            key = int(tmp[0], base=16)
            mask = int(tmp[1], base=16)
            priority = int(tmp[2])
            action_data = int(tmp[3], base=2)
            data_dict[key] = [mask, priority, action_data]
    return data_dict


def _get_filter_table_name(stage_number, count):
    return FILTER_TABLE_NAME_PREFIX.format(count, stage_number)
    
    
def _get_setmap_table_name(num):
    return SETMAP_TABLE_NAME_PREFIX.format(num)
    
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
        self._close_grpc_conn()
        self._close_file_handlers()

    def _get_filter_key_name(self, stage_number, count):
        return FILTER_KEY_NAME_PREFIX.format((count - 1) * 8 + stage_number)

    def _get_filter_table_name(self, stage_number, count):
        return FILTER_TABLE_NAME_PREFIX.format(count, stage_number)

    def _get_filter_action_name(self, stage_number, count):
        return FILTER_ACTION_NAME_PREFIX.format(count, stage_number)

    def _get_filter_table_data(self, stage_num):
        file_name = "sh_mask_shift_{}".format(stage_num * 4 - 4)
        file_handler = sh_mask_dic[file_name]
        data_dict = {}
        for line in file_handler:
            tmp = line.split(",")
            key = int(tmp[0])
            value1 = int(tmp[1], base=2)
            value2 = int(tmp[2], base=2)
            data_dict[key] = (value1, value2)
        return data_dict

    def add_filter_tables(self):
        for stage in range(1, FILTER_STAGE_NUM + 1):
            data = self._get_filter_table_data(stage)
            for table_num in range(1, TABLE_NUM_PER_STAGE + 1):
                if15 = None
                if table_num == TABLE_NUM_PER_STAGE:
                    if15 = True
                else:
                    if15 = False
                table_name = self._get_filter_table_name(stage, table_num)
                key_name = self._get_filter_key_name(stage, table_num)
                action_name = self._get_filter_action_name(stage, table_num)
                self._add_filter_table_entries(table_name, key_name, action_name, data, if15=if15)
        self.log.info("Finish filter table adding...")

    def _add_filter_table_entries(self, table_name, key_name, action_name, entries, if15=False):
        table_opt = self.bfrt_info.table_get(table_name)
        self.log.info("Begin to Add entries for table {}".format(table_name))
        key_list = []
        data_list = []
        for key, values in entries.iteritems():
            value1, value2 = values
            key_list.append(table_opt.make_key([gc.KeyTuple(name=key_name, value=key)]))
            if if15:
                data_list.append(
                    table_opt.make_data(data_field_list_in=[gc.DataTuple(name=FILTER_ACTION_PARAMS_NAME2, val=value2)],
                                        action_name=action_name))
            else:
                data_list.append(
                    table_opt.make_data(data_field_list_in=[gc.DataTuple(name=FILTER_ACTION_PARAMS_NAME1, val=value1),
                                                            gc.DataTuple(name=FILTER_ACTION_PARAMS_NAME2, val=value2)],
                                        action_name=action_name))
        table_opt.entry_add(self.target, key_list, data_list)
        self.log.info("Add {} entries to table {}".format(len(key_list), table_name))

    def add_setmap_tables(self):
        data = _get_setmap_data()
        for num in range(1, 15 + 1):
            table_name = "pipeline_profile_filter.Ingress_filter.set_map{}".format(num)
            key_name = "meta.st_mask{}_low1".format(num)
            action_name = "set_b{}".format(num)
            self._add_setmap_entries(table_name, key_name, action_name, data)
        self.log.info("Finish setmap table adding...")

    def _add_setmap_entries(self, table_name, key_name, action_name, entries):
        table_opt = self.bfrt_info.table_get(table_name)
        key_list = []
        data_list = []
        for key, values in entries.iteritems():
            mask = values[0]
            priority = values[1]
            action_value = values[2]
            key_list.append(
                table_opt.make_key(
                    [gc.KeyTuple(key_name, value=key, mask=mask), gc.KeyTuple("$MATCH_PRIORITY", value=priority)]))
            data_list.append(
                table_opt.make_data([gc.DataTuple(name="b", val=action_value)],
                                    action_name=action_name))
        table_opt.entry_add(self.target, key_list, data_list)
        self.log.info("Add {0} entries to table {1}".format(len(key_list), table_name))


    def _get_verify_data(self):
        data_dict = {}
        for line in ac_list:
            tmp = line.split(",")
            if tmp[0] not in data_dict:
                data_dict[tmp[0]] = []
                data_dict[tmp[0]].append([tmp[1], tmp[2], tmp[3]])
            else:
                data_dict[tmp[0]].append([tmp[1], tmp[2], tmp[3]])
        return data_dict
        # with open(file_path, "r") as f:
        #     for line in f.readlines():
        #         line = line.strip()
        #         tmp = line.split(",")
        #         if tmp[0] not in data_dict:
        #             data_dict[tmp[0]] = []
        #             data_dict[tmp[0]].append([tmp[1], tmp[2], tmp[3]])
        #         else:
        #             data_dict[tmp[0]].append([tmp[1], tmp[2], tmp[3]])


    def add_verify_tables(self):
        data = self._get_verify_data()
        for stage in range(1, 8 + 1):
            for table_num in range(1, 9):
                if stage == 8 and table_num == 1:
                    table_name = "win1_8"
                    key_name1 = "hdr.p1.p"
                    key_name2 = "meta.state1"
                    action_name = "match1_8"
                    stage_name = "stage_{}".format(stage)
                    self._add_vefify_table_entries_SRAM(table_name, key_name1, key_name2, action_name, stage_name, data)
                else:
                    table_name = "win{0}_{1}".format(table_num, stage)
                    key_name1 = "hdr.patrns.p{}".format(table_num * 8 - stage + 1)
                    key_name2 = "meta.state{}".format(table_num)
                    action_name = "match{0}_{1}".format(table_num, stage)
                    stage_name = "stage_{}".format(stage)
                    self._add_vefify_table_entries_SRAM(table_name, key_name1, key_name2, action_name, stage_name, data)
            # tcam win9_1,win10_1...win15_1
            # for table_num in range(14, 16):
            #     table_name = "win{0}_{1}".format(table_num, stage)
            #     key_name1 = "hdr.patrns.p{}".format(table_num * 8 - stage + 1)
            #     key_name2 = "meta.state{}".format(table_num)
            #     action_name = "match{}_{}".format(table_num, stage)
            #     stage_name = "stage_{}".format(stage)
            #     self._add_vefify_table_entries_TCAM(table_name, key_name1, key_name2, action_name, stage_name, data)


    def _add_vefify_table_entries_SRAM(self, table_name, key_name1, key_name2, action_name, stage_name, entries):
        table_opt = self.bfrt_info.table_get(table_name)
        self.log.info("Begin to Add entries for table {}".format(table_name))
        key_list = []
        data_list = []
        for key, values in entries.iteritems():
            if key == stage_name:
                for value in values:
                    value1 = value[0]
                    value2 = value[1]
                    value3 = value[2]
                    key_list.append(table_opt.make_key([gc.KeyTuple(name=key_name1, value=int(value2, 16)),
                                                        gc.KeyTuple(name=key_name2, value=int(value1, 10))]))
                    data_list.append(table_opt.make_data(data_field_list_in=[gc.DataTuple(name="state", val=int(value3, 10))],
                                                         action_name=action_name))

        table_opt.entry_add(self.target, key_list, data_list)
        self.log.info("Add {} entries to table {}".format(len(key_list), table_name))

    def _add_vefify_table_entries_TCAM(self, table_name, key_name1, key_name2, action_name, stage_name, entries):
        table_opt = self.bfrt_info.table_get(table_name)
        self.log.info("Begin to Add entries for table {}".format(table_name))
        key_list = []
        data_list = []
        for key, values in entries.iteritems():
            if key == stage_name:
                for value in values:
                    value1 = value[0]
                    value2 = value[1]
                    value3 = value[2]
                    key_list.append(table_opt.make_key([gc.KeyTuple(name=key_name1, value=int(value2, 16), mask=0xFF),
                                                        gc.KeyTuple(name=key_name2, value=int(value1, 10), mask=0xFFFF),
                                                        gc.KeyTuple("$MATCH_PRIORITY", value= self.verify_priority)]))
                    self.verify_priority += 1
                    data_list.append(table_opt.make_data(data_field_list_in=[gc.DataTuple(name="state", val=int(value3, 10))],
                                                         action_name=action_name))

        table_opt.entry_add(self.target, key_list, data_list)
        self.log.info("Add {} entries to table {}".format(len(key_list), table_name))
        
    def clear_filter_tables(self):
        for stage in range(1, FILTER_STAGE_NUM + 1):
            for table_num in range(1, TABLE_NUM_PER_STAGE + 1):
                table_name = _get_filter_table_name(stage, table_num)
                sel_table = self.bfrt_info.table_get(table_name)
                sel_table.entry_del(self.target)

    def clear_verify_tables(self):
        for stage in range(1, 8 + 1):
            for table_num in range(1, 9):
                if stage == 8 and table_num == 1:
                    table_name = "win1_8"
                else:
                    table_name = "win{0}_{1}".format(table_num, stage)
                sel_table = self.bfrt_info.table_get(table_name)
                sel_table.entry_del(self.target)
    
    
    def clear_smap_tables(self):
        for num in range(1, 15 + 1):
            table_name = _get_setmap_table_name(num)
            sel_table = self.bfrt_info.table_get(table_name)
            sel_table.entry_del(self.target)
            
            
    def fill_tables(self):
        self.clear_smap_tables()
        self.clear_filter_tables()
        self.clear_verify_tables()
        self.add_filter_tables()
        self.add_verify_tables()
        self.add_setmap_tables()
        

a = StrMatchCtrl()
a.setup(PROGRAM_NAME, "localhost", 50052)
a.fill_tables()
a.close_all()


# if __name__ == '__main__':
#     print("ceshi")
#     a = StrMatchCtrl()
#     try:
#         a.setup(PROGRAM_NAME, "localhost", 50052)
#         a.fill_tables()
#         a.close_all()
#     except gc.BfruntimeReadWriteRpcException as e:
#         print e
#         a.close_all()
#     except Exception as e:
#         print e
#         a.close_all()
