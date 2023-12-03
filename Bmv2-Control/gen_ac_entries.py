# python3
import json
import sys

sys.path.append('')
# from config import *
from collections import defaultdict
from config import hex_pattern_file_name, ac_file_name


class Node:
    def __init__(self, state_num, ch=None, is_end_ch=False, rule_number=0):
        self.state_flag = False
        self.state_list = []
        self.state_num = state_num
        self.ch = ch
        self.children = []
        self.children_state = []
        self.is_end_ch = is_end_ch
        self.rule_number = rule_number


class Trie(Node):
    """
    实现了一个简单的字典树
    """

    def __init__(self):
        Node.__init__(self, 0)

    def init(self):
        self._state_num_max = 0
        self.goto_dic = defaultdict(lambda: -1)
        self.fail_dic = defaultdict(int)
        self.output_dic = defaultdict(list)
        self.entries_dic = defaultdict(list)
        self.entries_count = 0
        self.stride_len = []
        self.max_match_times = 0
        self.level_dic = {}
        self.priority = 0

    def build(self, patterns):
        """
        参数 patterns 如['he', 'she', 'his', 'hers']
        # [['0x57', '0x65', '0x6c', '0x63', '0x6f', '0x6d', '0x65', '0x21'],[]]
        """
        for i in range(len(patterns)):
            self._build_for_each_pattern(patterns[i], i + 1)
        self._build_fail()

    def _build_for_each_pattern(self, pattern, pattern_number):
        # print("pattern:", pattern)
        # print("pattern_number: ", pattern_number)
        """
        将pattern添加到当前的字典树中
        """
        current = self
        pattern = eval(pattern)
        # pattern = ['0x57', '0x65', '0x6c', '0x63', '0x6f', '0x6d', '0x65', '0x21'] pattern_number = 1
        for i in range(len(pattern)):
            ch = pattern[i]

            # print(ch)
            # 判断字符 ch 是否为节点 current 的子节点
            index = self._ch_exist_in_node_children(current, ch)
            # 不存在 添加新节点并转向
            if index == -1:
                # if self.state_flag == True:
                #     if self.state_list == []:
                #         self.state_list.append(0)
                #     else:
                #         self.state_list.append(max(self.state_list) + 1)
                if i == len(pattern) - 1:
                    current = self._add_child_and_goto(current, ch, True, pattern_number)
                    if not self.state_list:
                        self.state_list.append(1)
                    else:
                        self.state_list.append(max(self.state_list) + 1)
                else:
                    current = self._add_child_and_goto(current, ch, False, 0)
                    self.state_list.append(0)

            # 存在 直接 goto
            else:
                self.state_flag = True
                current = current.children[index]
                # self._state_num_max += 1
        self.output_dic[current.state_num] = [pattern]

    def _ch_exist_in_node_children(self, current, ch):
        """
        判断字符 ch 是否为节点 current 的子节点，如果是则返回位置，否则返回-1
        """
        for index in range(len(current.children)):
            child = current.children[index]
            if child.ch == ch:
                return index
        return -1

    def _add_child_and_goto(self, current, ch, is_end_ch, rule_number):
        """
        在当前的字典树中添加新节点并转向
        新节点的编号为 当前最大状态编号+1
        """
        # self._state_num_max += 1
        if self.state_list == []:
            state = 0
        else:
            state = max(self.state_list)

        next_node = Node(state, ch, is_end_ch, rule_number)
        current.children.append(next_node)
        current.children_state.append(self._state_num_max)
        # 修改转向函数
        self.goto_dic[(current.state_num, ch)] = self._state_num_max
        return next_node

    def _build_fail(self):
        node_at_level = self.children
        while node_at_level:
            node_at_next_level = []
            for parent in node_at_level:
                node_at_next_level.extend(parent.children)
                for child in parent.children:
                    v = self.fail_dic[parent.state_num]
                    while self.goto_dic[(v, child.ch)] == -1 and v != 0:
                        v = self.fail_dic[v]
                    fail_value = self.goto_dic[(v, child.ch)]
                    self.fail_dic[child.state_num] = fail_value
                    if self.fail_dic[child.state_num] != 0:
                        self.output_dic[child.state_num].extend(self.output_dic[fail_value])
            node_at_level = node_at_next_level

    def DFS(self, root):
        if root == None:
            return
        # print("state:{0},char:{1},child:{2}".format(root.state_num, root.ch, root.children_state))
        # print("root.children: ", root.children)
        for index in range(len(root.children)):
            node = root.children[index]
            self.DFS(node)


    def gen_table_add_level(self, root, level):
        if root == None:
            return
        # print("state:{0},char:{1},child:{2},".format(root.state_num,root.ch,root.children_state))
        # src_state p1 p2 p3 => dstState,nextLen,ruleNumber
        for index in range(len(root.children)):
            string = ""
            node = root.children[index]
            if level + 1 not in self.level_dic:
                self.level_dic[level + 1] = 1
            else:
                self.level_dic[level + 1] += 1
            n = 1
            # for p in range(1, 9):
                # print("src_state:{0},char:{1},dstState:{2},nextlen:{3},node.ch: {4}".format(root.state_num, root.ch, node.state_num, len(node.ch), node.ch))
            str1 = "stage" +"_" + str(level+1) + "," + str(root.state_num) + ","
            str2 = ""
            # print(node.ch)
            str2 += str(node.ch)
            # print(len(node.children))
            str4 = str(node.state_num)
            # if len(node.children) > 1:
            #     str4 = "=> {0} {1} {2} 1".format(node.state_num, 1, node.rule_number)
            # elif len(node.children) == 1:
            #     str4 = "=> {0} {1} {2} 1".format(node.state_num, len(node.children[0].ch), node.rule_number)
            # else:
            #     str4 = "=> {0} {1} {2} 1".format(node.state_num, 0, node.rule_number)
            # string = str1 + str2 + str3 + str4 + '\n'
            self.priority += 1
            string = str1 + str2 + "," + str4 + "," + str(self.priority) + '\n'
            file.write(string)

            self.gen_table_add_level(node, level + 1)

    def compression(self, root):
        # leaf node
        if len(root.children) == 0:
            return
        # whether current node is branch node
        if len(root.children) > 1:
            for index in range(len(root.children)):
                # branch node's first child
                self.compression(root.children[index])
        else:
            if len(root.children[0].children) > 1 or len(root.children[0].children) == 0 or root.children[0].is_end_ch:
                self.compression(root.children[0])
            else:
                root.children[0].children[0].ch = root.children[0].ch + root.children[0].children[0].ch
                root.children_state.remove(root.children[0].state_num)
                root.children[0] = root.children[0].children[0]
                root.children_state.append(root.children[0].state_num)
                # 修改转向函数
                self.goto_dic[(root.state_num, root.children[0].ch)] = root.children[0].state_num
                self.compression(root)

    def k_stride_compression(self, root, k, k_stride, match_times):
        # leaf node
        if len(root.children) == 0:
            if match_times > self.max_match_times:
                self.max_match_times = match_times
            return
        # whether current node is branch node
        if len(root.children) > 1:
            for index in range(len(root.children)):
                # branch node's first child
                self.k_stride_compression(root.children[index], k, k_stride, match_times + 1)
        else:
            if len(root.children[0].children) > 1 or len(root.children[0].children) == 0 or root.children[0].is_end_ch:
                self.k_stride_compression(root.children[0], k, k_stride, match_times + 1)
            else:
                if k == k_stride:
                    k = 1
                    self.k_stride_compression(root.children[0], k, k_stride, match_times + 1)
                else:
                    root.children[0].children[0].ch = root.children[0].ch + root.children[0].children[0].ch
                    root.children_state.remove(root.children[0].state_num)
                    root.children[0] = root.children[0].children[0]
                    root.children_state.append(root.children[0].state_num)
                    # 修改转向函数
                    self.goto_dic[(root.state_num, root.children[0].ch)] = root.children[0].state_num
                    self.k_stride_compression(root, k + 1, k_stride, match_times)

    def gen_entries(self, root):
        if root == None:
            return
        for index in range(len(root.children)):
            # print("state:{0}  char:{1}  goto  state:{2}".format(root.state_num, root.children[index].ch, root.children[index].state_num))
            self.entries_dic[(root.state_num, root.children[index].ch)] = root.children[index].state_num
            # print("len(root.children[index].ch): " , len(root.children[index].ch))
            # self.stride_len.append(len(root.children[index].ch)/4)
            self.stride_len.append(1)
            self.entries_count += 1

            node = root.children[index]
            self.gen_entries(node)

        return self.entries_count


class AC(Trie):
    def __init__(self):
        Trie.__init__(self)

    def init(self, patterns):
        Trie.init(self)
        self.build(patterns)

    def goto(self, s, ch):
        if s == 0:
            if (s, ch) not in self.goto_dic:
                return 0
        return self.goto_dic[(s, ch)]

    def fail(self, s):
        return self.fail_dic[s]

    def output(self, s):
        return self.output_dic[s]

    def search(self, text):
        current_state = 0
        ch_index = 0
        while ch_index < len(text):
            ch = text[ch_index]

            if self.goto(current_state, ch) == -1:
                current_state = self.fail(current_state)

            current_state = self.goto(current_state, ch)

            patterns = self.output(current_state)
            if patterns:
                print(current_state, *patterns)
            ch_index += 1


if __name__ == "__main__":
    # 生成的规则文件
    # filename = "snort-ac/snort-1000-ac.txt"
    filename = ac_file_name
    file = open(filename, 'w')

    # pattern_file_name = "snort-patterns-hex/snort-1000-pattern.txt"
    # pattern_file_name = "verifier/test_pattern.txt"
    # pattern_file_name = "snort-patterns-hex/snort-all-reversed.txt"


    k_stride = 1
    pattern_file = open(hex_pattern_file_name, 'r')
    pattern_list = []
    lines = pattern_file.readlines()
    for line in lines:
        line = line.strip()
        pattern_list.append(line)

    ac = AC()
    ac.init(pattern_list)
    # ac.DFS(ac)
    entries_count = ac.gen_entries(ac)
    print('init entries count:', entries_count)
    print("after compression......")
    ac.k_stride_compression(ac, 1, k_stride, 0)
    # ac.DFS(ac)
    print("generate entries......")
    # !!!!!!before gen_entries() must initial  entries_count entries_dic and stride_len
    ac.entries_count = 0
    ac.entries_dic = {}
    ac.stride_len = []

    entries_count = ac.gen_entries(ac)
    print("compression entries count:", entries_count)
    print("average stride length:", sum(ac.stride_len) / entries_count)

    # origin version
    # ac.gen_table_add(ac)
    # compress version:base on one entry only can be matched on its level
    ac.gen_table_add_level(ac, 0)
    print(ac.level_dic)
    print("max_match_times:", ac.max_match_times)
    # print(max_match_times)

    file.close()
    file = open(filename, 'r+')

    table_add = file.read()
    file.seek(0, 0)
    file.write(table_add)
    print("k_stride: ", k_stride)
    # print("state_list: ",ac.state_list)
    print("总共用了多少个状态节点：", len(ac.state_list) + 1)
    print("最大的状态节点为：", max(ac.state_list) - 1)

    # snort
    # 总共用了多少个状态节点： 172451
    # 最大的状态节点为： 37284

    # suricata
    # 总共用了多少个状态节点： 124017
    # 最大的状态节点为： 26832