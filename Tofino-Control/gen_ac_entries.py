import time
from collections import defaultdict


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
        for i in range(len(patterns)):
            self._build_for_each_pattern(patterns[i], i + 1)
        self._build_fail()

    def _build_for_each_pattern(self, pattern, pattern_number):
        current = self
        for i in range(len(pattern)):
            ch = pattern[i]
            index = self._ch_exist_in_node_children(current, ch)
            if index == -1:
                if i == len(pattern) - 1:
                    current = self._add_child_and_goto(current, ch, True, pattern_number)
                    if not self.state_list:
                        self.state_list.append(1)
                    else:
                        self.state_list.append(max(self.state_list) + 1)
                else:
                    current = self._add_child_and_goto(current, ch, False, 0)
                    self.state_list.append(0)
            else:
                self.state_flag = True
                current = current.children[index]
        self.output_dic[current.state_num] = [pattern]

    def _ch_exist_in_node_children(self, current, ch):
        for index in range(len(current.children)):
            child = current.children[index]
            if child.ch == ch:
                return index
        return -1

    def _add_child_and_goto(self, current, ch, is_end_ch, rule_number):
        if self.state_list == []:
            state = 0
        else:
            state = max(self.state_list)

        next_node = Node(state, ch, is_end_ch, rule_number)
        current.children.append(next_node)
        current.children_state.append(self._state_num_max)
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
        for index in range(len(root.children)):
            node = root.children[index]
            self.DFS(node)

    def gen_table_add_level(self, root, level):
        if root == None:
            return
        for index in range(len(root.children)):
            node = root.children[index]
            if level + 1 not in self.level_dic:
                self.level_dic[level + 1] = 1
            else:
                self.level_dic[level + 1] += 1
            str1 = "stage" + "_" + str(level + 1) + "," + str(root.state_num) + ","
            str2 = ""
            str2 += str(node.ch)
            str4 = str(node.state_num)
            self.priority += 1
            string = str1 + str2 + "," + str4 + "," + str(self.priority)
            ac_list.append(string)
            self.gen_table_add_level(node, level + 1)

    def compression(self, root):
        if len(root.children) == 0:
            return
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
                self.goto_dic[(root.state_num, root.children[0].ch)] = root.children[0].state_num
                self.compression(root)

    def k_stride_compression(self, root, k, k_stride, match_times):
        if len(root.children) == 0:
            if match_times > self.max_match_times:
                self.max_match_times = match_times
            return
        if len(root.children) > 1:
            for index in range(len(root.children)):
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
                    self.goto_dic[(root.state_num, root.children[0].ch)] = root.children[0].state_num
                    self.k_stride_compression(root, k + 1, k_stride, match_times)

    def gen_entries(self, root):
        if root == None:
            return
        for index in range(len(root.children)):
            self.entries_dic[(root.state_num, root.children[index].ch)] = root.children[index].state_num
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
            # if patterns:
            #     print(current_state, *patterns)
            ch_index += 1


def transfer_str_to_ascii(pattern):
    result = []
    flag = 0
    buffer = ''
    for i in range(len(pattern)):
        if pattern[i] != '|' and flag == 0:
            result.append(hex(ord(pattern[i])))
        elif pattern[i] == '|' and flag == 0:
            flag = 1
        elif pattern[i] != '|' and flag == 1:
            if pattern[i] != ' ':
                buffer += pattern[i]
        elif pattern[i] == '|' and flag == 1:
            flag = 0
            for i in range(0, len(buffer) - 1, 2):
                result.append("0x" + buffer[i:i + 2])
            buffer = ''
    return result


def gen_reverse_top_8_pattern(rule_file):
    reverse_top_8_pattern_list = []
    lines = rule_file.readlines()
    for line in lines:
        line = line.strip()
        line = transfer_str_to_ascii(line)
        line = [hex.upper() for hex in line]
        if len(line) <= 8:
            reverse_top_8_pattern_list.append(line[::-1])
        else:
            reverse_top_8_pattern_list.append(line[:8][::-1])
    return reverse_top_8_pattern_list


print("start generating verifier entries...")
start_time = time.time()
ac_list = []
rule_file = open('/root/bf-sde-9.2.0/filter/backend/rules.txt', 'r')
pattern_list = gen_reverse_top_8_pattern(rule_file)
k_stride = 1
ac = AC()
ac.init(pattern_list)
ac.k_stride_compression(ac, 1, k_stride, 0)
ac.entries_count = 0
ac.entries_dic = {}
ac.stride_len = []
ac.gen_table_add_level(ac, 0)
print("ending...time: {}".format(time.time() - start_time))
# print("ac_list: ", ac_list)
print("==============================================")
