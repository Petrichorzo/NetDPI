import string
from binascii import a2b_hex
from config import pattern_file_name, packge_name
INIT_SH_MASK =  0xFFFFFFFFFFFFFFFF
SHIFT_PADDING = 0xFFFFFFFFFFFFFFF0
# INIT_ST_MASK =  0x0000000000000000
# SHIFT_PADDING=0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000


sh_mask_list = [INIT_SH_MASK] * 256
sh_mask_shift_4_list = [INIT_SH_MASK] * 256
sh_mask_shift_8_list = [INIT_SH_MASK] * 256
sh_mask_shift_12_list = [INIT_SH_MASK] * 256
sh_mask_shift_16_list = [INIT_SH_MASK] * 256
sh_mask_shift_20_list = [INIT_SH_MASK] * 256
sh_mask_shift_24_list = [INIT_SH_MASK] * 256
sh_mask_shift_28_list = [INIT_SH_MASK] * 256

# 将模式串转换为10进制ascii
def transfer_str_to_ascii(pattern):
    # print(pattern)

    result = []
    # 0: normal
    # 1: left | waiting for rigth |
    flag = 0
    buffer = ''
    for i in range(len(pattern)):
        if pattern[i] != '|' and flag == 0:
            # print(pattern[i])
            result.append(ord(pattern[i]))
        elif pattern[i] == '|' and flag == 0:
            flag = 1
        elif pattern[i] != '|' and flag == 1:
            if pattern[i] != ' ':
                buffer += pattern[i]
        elif pattern[i] == '|' and flag == 1:
            flag = 0
            # print("buffer: ", buffer)
            for i in range(0, len(buffer) - 1, 2):
                result.append(int(buffer[i:i+2], 16))
            buffer = ''
    # print(result)
    return result

def set_mask(pattern, bucket_id):
    # print("sh_mask_list[99]: ", bin(sh_mask_list[99]))
    for i in range(len(pattern) - 1, -1, -1):
        # i = 2, 1, 0
        # print(int(pattern[i]))
        sh_mask_list[int(pattern[i])] &= ~(0x01 << (4 * (len(pattern) - i - 1) + bucket_id))
    # print("sh_mask_list[99]: ", bin(sh_mask_list[99]))


def set_mask_over_len():
    for bucket_id in range(4):
        for i in range(256):
            for j in range(bucket_id + 1, 16):
                sh_mask_list[i] &= ~(0x01 << (4 * j + bucket_id))
    # print("sh_mask_list[99]: ", bin(sh_mask_list[99]))


def distribute_pattern_to_bucket(patterns):
    for pattern in patterns:
        # 1.transfer pattern to ord ASCII
        dec_pattern_list = transfer_str_to_ascii(pattern)
        # print("dec_pattern_list: ", dec_pattern_list)
        # print("pattern: ", dec_pattern_list)
        # 2.add pattern to bucket 所有长度分布在不同的桶
        pattern_length = len(dec_pattern_list)
        # print("pattern_top_8_list: ", pattern_top_8_list)

        if pattern_length == 1 or pattern_length == 2:
            bucket[0].append(dec_pattern_list)
            set_mask(dec_pattern_list, 0)
        elif pattern_length == 3 or pattern_length == 4:
            # print("dec_pattern_list: ", dec_pattern_list)
            bucket[1].append(dec_pattern_list)
            set_mask(dec_pattern_list, 1)
        elif pattern_length == 5 or pattern_length == 6:
            bucket[2].append(dec_pattern_list)
            set_mask(dec_pattern_list, 2)
        elif pattern_length == 7 or pattern_length == 8:
            bucket[3].append(dec_pattern_list)
            set_mask(dec_pattern_list, 3)
        else:
            bucket[3].append(dec_pattern_list[:8])
            set_mask(dec_pattern_list[:8], 3)


def get_patterns():
    with open(pattern_file_name) as file:
        for line in file:
            line = line.strip()
            pattern_length_set.add(len(line))
            patterns_list.append(line)


def print_sh_mask():
    for i in range(256):
        print("{0}:{1}".format(i, bin(sh_mask_list[i])))


# def print_sh_mask_shift():
#     for i in range(256):
#         print("{0}:{1} {2}".format(i, bin(sh_mask_list[i]), sh_mask_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_8_list[i]), sh_mask_shift_8_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_16_list[i]), sh_mask_shift_16_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_24_list[i]), sh_mask_shift_24_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_32_list[i]), sh_mask_shift_32_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_40_list[i]), sh_mask_shift_40_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_48_list[i]), sh_mask_shift_48_list[i]))
#         print("{0}:{1} {2}".format(i, bin(sh_mask_shift_56_list[i]), sh_mask_shift_56_list[i]))


def gen_shift_mask():
    for i in range(256):
        # sh_mask_list[i]='{:0128b}'.format(sh_mask_list[i])
        sh_mask_shift_4_list[i] = sh_mask_list[i] << 4 & SHIFT_PADDING
        sh_mask_shift_8_list[i] = sh_mask_list[i] << 8 & SHIFT_PADDING
        sh_mask_shift_12_list[i] = sh_mask_list[i] << 12 & SHIFT_PADDING
        sh_mask_shift_16_list[i] = sh_mask_list[i] << 16 & SHIFT_PADDING
        sh_mask_shift_20_list[i] = sh_mask_list[i] << 20 & SHIFT_PADDING
        sh_mask_shift_24_list[i] = sh_mask_list[i] << 24 & SHIFT_PADDING
        sh_mask_shift_28_list[i] = sh_mask_list[i] << 28 & SHIFT_PADDING

# 假设模式串为
# aaaaccccqqq
# bbbbddddwww

# UUUaaaaccccqqqUUbbbbddddwwwUUUUaaaaddddqqqUUaaaaddddUUUUaaaaccccUUUU
# before: true应该2 false应该3，包括aaaaddddqqq，aaaaddddUUU，aaaaccccUUU
# after:  true应该2 false应该1，只有aaaaccccUUU

# pattern_file_name = "../../../DatasetPatterns/snort/patterns_1000.txt"


# 先用一个set存所有的pattern长度，避免重复
pattern_length_set = set()
# 存储所有的patterns
patterns_list = []
# 生成patterns
get_patterns()
# 存储所有patterns的长度
patterns_length_list = list(pattern_length_set)

bucket = []
for i in range(4):
    bucket.append([])

# patterns_list=["xxa","cd","|00 01|"]
# 把patterns分配到bucket_list的各个桶里
distribute_pattern_to_bucket(patterns_list)
set_mask_over_len()
gen_shift_mask()


f1 = open(packge_name + "/sh_mask_shift_0.txt", 'w')
f1.truncate(0)
f2 = open(packge_name + "/sh_mask_shift_4.txt", 'w')
f2.truncate(0)
f3 = open(packge_name + "/sh_mask_shift_8.txt", 'w')
f3.truncate(0)
f4 = open(packge_name + "/sh_mask_shift_12.txt", 'w')
f4.truncate(0)
f5 = open(packge_name + "/sh_mask_shift_16.txt", 'w')
f5.truncate(0)
f6 = open(packge_name + "/sh_mask_shift_20.txt", 'w')
f6.truncate(0)
f7 = open(packge_name + "/sh_mask_shift_24.txt", 'w')
f7.truncate(0)
f8 = open(packge_name + "/sh_mask_shift_28.txt", 'w')
f8.truncate(0)
# f9 = open(packge_name + "/test.txt", 'w')
# f9.truncate(0)
#
print("开始生成mask txt文件...")
for index in range(len(sh_mask_list)):
    low_32_mask = bin(sh_mask_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f1.write(string)
for index in range(len(sh_mask_shift_4_list)):
    low_32_mask = bin(sh_mask_shift_4_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_4_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f2.write(string)
for index in range(len(sh_mask_shift_8_list)):
    low_32_mask = bin(sh_mask_shift_8_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_8_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f3.write(string)
for index in range(len(sh_mask_shift_12_list)):
    low_32_mask = bin(sh_mask_shift_12_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_12_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f4.write(string)
for index in range(len(sh_mask_shift_16_list)):
    low_32_mask = bin(sh_mask_shift_16_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_16_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f5.write(string)
for index in range(len(sh_mask_shift_20_list)):
    low_32_mask = bin(sh_mask_shift_20_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_20_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f6.write(string)
for index in range(len(sh_mask_shift_24_list)):
    low_32_mask = bin(sh_mask_shift_24_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_24_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f7.write(string)
for index in range(len(sh_mask_shift_28_list)):
    low_32_mask = bin(sh_mask_shift_28_list[index] & 0xFFFFFFFF)[2:].zfill(32)
    high_32_mask = bin((sh_mask_shift_28_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
    string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask) + '\n'
    f8.write(string)
print("生成结束...")

# print_sh_mask()

# print(bin(sh_mask_list[1]))
# print(bin(sh_mask_shift_4_list[1]))