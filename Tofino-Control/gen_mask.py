import time

INIT_SH_MASK = 0xFFFFFFFFFFFFFFFF
SHIFT_PADDING = 0xFFFFFFFFFFFFFFF0
sh_mask_list = [INIT_SH_MASK] * 256
sh_mask_shift_4_list = [INIT_SH_MASK] * 256
sh_mask_shift_8_list = [INIT_SH_MASK] * 256
sh_mask_shift_12_list = [INIT_SH_MASK] * 256
sh_mask_shift_16_list = [INIT_SH_MASK] * 256
sh_mask_shift_20_list = [INIT_SH_MASK] * 256
sh_mask_shift_24_list = [INIT_SH_MASK] * 256
sh_mask_shift_28_list = [INIT_SH_MASK] * 256
sh_mask_dic = {"sh_mask_shift_0": [], "sh_mask_shift_4": [], "sh_mask_shift_8": [], "sh_mask_shift_12": [],
               "sh_mask_shift_16": [], "sh_mask_shift_20": [], "sh_mask_shift_24": [], "sh_mask_shift_28": []}


def transfer_str_to_ascii(pattern):
    result = []
    flag = 0
    buffer = ''
    for i in range(len(pattern)):
        if pattern[i] != '|' and flag == 0:
            result.append(ord(pattern[i]))
        elif pattern[i] == '|' and flag == 0:
            flag = 1
        elif pattern[i] != '|' and flag == 1:
            if pattern[i] != ' ':
                buffer += pattern[i]
        elif pattern[i] == '|' and flag == 1:
            flag = 0
            for i in range(0, len(buffer) - 1, 2):
                result.append(int(buffer[i:i + 2], 16))
            buffer = ''
    return result


def set_mask(pattern, bucket_id):
    for i in range(len(pattern) - 1, -1, -1):
        sh_mask_list[int(pattern[i])] &= ~(0x01 << (4 * (len(pattern) - i - 1) + bucket_id))


def set_mask_over_len():
    for bucket_id in range(4):
        for i in range(256):
            for j in range(bucket_id + 1, 16):
                sh_mask_list[i] &= ~(0x01 << (4 * j + bucket_id))


def distribute_pattern_to_bucket(patterns):
    for pattern in patterns:
        dec_pattern_list = transfer_str_to_ascii(pattern)
        pattern_length = len(dec_pattern_list)
        if pattern_length == 1 or pattern_length == 2:
            bucket[0].append(dec_pattern_list)
            set_mask(dec_pattern_list, 0)
        elif pattern_length == 3 or pattern_length == 4:
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
    with open('/root/bf-sde-9.2.0/filter/backend/rules.txt', 'r') as file:
        for line in file:
            line = line.strip()
            pattern_length_set.add(len(line))
            patterns_list.append(line)


def print_sh_mask():
    for i in range(256):
        print("{0}:{1}".format(i, bin(sh_mask_list[i])))


def gen_shift_mask():
    for i in range(256):
        sh_mask_shift_4_list[i] = sh_mask_list[i] << 4 & SHIFT_PADDING
        sh_mask_shift_8_list[i] = sh_mask_list[i] << 8 & SHIFT_PADDING
        sh_mask_shift_12_list[i] = sh_mask_list[i] << 12 & SHIFT_PADDING
        sh_mask_shift_16_list[i] = sh_mask_list[i] << 16 & SHIFT_PADDING
        sh_mask_shift_20_list[i] = sh_mask_list[i] << 20 & SHIFT_PADDING
        sh_mask_shift_24_list[i] = sh_mask_list[i] << 24 & SHIFT_PADDING
        sh_mask_shift_28_list[i] = sh_mask_list[i] << 28 & SHIFT_PADDING


def gen_sh_mask_dic():
    for index in range(len(sh_mask_list)):
        low_32_mask = bin(sh_mask_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_0"].append(string)

    for index in range(len(sh_mask_shift_4_list)):
        low_32_mask = bin(sh_mask_shift_4_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_4_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_4"].append(string)

    for index in range(len(sh_mask_shift_8_list)):
        low_32_mask = bin(sh_mask_shift_8_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_8_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_8"].append(string)

    for index in range(len(sh_mask_shift_12_list)):
        low_32_mask = bin(sh_mask_shift_12_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_12_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_12"].append(string)

    for index in range(len(sh_mask_shift_16_list)):
        low_32_mask = bin(sh_mask_shift_16_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_16_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_16"].append(string)

    for index in range(len(sh_mask_shift_20_list)):
        low_32_mask = bin(sh_mask_shift_20_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_20_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_20"].append(string)

    for index in range(len(sh_mask_shift_24_list)):
        low_32_mask = bin(sh_mask_shift_24_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_24_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_24"].append(string)

    for index in range(len(sh_mask_shift_28_list)):
        low_32_mask = bin(sh_mask_shift_28_list[index] & 0xFFFFFFFF)[2:].zfill(32)
        high_32_mask = bin((sh_mask_shift_28_list[index] >> 32) & 0xFFFFFFFF)[2:].zfill(32)
        string = str(index) + ',' + str(high_32_mask) + ',' + str(low_32_mask)
        sh_mask_dic["sh_mask_shift_28"].append(string)


pattern_length_set = set()
patterns_list = []
get_patterns()
patterns_length_list = list(pattern_length_set)
bucket = []
for i in range(4):
    bucket.append([])
distribute_pattern_to_bucket(patterns_list)
set_mask_over_len()
gen_shift_mask()
print("start generating sh_mask_dic...")
start_time = time.time()
gen_sh_mask_dic()
print("ending...time: {}".format(time.time() - start_time))
print("==============================================")
