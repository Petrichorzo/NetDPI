from itertools import combinations
from config import packge_name

def generate_combinations(hex_number):
    combinations_list = []
    combinations_list.append("FFFFFFFF")
    for num_zeros in range(1, 9):
        positions = range(len(hex_number))
        for positions_with_zeros in combinations(positions, num_zeros):
            new_combination = list(hex_number)

            for pos in positions_with_zeros:
                new_combination[pos] = '0'

            combinations_list.append(''.join(new_combination))

    return combinations_list


def write_combinations_to_file(combinations_list):
    with open('{}/smap.txt'.format(packge_name), 'w') as file:
        file.truncate(0)
        priority = 1
        for combination in combinations_list:
            value = combination
            # print(value)
            value = value.replace('0', '1')
            value = value.replace('F','0')
            value = value[::-1]
            file.write("0x" + combination + "," + "0x" + combination + "," + str(priority) + "," + value + '\n')
            priority += 1


if __name__ == '__main__':
    print("\n开始生成map txt文件...")
    hex_number = 'FFFFFFFF'
    combinations_list = generate_combinations(hex_number)
    # print(combinations_list)
    write_combinations_to_file(combinations_list)
    print("生成结束...")
