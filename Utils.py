import json


assBasic = ['ret', 'leave', 'nop', 'push', 'pop', 'call', 'mov', 'lea', 'sub', 'add']
assAdvc = ['cmp', 'test', 'je', 'jmp', 'jne']
funDang = {'gets': 1, 'strcpy': 2, 'strcat':2, 'sprintf': 2, 'scanf':1, 'fscanf':2, 'fgets': 2, 'strncpy':3, 'strncat':3, 'snprintf':3, 'read':3}

memAlloc = {'BYTE': 1,'WORD':2, 'DWORD':4,'QWORD':8}
arg_reg_order = ['RDI','RSI','RDX','RCX','R8','R9']



def sum_str_hexes(str1 ,str2):
    return str(hex(str_to_hex(str1) + str_to_hex(str2)))

# _str in format "0xYYY..."
def str_to_hex(_str):
    return int(_str ,16)

def trans_addr(address):
    #add = trans_addr1(address)
    add = address.split("rbp")
    if len(add) == 2 :
        rel_addr = add[1]
    else:
        rel_addr = add[0]
    return hex(int(rel_addr,16))


