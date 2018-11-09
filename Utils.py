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

def test():
    testData = ['public_tests/test01.json','public_tests/test02.json',
                'public_tests/test03.json','public_tests/test04.json',
                'public_tests/test05.json','public_tests/test11.json',
                'public_tests/test12.json',
                'public_tests/test13.json','public_tests/test14.json',
                'public_tests/test15.json']
    for test in testData:
        print("Reading test data: " + test)
        with open(test,'r') as file:
            rawData =json.load(file)
            #program = processData(rawData)


def eval_function(stack,fname,function):
    if fname == 'gets':
        destination = stack.store_reg['DI'][1:-1]
        stack.fullstack[0][destination] = "Unlimited gets " + function

