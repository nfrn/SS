import json
import os
from collections import OrderedDict
from Vulnerability import *
from program import *

assBasic = ['ret', 'leave', 'nop', 'push', 'pop', 'call', 'mov', 'lea', 'sub', 'add']
assAdvc = ['cmp', 'test', 'je', 'jmp', 'jne']
funDang = ['gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'fscanf', 'fgets', 'strncpy', 'strncat', 'snprintf', 'read']

def processFunction(data,name):
    function = Function(name)

    for varData in data['variables']:
        var = Variable(varData['bytes'],varData['type'],varData['name'],varData[
            'address'])
        function.addVariable(var)

    for insData in data['instructions']:
        inst = Instruction(insData['op'], insData['pos'],
                                       insData['address'])

        if 'args' in insData:
            for key,val in insData['args'].items():
                inst.addArgument(key,val)

        function.addInstruction(inst)
    return function

def processData(rawData):

    main = processFunction(rawData['main'], 'main')
    program = Program(main)

    if 'fun1' in rawData:
        f1 = processFunction(rawData['fun1'], 'fun1')
        program.addFunction(f1)

    if 'fun2' in rawData:
        f2 = processFunction(rawData['fun2'], 'fun2')
        program.addFunction(f2)

    return program

class Stack:
    
    def __init__(self, program):
        self.stack_values = {}

        for var in program.main.variables:
            key,value = var.toStackEntry()
            self.stack_values[key] = value

        for func in program.extra_functions:
            for var in func.variables:
                key,value = var.toStackEntry()
                self.stack_values[key] = value

    def __str__(self):
        ordered_vals = OrderedDict(sorted(self.stack_values.items(), reverse = True))
        ret_str = "STACK (higher addresses on bottom):\n"
        for addr, val in ordered_vals.items():
            ret_str += "> " + str(addr) +"|" + str(val[0]) + " " + str(val[1]) + "\n"
    
        return ret_str

def createStack(program):
    stack = Stack(program)
    return stack

def checkVulnerability(program,stack):
    vulnerability = Vulnerability( Vulnerability.RBP_OVERFLOW, "func1", "123456","strcopy?", "buf")
    return vulnerability

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
            program = processData(rawData)

##maybe we will need this??
def sum_str_hexes(str1,str2):
    return str(hex(str_to_hex(str1) + str_to_hex(str2)))
#_str in format "0xYYY..."
def str_to_hex(_str):
    return int(_str,16)
        
if __name__ == "__main__":
    test = '02'

    with open('public_tests/test'+ test + '.json', 'r') as file:
        rawData = json.load(file)
        program = processData(rawData)
        stack = createStack(program)

        print (program)
        print(stack)

        conta = sum_str_hexes("0x1111","0x09")
        print( str(conta))
        vulnerability = checkVulnerability(program, stack)
        outputdata =  vulnerability.toJSON()

        test_dir = "prog_outs"
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)

        #write to folder 'test' then compare ourselves
        with open(test_dir + '/test'+ test +'.output.json', 'w') as outfile:
            json.dump(outputdata, outfile)


