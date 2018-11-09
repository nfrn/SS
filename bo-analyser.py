import json

from Program import *
from Stack import *
from Vulnerability import *

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

def checkVulnerability(program,stack):
    vulnerability = Vulnerability( Vulnerability.RBP_OVERFLOW, "func1", "123456","strcopy?", "buf")
    return vulnerability

if __name__ == "__main__":
    test = '01_gets_all'

    with open('public_basic_tests/'+ test + '.json', 'r') as file:
        rawData = json.load(file)
        program = processData(rawData)

        stack = Stack()
        stack = stack.process_function_stack(program , 'main')

        vulnerability = checkVulnerability(program, stack)
        outputdata =  vulnerability.toJSON()




'''        
        test_dir = "prog_outs"
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)

        #write to folder 'test' then compare ourselves
        with open(test_dir + '/test'+ test +'.output.json', 'w') as outfile:
            json.dump(outputdata, outfile)

'''