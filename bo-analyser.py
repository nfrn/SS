import json

assBasic = ['ret', 'leave', 'nop', 'push', 'pop', 'call', 'mov', 'lea', 'sub', 'add']
assAdvc = ['cmp', 'test', 'je', 'jmp', 'jne']
funDang = ['gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'fscanf', 'fgets', 'strncpy', 'strncat', 'snprintf', 'read']

class Variable:
    def __init__(self, bytes, type, name, address):
        self.bytes = bytes
        self.type = type
        self.name = name
        self.address = address

class Instruction:
    def __init__(self,op,pos,address):
        self.op = op
        self.pos = pos
        self.address = address
        self.args = {}

    def addArgument(self,key,value):
        self.args[key]=value

class Function():
    def __init__(self,name):
        self.name = name
        self.variables = []
        self.instructions = []

    def addVariable(self, variable):
        self.variables.append(variable)

    def addInstruction(self, instruction):
        self.instructions.append(instruction)

class Program:
    def __init__(self,main):
        self.main = main
        self.extraFunction = []

    def addFunction(self,function):
        self.extraFunction.append(function)

class Stack:
    def __init__(self):
        self.values = []

class Vulnerability:

    def __init__(self,name):
        self.name = name

    def setVar(self,var):
        self.var = var

    def setMainFunction(self,function):
        self.function = function

    def setAddress(self,address):
        self.address= address

    def setMalFunction(self,function):
        self.malfun = function

    def toJSON( self ):
        output = {}
        output['vulnerability'] = self.name
        output['overflow_var'] = self.var
        output['vuln_function'] = self.function
        output['address'] = self.address
        output['fnname'] = self.malfun
        return output

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

def createStack():
    stack = Stack()
    return stack

def checkVulnerability(program,stack):
    vulnerability = Vulnerability()
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

            
if __name__ == "__main__":
    with open('public_tests/test02.json', 'r') as file:
        rawData = json.load(file)
        program = processData(rawData)
        stack = createStack()

        vulnerability = checkVulnerability(program, stack)
        outputdata =  vulnerability.toJSON()
        with open('public_tests/test02.output.json', 'w') as outfile:
            json.dump(outputdata, outfile)


