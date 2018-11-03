import json

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


if __name__ == "__main__":
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

