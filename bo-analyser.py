import json
import os
import sys
from Program import *
from State import *
from Vulnerability import *

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
    filename = sys.argv[1]
    print(filename)

    with open(filename, 'r') as file:
        rawData = json.load(file)
        program = processData(rawData)

        stack = State(program)
        stack = stack.process_function_stack('main')

        vulnerabilities = stack.vulns
        outputdata = []
        for vuln in vulnerabilities:
            outputdata.append(vuln.toJSON())

        out_file = filename[:-5] + '.output.json'
        with open(out_file, 'w') as outfile:
            json.dump(outputdata, outfile, indent='\t', separators=(',', ': '))
