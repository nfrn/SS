import json
import os
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
    test = '02_fgets_strcpy_ok'

    with open('public_basic_tests/'+ test + '.json', 'r') as file:
        rawData = json.load(file)
        program = processData(rawData)

        stack = State(program)
        stack = stack.process_function_stack('main')

        #vulnerabilities = checkVulnerability(stack)
        vulnerabilities = stack.vulns
        outputdata = []
        for vuln in vulnerabilities:
            outputdata.append(vuln.toJSON())

        test_dir = "prog_outs"
        if not os.path.exists(test_dir):
            os.mkdir(test_dir)

        #write to folder 'test' then compare ourselves
        out_file = test_dir + '/'+ test +'.output.json'
        with open(out_file, 'w') as outfile:
            print("\ndumping output to: \'" + out_file + "\'")
            json.dump(outputdata, outfile, indent='\t', separators=(',', ': '))
