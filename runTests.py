import json
import glob
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

def getTestData():
    basic_test_input = []
    basic_test_output = []

    advanced_test_input = []
    advanced_test_output = []

    i = 0
    for file in os.listdir("public_basic_tests"):
        if i == 0 and file.endswith(".json"):
            i = 1
            basic_test_input.append(os.path.join("public_basic_tests/", file))
        elif i == 1 and file.endswith(".json"):
            i = 0
            basic_test_output.append(os.path.join("public_basic_tests/", file))

    i = 0
    for file in os.listdir("public_advanced_tests"):
        if i == 0 and file.endswith(".json"):
            i = 1
            advanced_test_input.append(os.path.join("public_advanced_tests/", file))
        elif i == 1 and file.endswith(".json"):
            i = 0
            advanced_test_output.append(os.path.join("public_advanced_tests/", file))

    return basic_test_input, basic_test_output,advanced_test_input,advanced_test_output

def json_equals(jsonA, jsonB):
    if type(jsonA) != type(jsonB):
        # not equal
        return False
    if type(jsonA) == 'dict':
        if len(jsonA) != len(jsonB):
            return False
        for keyA in jsonA:
            if keyA not in jsonB or not json_equals(jsonA[keyA], jsonB[keyA]):
                return False
    elif type(jsonA) == 'list':
        if len(jsonA) != len(jsonB):
            return False
        for itemA, itemB in zip(jsonA, jsonB):
            if not json_equals(itemA, itemB):
                return False
    else:
        return jsonA == jsonB


if __name__ == "__main__":

    basic_test_input, basic_test_output, advanced_test_input, advanced_test_output = getTestData()
    with open("testResults.txt", 'w') as outfile:
        #First Run Basic Tests
        #len(basic_test_input)
        for count in range (0, 2):
            current_test = basic_test_input[count]
            current_target = basic_test_output[count]
            with open(current_test, 'r') as file , open(current_target, 'r') as target:
                rawData = json.load(file)
                program = processData(rawData)

                stack = State(program)
                stack = stack.process_function_stack('main')

                vulnerabilities = stack.vulns

                outputdata = []
                for vuln in vulnerabilities:
                    outputdata.append(vuln.toJSON())

                targetjson = json.load(target)
                outputedjson = json.dumps(outputdata, indent='\t',sort_keys=True, separators=(',', ': '))
                targetedjson = json.dumps(targetjson, indent='\t', sort_keys=True, separators=(',', ': '))


                if json_equals(outputedjson,targetedjson):
                    outfile.write("[OK] Test: " + current_test + "\n")
                    print("OK")
                else:
                    outfile.write("[NO] Test: " + current_test + "\n")
                    json.dump(outputdata,outfile, indent='\t', separators=(',', ': '))
                    outfile.write("___________DIF____________ " + "\n")
                    json.dump(targetjson, outfile, indent='\t', separators=(',', ': '))

        # Then advanced Tests
'''        for count in range(0, len(advanced_test_input)):
            current_test = advanced_test_input[count]
            current_target = advanced_test_output[count]
            with open(current_test, 'r') as file:
                rawData = json.load(file)
                program = processData(rawData)

                stack = State(program)
                stack = stack.process_function_stack('main')

                vulnerabilities = stack.vulns

                outputdata = []
                for vuln in vulnerabilities:
                    outputdata.append(vuln.toJSON())

                outputedjson = json.dumps(outputdata, indent='\t', separators=(',', ': '))

                if outputedjson == current_target:
                    outfile.write("[OK] Test: " + current_test + "\n")
                else:
                    outfile.write("[NO] Test: " + current_test + "\n")
'''