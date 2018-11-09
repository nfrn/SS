import json

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

