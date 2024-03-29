from Utils import trans_addr
from Utils import funDang

class Variable:
    def __init__(self, bytes, type, name, address):
        self.bytes = bytes
        self.type = type
        self.name = name

        #address relative to ebp
        #always put in format 0xYY
        self.address = trans_addr(address)

    def toStackEntry(self):
        return self.address, [self.name, self.bytes]

    def __str__(self):
        return "\tvar: "+ self.name + " " + str(self.type) + " " + str(self.address) + " " + str(self.bytes) + "\n"

class Instruction:
    def __init__(self,op,pos,address):
        self.op = op
        self.pos = pos
        self.address = address
        self.args = {}

    def addArgument(self,key,value):
        if key == 'fnname':
            if '@plt' not in value:
                self.args[key] = value[1:-1]  # function from program
            else:
                self.args[key] = value[1:-5]  # builtin
        else:
            self.args[key]=value

    def __str__(self):
        return self.op + " " + str(self.pos) + " " + self.address + " " + \
               str(self.args)

class Function():
    def __init__(self,name):
        self.name = name
        self.variables = []
        self.instructions = []

    def addVariable(self, variable):
        self.variables.append(variable)

    def addInstruction(self, instruction):
        self.instructions.append(instruction)

    def __str__(self):
        ret_str = "function: " + self.name + "\n"
        for var in self.variables:
            ret_str += str(var)

        return ret_str

class Program:
    def __init__(self,main):
        self.functions = {}
        self.functions[main.name] = main

    def addFunction(self,function):
        self.functions[function.name] = function

    def getFunctionNames(self):
        names = []
        for function in self.functions.keys():
            names.append(function)
        return names

    def __str__(self):
        ret_str = "program\n"
        for func in self.functions:
            ret_str += str(func)

        return ret_str
