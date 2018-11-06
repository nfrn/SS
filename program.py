class Variable:
    def __init__(self, bytes, type, name, address):
        self.bytes = bytes
        self.type = type
        self.name = name

        #address relative to ebp
        #always put in format 0xYY
        add = address.split("0x")
        rel_addr = add[1]
        if(len(rel_addr) <2):
            rel_addr = "0" + rel_addr
        self.address = add[0]+"0x"+rel_addr

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
        self.args[key]=value

    def __str__(self):
        return self.op + " " + self.pos + " " + self.address + " " + self.args

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
        self.main = main
        self.extra_functions = []

    def addFunction(self,function):
        self.extra_functions.append(function)

    def __str__(self):
        ret_str = "program\n"
        ret_str += str(self.main)

        for func in self.extra_functions:
            ret_str += str(func)

        return ret_str
