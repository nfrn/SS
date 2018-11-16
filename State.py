import collections
from Utils import *
from tabulate import tabulate
import Vulnerability
from Program import Program, Variable

class State:
    def __init__(self, pg):
        self.program = pg
        self.sub_stack={}
        self.vulns = []
        self.current_function_pointer = '0x0'
        self.lower_pointer = '0x0'
        #self.store_reg = {'AX':0,'BX':0,'CX':0, 'DX':0,'DI':0,'SI':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}
        
        #ordered with func args order
        #self.store_reg = ['RDI','RSI','RDX','RCX','R8','R9']
        self.store_reg = {'DI':"0x0",'SI':"0x0",'DX':"0x0",'CX':"0x0",'AX':"0x0",'BX':"0x0",'R8':"0x0",'R9':"0x0",'R10':"0x0",'R11':"0x0",'R12':"0x0",'R13':"0x0",'R14':"0x0",'R15':"0x0",'BP':"0x0",'SP':"0x0",'IP':"0x0"}
        self.base_store_reg = self.store_reg.copy()

    def process_function_stack(self,function):
        if function == 'main':
            self.add_to_stack("POINTER", "STK", "0x10", descr='Other Stack Frame', value="STK")
            self.add_to_stack("POINTER", "RET", "0x08", descr='Return Address')
            self.add_to_stack("POINTER", "RBP", "0x00", descr='Base Pointer')

        ##set loval vars in stack

        self.set_local_vars(self.program, function)
        for instruction in self.program.functions[function].instructions:
            self.store_reg["IP"] = instruction.address
            #if instruction.pos==2 and instruction.op == 'sub' and instruction.args['dest']=='rsp':
                #addr = 'rbp-'+ trans_addr(str(instruction.args['value'] + "[INFO]"))
                #self.add_to_stack(addr,descr = "Main function Stack Delimiter")

            #mov / lea
            if instruction.op == 'mov' or instruction.op == 'lea':
                token = instruction.args['dest'].split(' ')

                dest_reg = token[0].upper()[1:]
                if dest_reg in self.store_reg.keys():
                    if instruction.args['value'].upper()[1:] in self.store_reg.keys():
                        # If R->R, then crop R of Register
                        orig_reg = instruction.args['value'].upper()[1:]
                        self.store_reg[dest_reg] = self.store_reg[orig_reg]

                    else:
                        # If V->R, no need
                        self.store_reg[dest_reg] = instruction.args['value']

                # set char to buff
                elif token[0] == "BYTE" and token[1] == 'PTR':
                    dest_addr = trans_addr(token[2][1:-1])
                    char = instruction.args['value']
                    print("Directly setting in buffer @" + dest_addr, "val:", char)
                    Vulnerability.eval_direct_write(self, instruction.op, dest_addr, char, function)

                #set val to var
                elif token[0] in memAlloc.keys() and token[1] == 'PTR':
                    addr = trans_addr(token[2][1:-1])
                    self.add_to_stack( "","", addr, value=instruction.args['value'])

            elif instruction.op == "add" or instruction.op == "sub":
                dest_reg = instruction.args['dest']

                val = instruction.args['value']

                print(self.store_reg[dest_reg.upper()[1:]])
                print(int(self.store_reg[dest_reg.upper()[1:]],16))
                #reading from reg
                if val.upper()[1:] in self.store_reg.keys():
                    val = self.store_reg[val.upper()[1:]]

                if instruction.op == "add":
                    self.store_reg[dest_reg.upper()[1:]] = hex(int(self.store_reg[dest_reg.upper()[1:]], 16) + int(val, 16))
                else:
                    self.store_reg[dest_reg.upper()[1:]] = hex(int(self.store_reg[dest_reg.upper()[1:]], 16) - int(val, 16))


            elif instruction.op == "nop":
                pass

            elif instruction.op == "leave" or instruction.op == "ret":
                break #this works because we are processing function calls "recursively"

            #call
            elif instruction.op == 'call':
                print(instruction)
                fun_name = instruction.args['fnname']
                #print("==== before func call("+fun_name+") stack and reg====")aw
                if fun_name in funDang.keys() or "__isoc99_" in fun_name:
                    Vulnerability.eval_function(self, fun_name, function)

                elif fun_name in self.program.getFunctionNames():

                    if self.lower_pointer != self.current_function_pointer:
                        print("NEW POINTER" + self.lower_pointer)
                        self.addRET_EBP(self.lower_pointer)
                        print(self)
                    self.process_function_stack(fun_name)
                self.store_reg = self.base_store_reg.copy()




        #print(self.store_reg)
        return self

    def set_local_vars(self, program, function):
        print("ADD VARS OF FUNCTION: " + function)
        self.lower_pointer = self.current_function_pointer
        if function in program.getFunctionNames():
            for var in program.functions[function].variables:
                addr = self.addRelAddTOStatAdd(var.address)
                print("VAR: " + var.name + "| ADD_" + addr)
                self.lower_pointer = self.getLowerAdd(self.lower_pointer,addr)
                type = var.type
                name = var.name
                size = var.bytes
                self.add_to_stack(type, name, addr, descr = type.upper() + " " + name, size=size)


    
    def next_item_in_stack(self, address):
        ordered = self.ordered()
        for addr in ordered.keys():
            if int(addr,16) <= int(address,16):
                continue
            break

        return self.sub_stack[addr]

    def add_to_stack(self, type, name, addr, descr='', value='?', size = 8):
        # addrr already set in stack
        addr = trans_addr(addr)
        if(addr in self.sub_stack.keys()):
            self.sub_stack[addr].val = value
        else:
            if descr != "Return Address" and descr != "Function Args" and addr[0] == '-':
                addr_number = int(addr.split("x",1)[1],16)
                if addr_number % 8 != 0:
                    block_not_full_initialized = ((addr_number // 10) + 1) * 10
                    addres_block = '-0x' + str(block_not_full_initialized)

                    print("ERROR: "+ name)
                    self.sub_stack[addres_block] = StackEntry(size, type, 'block', addres_block, self, 'NI', "BLOCK INVALID")
            self.sub_stack[addr]= StackEntry(size, type, name, addr, self, value, descr)

    def ordered(self):
        ordered = collections.OrderedDict(sorted(self.sub_stack.items(), key = lambda x: int(x[0],16)))
        return ordered

    def add_vulnerability(self, vuln):
        self.vulns.append(vuln)

    def __str__(self):
        ordered_vals = self.ordered()
        ret_str = "\n======== STACK (higher addresses on bottom): ==========\n"       
        ret_str += tabulate(ordered_vals.items(), headers=['Addresses',StackEntry.vals])
        ret_str += "\n\n" + tabulate([self.store_reg.values()], headers=self.store_reg.keys())
        return ret_str


    def addRelAddTOStatAdd(self,add):
        #print(":::::" + add)
        newAdd = hex(int(self.current_function_pointer, 16) - abs(int(add, 16)))
        #print(":::::" + newAdd)
        return newAdd

    def addRET_EBP(self,add):
        print('addRET_EBP')

        newAdd = hex(int(add, 16) - 8)
        self.add_to_stack("POINTER","ARGS", str(newAdd), descr='Function Args')

        newAdd = hex(int(add, 16) - 16 )
        self.add_to_stack("POINTER", "RET", str(newAdd), descr='Return Address')

        newAdd = hex(int(add, 16) - 24)
        self.add_to_stack("POINTER", "RBP", newAdd, descr='Base Pointer')

        self.current_function_pointer = newAdd

    def get_entry_of_addr(self, addr):
        ordered_keys = list(self.ordered().keys())
        previous_addr = ordered_keys[0]

        for entry_addr in ordered_keys:
            if entry_addr < addr:
                previous_addr = entry_addr
                continue
            else:
                return previous_addr, self.sub_stack[previous_addr]


    def getLowerAdd(self,add1,add2):
        if add1[0] == add2[0] == '-':
            if int(add1[3:],16) > int(add2[3:],16):
                return add1
            else:
                return add2

        elif add1[0] != add2[0]:
            if add1[0] == '-':
                return add1
            else:
                return add2

        elif add1[0] == add2[0] != '-':
            if int(add1[3:],16) < int(add2[3:],16):
                return add1
            else:
                return add2






class StackEntry(Variable):
    vals = "value | descr | size | writen_size"
    def __init__(self, bytes, type, name, address, stack, value, descr):
        super().__init__(bytes, type, name, address)
        self.stack = stack
        self.val = value
        self.descr = descr

        self.write_size = 0

    def set_write_size(self, write_size, fnn, function_writing,function_instr_address):
        self.write_size = write_size
        Vulnerability.check_write(self, write_size, fnn, function_writing,function_instr_address)

    def __str__(self):
        return self.val + " | " + self.descr  + " | " + str(self.bytes)  + " | " + str(self.write_size)