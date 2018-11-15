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
        #self.store_reg = {'AX':0,'BX':0,'CX':0, 'DX':0,'DI':0,'SI':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}
        
        #ordered with func args order
        #self.store_reg = ['RDI','RSI','RDX','RCX','R8','R9']
        self.store_reg = {'DI':0,'SI':0,'DX':0,'CX':0,'AX':0,'BX':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}

    def process_function_stack(self,function):

        self.add_to_stack("POINTER", "STK", str(self.addRelAddTOStatAdd("0x10")), descr='Other Stack Frame', value="STK")
        self.add_to_stack("POINTER","RET", str(self.addRelAddTOStatAdd("0x08")), descr='Return Address')
        self.add_to_stack("POINTER","RBP", str(self.addRelAddTOStatAdd("0x00")), descr='Base Pointer')
        ##set loval vars in stack

        self.set_local_vars(self.program, function)
        for instruction in self.program.functions[function].instructions:
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

                #set val to var
                elif token[0] in memAlloc.keys() and token[1] == 'PTR':
                    addr = trans_addr(token[2][1:-1])
                    self.add_to_stack( "","", addr, value=instruction.args['value'])

            #call
            if instruction.op == 'call':
                print(instruction)
                fun_name = instruction.args['fnname']
                #print("==== before func call("+fun_name+") stack and reg====")aw
                if fun_name in funDang.keys():
                    Vulnerability.eval_function(self, fun_name, function, instruction.address)

                elif fun_name in self.program.getFunctionNames():
                    print(fun_name)
                    self.add_to_stack("POINTER", "ARGS FOR" + fun_name, self.addRelSubTOStatAdd("0x08"), descr="ARGS FOR" + fun_name)
                    self.process_function_stack(fun_name)




        #print(self.store_reg)
        return self

    def set_local_vars(self, program, function):
        lower_pointer = self.current_function_pointer
        if function in program.getFunctionNames():
            for var in program.functions[function].variables:
                addr = self.addRelAddTOStatAdd(var.address)
                lower_pointer = self.getLowerAdd(lower_pointer,addr)
                type = var.type
                name = var.name
                size = var.bytes
                self.add_to_stack(type, name, addr, descr = type.upper() + " " + name, size=size)

        if lower_pointer != self.current_function_pointer:
            print("NEW POINTER" + lower_pointer)
            self.current_function_pointer = lower_pointer
        print(self)


    
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
            if addr[0] == '-':
                addr_number = int(addr.split("x",1)[1],16)
                if addr_number % 16 != 0:
                    block_not_full_initialized = ((addr_number // 10) + 1) * 10
                    addres_block = '-0x' + str(block_not_full_initialized)

                    print(addres_block)
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
        print(":::::" + add)
        newAdd = hex(int(add, 16) + int(self.current_function_pointer, 16))
        print(":::::" + newAdd)
        return newAdd

    def addRelSubTOStatAdd(self,add):
        print(":::::" + add)
        newAdd = hex(int(add, 16) + int(self.current_function_pointer, 16))
        print(":::::" + newAdd)

        lower_pointer = self.getLowerAdd(self.current_function_pointer, newAdd)

        if lower_pointer != self.current_function_pointer:
            print("NEW POINTER" + lower_pointer)
            self.current_function_pointer = lower_pointer

        return newAdd

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

        self.write_size = bytes

    def set_write_size(self, write_size, fnn, function_writing,function_instr_address):
        self.write_size = write_size
        Vulnerability.check_write(self, write_size, fnn, function_writing,function_instr_address)

    def __str__(self):
        return self.val + " | " + self.descr  + " | " + str(self.bytes)  + " | " + str(self.write_size)