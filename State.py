from collections import OrderedDict
from Utils import *
from tabulate import tabulate
import Vulnerability
from Program import Program, Variable

class State:
    def __init__(self, pg):
        self.program = pg
        self.sub_stack={}
        self.vulns = []
        #self.store_reg = {'AX':0,'BX':0,'CX':0, 'DX':0,'DI':0,'SI':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}
        
        #ordered with func args order
        #self.store_reg = ['RDI','RSI','RDX','RCX','R8','R9']
        self.store_reg = {'DI':0,'SI':0,'DX':0,'CX':0,'AX':0,'BX':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}

    def process_function_stack(self,function):
        self.add_to_stack("POINTER","RBP",'rbp+0x08', descr='Return Address')
        self.add_to_stack("POINTER","RET",'rbp+0x00', descr='Base Pointer')
        ##set loval vars in stack

        if function == 'main':
            self.set_local_vars(self.program, function, main_func=True)
            for instruction in self.program.main.instructions:
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
                    fun_name = instruction.args['fnname']
                    #print("==== before func call("+fun_name+") stack and reg====")
                    #print(self)
                    #input()
                    if fun_name in funDang.keys():
                        Vulnerability.eval_function(self, fun_name, function)

        #print(sub_stack)
        #print(self.store_reg)
        return self

    def set_local_vars(self, program, function, main_func=True):
        for var in program.main.variables:
            addr = var.address
            type = var.type
            name = var.name
            size = var.bytes
            self.add_to_stack(type, name, addr, descr = type.upper() + " " + name, size=size)
            
    def add_to_stack(self, type, name, addr, descr='', value='?', size = 8):
        # addrr already set in stack
        if(addr in self.sub_stack.keys()):
            print("stack warning - setting value already set")
            self.sub_stack[addr].val = value
        else:
            self.sub_stack[addr]= StackEntry(size, type, name, addr, self, value, descr)

    def ordered(self):
        ordered_keys = sorted(self.sub_stack.keys(), reverse=True)

        ordered_vals = dict()
        for key in ordered_keys:
            ordered_vals[key] = []
            ordered_vals[key] = self.sub_stack[key]
        return ordered_vals

    def add_vulnerability(self, vuln):
        self.vulns.append(vuln)

    def __str__(self):
        ordered_vals = self.ordered()
        ret_str = "\nSTACK (higher addresses on bottom):\n"       
        ret_str += tabulate(ordered_vals.items(), headers=['Addresses',StackEntry.vals])
        ret_str += "\n\n" + tabulate([self.store_reg.values()], headers=self.store_reg.keys())
        return ret_str

class StackEntry(Variable):
    vals = "value | descr | size | writen_size"
    def __init__(self, bytes, type, name, address, stack, value, descr):
        super().__init__(bytes, type, name, address)
        self.stack = stack
        self.val = value
        self.descr = descr

        self.write_size = 0

    def set_write_size(self, write_size, fnn, function_writing):
        Vulnerability.check_write(self, write_size, fnn, function_writing)
        self.write_size = write_size

    def __str__(self):
        return self.val + " | " + self.descr  + " | " + str(self.bytes)  + " | " + str(self.write_size)