from collections import OrderedDict
from Utils import *

class Stack:
    def __init__(self):
        self.fullstack =[]
        self.store_reg = {'AX':0,'BX':0,'CX':0, 'DX':0,'DI':0,'SI':0,'R8':0,'R9':0,'R10':0,'R11':0,'R12':0,'R13':0,'R14':0,'R15':0,'BP':0,'SP':0,'IP':0}

    def process_function_stack(self,program,function):
        sub_stack={}
        sub_stack['rbp+0x8'] = 'Main Return Address'
        sub_stack['rbp'] = 'Main Stack base Pointer'

        if function == 'main':

            for instruction in program.main.instructions:
                if instruction.pos==2 and instruction.op == 'sub' and instruction.args['dest']=='rsp':
                    sub_stack['rbp-'+ str(instruction.args['value'])] = "Main function Stack Delimiter"

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

                    elif token[0] in memAlloc.keys() and token[1] == 'PTR':
                        sub_stack[token[2][1:-1]] = 'variable with value: ' + instruction.args['value']

                if instruction.op == 'call':
                    self.fullstack.append(sub_stack)
                    fun_name = instruction.args['fnname']
                    if fun_name in funDang.keys():
                        eval_function(self, fun_name)








        print(sub_stack)
        print(self.store_reg)

    def __str__(self):
        str = []
        for stack in self.fullstack:
            ordered_vals = OrderedDict(
                sorted(self.stack_values.items(), reverse=True))
            ret_str = "STACK (higher addresses on bottom):\n"
            for addr, val in ordered_vals.items():
                ret_str += "> " + str(addr) + "|" + str(val[0]) + " " + str(
                    val[1]) + "\n"
                str.append(ret_str)
        return str
