from collections import OrderedDict


class Stack:
    def __init__(self, program):
        self.fullstack =[]

    def process_function_stack(self,program,function):
        
        for var in program.main.:
            key, value = var.toStackEntry()
            self.stack_values[key] = value

        for func in program.extra_functions:
            for var in func.variables:
                key, value = var.toStackEntry()
                self.stack_values[key] = value

    def __str__(self):
        ordered_vals = OrderedDict(
            sorted(self.stack_values.items(), reverse=True))
        ret_str = "STACK (higher addresses on bottom):\n"
        for addr, val in ordered_vals.items():
            ret_str += "> " + str(addr) + "|" + str(val[0]) + " " + str(
                val[1]) + "\n"

        return ret_str


def createStack(program):
    stack = Stack(program)
    return stack