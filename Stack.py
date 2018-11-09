from collections import OrderedDict


class Stack:
    def __init__(self):
        self.fullstack =[]

    def process_function_stack(self,program,function):
        if function == 'main':
            for instruction in program.main.instructions:
                print(instruction)

    def __str__(self):
        ordered_vals = OrderedDict(
            sorted(self.stack_values.items(), reverse=True))
        ret_str = "STACK (higher addresses on bottom):\n"
        for addr, val in ordered_vals.items():
            ret_str += "> " + str(addr) + "|" + str(val[0]) + " " + str(
                val[1]) + "\n"

        return ret_str
