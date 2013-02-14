
from clint.textui import puts, columns, colored, indent
import bytecode
import javaclass
import sys


def disassemble(f):
    klass = javaclass.ClassData(f)
    f.close()
    
    puts(colored.blue("CONSTANT POOL"))
    puts("")
    for k in klass.constant_pool.keys():
        tagname = javaclass.tagname_str.get(klass.constant_pool[k].tag)
        puts(columns([str(k), 5], [tagname, 25], [bytecode.cplookup(klass.constant_pool,k), 75]))
    
    puts("")
    puts(colored.blue("METHODS"))
    for method in klass.methods:
        puts("")
        puts(colored.yellow(klass.constant_pool[method.name_index].info))
        with indent(4):
            for attribute in method.attributes:
                if "Code" == klass.constant_pool[attribute.attribute_name_index].info:
                    code = javaclass.code_attribute(attribute)
                    for op in bytecode.interpret(klass.constant_pool, code.code):
                        if op.get_value() != None:
                            puts(columns([bytecode.opcode_str.get(op.get_opcode()), 25], [str(op.get_value()), 75]))
                        else:
                            puts(bytecode.opcode_str.get(op.get_opcode()))
    
    
def main(args):
    for fname in args:
        f = open(fname)
        disassemble(f)
        f.close()

if __name__ == "__main__":
    main(sys.argv[1:])
