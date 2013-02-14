import bytecode
import classutils

class JavaClass(object):

    def __init__(self, f):

        self.class_data = classutils.ClassData(f)
        cp = self.class_data.constant_pool
        self.access_flags = classutils.access_flags(self.class_data.access_flags, is_class=True)
        self.class_name = bytecode.cplookup(cp, self.class_data.this_class)
        self.super_name = bytecode.cplookup(cp, self.class_data.super_class) 

        self.interfaces = []
        for impl in self.class_data.interfaces:
            self.interfaces.append(bytecode.cplookup(cp, impl))

        self.fields = []
        for field in self.class_data.fields:
            field_info = {
                "name"      : bytecode.cplookup(cp, field.name_index),
                "descriptor": bytecode.cplookup(cp, field.descriptor_index),
                "flags"     : classutils.access_flags(field.access_flags)
            }
            # TODO: attributes skipped. is this ok?
            self.fields.append(field_info)

        self.methods = [] 
        for method in self.class_data.methods:
            method_info = {
                "name"      : bytecode.cplookup(cp, method.name_index), 
                "descriptor": bytecode.cplookup(cp, method.descriptor_index),
                "flags"     : classutils.access_flags(method.access_flags),
                "code"      : []
            }

            for attr in method.attributes:
                ops = []
                instr = classutils.code_attribute(attr)
                for op in bytecode.interpret(cp, instr.code):
                    ops.append(op)
                    
                method_info["code"].append(ops)

            self.methods.append(method_info)

    def __str__(self):
        
        flags = " ".join(self.access_flags)
        implements = " ".join(self.interfaces)
        class_description = "%s %s extends %s implements %s" % \
            (flags, self.class_name, self.super_name, implements)

        fields = "fields:\n"
        for field in sorted(self.fields):
            flags = " ".join(field["flags"])
            fields += "\t%s %s %s\n" % \
                (flags, field["name"], field["descriptor"])

        methods = "methods:\n"
        for method in sorted(self.methods):
            flags = " ".join(method["flags"])
            methods += "\t%s %s %s\n" % \
                (flags, method["name"], method["descriptor"])

            for code in method["code"]:
                for op in code:
                    methods += "\t %s" % (bytecode.opcode_str.get(op.get_opcode()))
                    if op.get_value() != None: 
                        methods += "( %s )" % str(op.get_value())

                    methods += "\n"
            methods += "\n"
                
        return "\n".join([class_description, fields, methods])


