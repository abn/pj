# beware! ere be dragons!  import sys
import struct
import javaclass

def cpindex(byte1, byte2):
    """
     For the cases where the next two bytes are a reference to the 
     constant pool the index should be calculated as follows: 
     index is (indexbyte1 << 8) | indexbyte2
    """
    return (byte1 << 8) | byte2

def cplookup(cp, index):
    """
    Resolves a string value associated with a constant pool 
    entry.
    """
    if index not in cp:
        raise RuntimeError("Invalid index to constant pool")

    if cp[index].tag == javaclass.CONSTANT_Class:
        name_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, name_index)
        
    elif cp[index].tag == javaclass.CONSTANT_FieldRef:
        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index),cplookup(cp, name_and_type_index)])

    elif cp[index].tag == javaclass.CONSTANT_MethodRef:

        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index),cplookup(cp, name_and_type_index)])

    elif cp[index].tag == javaclass.CONSTANT_InterfaceMethodref:
        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index), cplookup(cp, name_and_type_index)])
    
    elif cp[index].tag == javaclass.CONSTANT_String:
        string_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, string_index) 

    elif cp[index].tag == javaclass.CONSTANT_Integer:
        int_val, = struct.unpack(">h", str(cp[index].info)) 
        return str(int_val)

    elif cp[index].tag == javaclass.CONSTANT_Float:
        # FIXME 
        raise RuntimeError("Not implemented: float")

    elif cp[index].tag == javaclass.CONSTANT_Long:
        high_bytes, low_bytes, = struct.unpack(">ll", str(cp[index].info))
        return str(long((high_bytes << 32) + low_bytes))

    elif cp[index].tag == javaclass.CONSTANT_Double:
        # FIXME
        raise RuntimeError("Not implemented: double")

    elif cp[index].tag == javaclass.CONSTANT_NameAndType:
        name_index, descriptor, = struct.unpack(">HH", str(cp[index].info))
        return ":".join([cplookup(cp, name_index), cplookup(cp, descriptor)])

    elif cp[index].tag == javaclass.CONSTANT_Utf8:
        return str(cp[index].info)

    elif cp[index].tag == javaclass.CONSTANT_MethodHandle:
        reference_kind, reference_index, = struct.unpack(">HH", str(cp[index].info))
        return ":".join([javaclass.REFERENCE_KINDS[reference_kind], cplookup(cp, reference_index)])

    elif cp[index].tag == javaclass.CONSTANT_MethodType:
        descriptor_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, descriptor_index)

    elif cp[index].tag == javaclass.CONSTANT_InvokeDynamic:
        boostrap_method_attr_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        # FIXME (BUG): nfi about bootstrap_methods etc.
        return cplookup(cp, name_and_type_index)

    else: 
        raise RuntimeError("Unexpected tag")


# http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html#jvms-6.5 
opcode_str  = {

    0x32    :   "aaload",
    0x53    :   "aastore",
    0x1     :   "aconst_null",
    0x19    :   "aload",
    0x2a    :   "aload_0", 
    0x2b    :   "aload_1",
    0x2c    :   "aload_2", 
    0x2d    :   "aload_3", 
    0xbd    :   "anewarray",
    0xb0    :   "areturn",
    0xbe    :   "arraylength",
    0x3a    :   "astore",
    0x4b    :   "astore_0",
    0x4c    :   "astore_1",
    0x4d    :   "astore_2",
    0x4e    :   "astore_3",
    0xbf    :   "athrow",
    0x33    :   "baload",
    0x54    :   "bastore",
    0x10    :   "bipush",
    0x34    :   "caload",
    0x55    :   "castore",
    0xc0    :   "checkcast",
    0x90    :   "d2f",
    0x8e    :   "d2i",
    0x8f    :   "d2l", 
    0x63    :   "dadd",
    0x31    :   "daload", 
    0x52    :   "dastore",
    0x98    :   "dcmpg",
    0x97    :   "dcmpl",
    0xe     :   "dconst_0", 
    0xf     :   "dconst_1",
    0x6f    :   "ddiv",
    0x18    :   "dload",
    0x26    :   "dload_0",
    0x27    :   "dload_1",
    0x28    :   "dload_2",
    0x29    :   "dload_3",
    0x6b    :   "dmul", 
    0x77    :   "dneg",
    0x73    :   "drem",
    0xaf    :   "dreturn",
    0x39    :   "dstore", 
    0x47    :   "dstore_0",
    0x48    :   "dstore_1",
    0x49    :   "dstore_2",
    0x4a    :   "dstore_3",
    0x67    :   "dsub",
    0x59    :   "dup",
    0x5a    :   "dup_x1",
    0x5b    :   "dup_x2",
    0x5c    :   "dup2",
    0x5d    :   "dup2_x1",
    0x5e    :   "dup2_x2",
    0x8d    :   "f2d",
    0x8b    :   "f2i",
    0x8c    :   "f2l", 
    0x62    :   "fadd",
    0x30    :   "faload", 
    0x51    :   "fastore",
    0x96    :   "fcmp<g>",
    0x95    :   "fcmp<l>", 
    0xb     :   "fconst_0",
    0xc     :   "fconst_1", 
    0xd     :   "fconst_2",
    0x6e    :   "fdiv",
    0x17    :   "fload",
    0x22    :   "fload_0",
    0x23    :   "fload_1",
    0x24    :   "fload_2",
    0x25    :   "fload_3",
    0x6a    :   "fmul", 
    0x76    :   "fneg",
    0x72    :   "frem",
    0xae    :   "freturn",
    0x38    :   "fstore",
    0x43    :   "fstore_0",
    0x44    :   "fstore_1",
    0x45    :   "fstore_2",
    0x46    :   "fstore_3",
    0x66    :   "fsub",
    0xb4    :   "getfield",     # refs constant pool (index byte, index byte)
    0xb2    :   "getstatic",    # refs constant pool (index byte, index byte)
    0xa7    :   "goto",
    0xc8    :   "goto_w", 
    0x91    :   "i2b",
    0x92    :   "i2c",
    0x87    :   "i2d",
    0x86    :   "i2f",
    0x85    :   "i2l",
    0x93    :   "i2s",
    0x60    :   "iadd",
    0x2e    :   "iaload", 
    0x7e    :   "iand", 
    0x4f    :   "iastore",
    0x2     :   "iconst_m1",
    0x3     :   "iconst_0",
    0x4     :   "iconst_1",
    0x5     :   "iconst_2",
    0x6     :   "iconst_3",
    0x7     :   "iconst_4",
    0x8     :   "iconst_5",
    0x6c    :   "idiv",
    0xa5    :   "if_acmpeq", 
    0xa6    :   "if_acmpne",
    0x9f    :   "if_icmpeq",
    0xa0    :   "if_icmpne",
    0xa1    :   "if_icmplt",
    0xa2    :   "if_icmpge",
    0xa3    :   "if_icmpgt",
    0xa4    :   "if_icmple",
    0x99    :   "ifeq",
    0x9a    :   "ifne",
    0x9b    :   "iflt",
    0x9c    :   "ifge",
    0x9d    :   "ifgt",
    0x9e    :   "ifle",
    0xc7    :   "ifnonnull",
    0xc6    :   "ifnull",
    0x84    :   "iinc",
    0x15    :   "iload",
    0x1a    :   "iload_0",
    0x1b    :   "iload_1",
    0x1c    :   "iload_2",
    0x1d    :   "iload_3",
    0x68    :   "imul",
    0x74    :   "ineg",
    0xc1    :   "instanceof",       # refs constant pool (index byte, index byte)
    0xba    :   "invokedynamic",    # refs constant pool (index byte, index byte) (more args)
    0xb9    :   "invokeinterface",  # refs constant pool (index byte, index byte) (more args)
    0xb7    :   "invokespecial",    # refs constant pool (index byte, index byte)
    0xb8    :   "invokestatic",     # refs constant pool (index byte, index byte) 
    0xb6    :   "invokevirtual",    # refs constnat pool (index byte, index byte)
    0x80    :   "ior",
    0x70    :   "irem",
    0xac    :   "ireturn",
    0x78    :   "ishl",
    0x7a    :   "ishr",
    0x36    :   "istore",
    0x3b    :   "istore_0",
    0x3c    :   "istore_1",
    0x3d    :   "istore_2",
    0x3e    :   "istore_3",
    0x64    :   "isub",
    0x7c    :   "iushr",
    0x82    :   "ixor",
    0xa8    :   "jsr",
    0xc9    :   "jsr_w", 
    0x8a    :   "l2d",
    0x89    :   "l2f",
    0x88    :   "l2i",
    0x61    :   "ladd", 
    0x2f    :   "laload",
    0x7f    :   "land",
    0x50    :   "lastore",
    0x94    :   "lcmp",
    0x9     :   "lconst_0",
    0xa     :   "lconst_1",
    0x12    :   "ldc",          # refs constant pool (index)
    0x13    :   "ldc_w",        # refs constant pool (index byte, index byte)
    0x14    :   "ldc2_w",       # refs constant pool (index byte, index byte)
    0x6d    :   "ldiv",         
    0x16    :   "lload", 
    0x1e    :   "lload_0", 
    0x1f    :   "lload_1", 
    0x20    :   "lload_2", 
    0x21    :   "lload_3", 
    0x69    :   "lmul",
    0x75    :   "lneg",
    0xab    :   "lookupswitch",
    0x81    :   "lor",
    0x71    :   "lrem", 
    0xad    :   "lreturn",
    0x79    :   "lshl",
    0x7b    :   "lshr", 
    0x37    :   "lstore", 
    0x3f    :   "lstore_0",
    0x40    :   "lstore_1",
    0x41    :   "lstore_2",
    0x42    :   "lstore_3",
    0x65    :   "lsub", 
    0x7d    :   "lusr", 
    0x83    :   "lxor",
    0xc2    :   "monitorenter",
    0xc3    :   "monitorexit",
    0xc5    :   "multianewarray",   # refs constant pool? (index byte, index byte, dimensions)
    0xbb    :   "new",              # refs constant pool (index byte, index byte)
    0xbc    :   "newarray", 
    0x0     :   "nop",
    0x57    :   "pop", 
    0x58    :   "pop2", 
    0xb5    :   "putfield",     # refs constant pool (index byte, index byte)
    0xb3    :   "putstatic",    # refs constant pool (index byte, index byte)  
    0xa9    :   "ret",          
    0xb1    :   "return",
    0x35    :   "saload", 
    0x56    :   "sastore", 
    0x11    :   "sipush", 
    0x5f    :   "swap", 
    0xaa    :   "tableswitch",
    0xc4    :   "wide"
}

class opcode(object):
    """
    Encapsulates a single opcode and 
    associated data.
    """
    def __init__(self, op, value=None):
        self.op = op
        self.val= value

    def __str__(self):
        try:
            opcode = opcode_str[self.op]
        except KeyError, e:
            opcode = hex(self.op)

        value = ""
        if self.val != None: 
            value = self.val

        return " ".join([opcode, value])
            
    def get_opcode(self):
        return self.op

    def get_value(self):
        return self.val

def pc(registers):
    return registers.get("ip")

def step(registers):
    registers["ip"] += 1

def reset(registers):
    registers["ip"] = 0

def cond(cp, code, registers):
    """
    Process conditional instructions and 
    generate an appropriate op code.
    """
    op = code[pc(registers)]
    step(registers); branchbyte1 = code[pc(registers)]
    step(registers); branchbyte2 = code[pc(registers)]
    return opcode(op, { 
        "branchbyte1" : branchbyte1, 
        "branchbyte2" : branchbyte2 
    })

def cpool(cp, code, registers):
    """
    Resolve a constant pool entry using 
    a multi-byte address for the index
    """
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    index = cpindex(indexbyte1, indexbyte2)
    return opcode(op, cplookup(cp, index))


def lcl(cp, code, registers):
    """
    Return an opcode whose value can be derived from 
    a single byte address within the current frame
    """
    op = code[pc(registers)]
    step(registers)
    return opcode(op, { "local":  code[pc(registers)] })


def interpret_aaload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aconst_null(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aload(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_aload_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aload_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aload_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_aload_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_anewarray(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_areturn(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_arraylength(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_astore(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_astore_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_astore_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_astore_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_astore_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_athrow(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_baload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_bastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_bipush(cp, code, registers):
    op = code[pc(registers)]
    step(registers); byte_val = code[pc(registers)]
    return opcode(op, { "byte" : byte_val} )

def interpret_caload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_castore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_checkcast(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_d2f(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_d2i(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_d2l(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dadd(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_daload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dcmpg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dcmpl(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dconst_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dconst_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ddiv(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dload(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_dload_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dload_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dload_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dload_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dmul(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dneg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_drem(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dreturn(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dstore(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_dstore_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dstore_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dstore_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dstore_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dsub(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup_x1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup_x2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup2_x1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_dup2_x2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_f2d(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_f2i(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_f2l(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fadd(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_faload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fcmpg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fcmpl(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fconst_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fconst_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fconst_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fdiv(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fload(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_fload_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fload_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fload_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fload_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fmul(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fneg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_frem(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_freturn(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fstore(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_fstore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fstore_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fstore_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fstore_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fstore_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_fsub(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_getfield(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_getstatic(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_goto(cp, code, registers):
    return cond(cp, code, registers)

def interpret_goto_w(cp, code, registers):
    op = code[pc(registers)]
    step(registers); branchbyte1 = code[pc(registers)]
    step(registers); branchbyte2 = code[pc(registers)]
    step(registers); branchbyte3 = code[pc(registers)]
    step(registers); branchbyte4 = code[pc(registers)]
    return opcode(op, {
        "branchbyte1"   : branchbyte1,
        "branchbyte2"   : branchbyte2,
        "branchbyte3"   : branchbyte3,
        "branchbyte4"   : branchbyte4
    })


def interpret_i2b(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_i2c(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_i2d(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_i2f(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_i2l(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_i2s(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iadd(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iaload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iand(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_m1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_4(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iconst_5(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_idiv(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_if_acmpeq(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_acmpne(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmpeq(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmpne(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmplt(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmpge(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmpgt(cp, code, registers):
    return cond(cp, code, registers)

def interpret_if_icmple(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifeq(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifne(cp, code, registers):
    return cond(cp, code, registers)

def interpret_iflt(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifge(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifgt(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifle(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifnonnull(cp, code, registers):
    return cond(cp, code, registers)

def interpret_ifnull(cp, code, registers):
    return cond(cp, code, registers)

def interpret_iinc(cp, code, registers):
    op = code[pc(registers)]
    step(registers); index = code[pc(registers)]
    step(registers); const = code[pc(registers)]
    return opcode(op, { "index" : index, "const" : const })

def interpret_iload(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_iload_(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iload_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iload_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iload_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_imul(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ineg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_instanceof(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_invokedynamic(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers); # 0
    step(registers); # 0
    return opcode(op, cplookup(cp, cpindex(indexbyte1, indexbyte2)))


def interpret_invokeinterface(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers); count = code[pc(registers)] 
    step(registers); # 0
    return opcode(op, { 
        "name"  : cplookup(cp, cpindex(indexbyte1, indexbyte2)),
        "count" : count
    })

def interpret_invokespecial(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_invokestatic(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_invokevirtual(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_ior(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_irem(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ireturn(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ishl(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ishr(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_istore(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_istore_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_istore_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_istore_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_istore_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_isub(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_iushr(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ixor(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_jsr(cp, code, registers):
    return cond(cp, code, registers)

def interpret_jsr_w(cp, code, registers):
    op = code[pc(registers)]
    step(registers); branchbyte1 = code[pc(registers)]
    step(registers); branchbyte2 = code[pc(registers)]
    step(registers); branchbyte3 = code[pc(registers)]
    step(registers); branchbyte4 = code[pc(registers)]
    return opcode(op, {
        "branchbyte1"   : branchbyte1,
        "branchbyte2"   : branchbyte2,
        "branchbyte3"   : branchbyte3,
        "branchbyte4"   : branchbyte4
    })

def interpret_l2d(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_l2f(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_l2i(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ladd(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_laload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_land(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lcmp(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lconst_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lconst_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_ldc(cp, code, registers):
    op = code[pc(registers)]
    step(registers)
    return opcode(op, cplookup(cp, code[pc(registers)]))

def interpret_ldc_w(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_ldc2_w(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_ldiv(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lload(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_lload_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lload_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lload_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lload_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lmul(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lneg(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lookupswitch(cp, code, registers):
    raise RuntimeError("Not Implemented: lookupswitch")

def interpret_lor(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lrem(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lreturn(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lshl(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lshr(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lstore(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_lstore_0(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lstore_1(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lstore_2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lstore_3(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lsub(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lusr(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_lxor(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_monitorenter(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_monitorexit(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_multianewarray(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers); dimensions = code[pc(registers)]
    return opcode(op, {
        "name"      :   cplookup(cpindex(indexbyte1, indexbyte2)),
        "dimensions":   dimensions 
    })


def interpret_new(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_newarray(cp, code, registers):
    op = code[pc(registers)]
    step(registers); atype = code[pc(registers)]
    atypes = [
        "UNDEFINED",
        "UNDEFINED",
        "UNDEFINED",
        "UNDEFINED",
        "T_BOOLEAN",
        "T_CHAR", 
        "T_FLOAT",
        "T_DOUBLE",
        "T_BYTE",
        "T_SHORT",
        "T_INT",
        "T_LONG",
    ]
    return opcode(op, atypes[atype])

def interpret_nop(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_pop(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_pop2(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_putfield(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_putstatic(cp, code, registers):
    return cpool(cp, code, registers)

def interpret_ret(cp, code, registers):
    return lcl(cp, code, registers)

def interpret_return(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_saload(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_sastore(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_sipush(cp, code, registers):
    op  = code[pc(registers)]
    step(registers); byte1 = code[pc(registers)]
    step(registers); byte2 = code[pc(registers)]
    return opcode(op, {
        "byte" :   byte1,
        "byte2":   byte2
    })

def interpret_swap(cp, code, registers):
    return opcode(code[pc(registers)])

def interpret_tableswitch(cp, code, registers):
    raise RuntimeError("Not Implemented: tableswitch")

def interpret_wide(cp, code, registers):
    op = code[pc(registers)]
    step(registers); wide_op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    val = {
        "op"            : wide_op, 
        "indexbyte1"    : indexbyte1,
        "indexbyte2"    : indexbyte2
    }
    if wide_op ==  0x84: 
        step(registers); val["constbyte1"] = code[pc(registers)]
        step(registers); val["constbyte2"] = code[pc(registers)]

    return opcode(op, val)


interpreter = {

    0x32    :   interpret_aaload,
    0x53    :   interpret_aastore,
    0x1     :   interpret_aconst_null,
    0x19    :   interpret_aload,
    0x2a    :   interpret_aload_0, 
    0x2b    :   interpret_aload_1,
    0x2c    :   interpret_aload_2, 
    0x2d    :   interpret_aload_3, 
    0xbd    :   interpret_anewarray,
    0xb0    :   interpret_areturn,
    0xbe    :   interpret_arraylength,
    0x3a    :   interpret_astore,
    0x4b    :   interpret_astore_0,
    0x4c    :   interpret_astore_1,
    0x4d    :   interpret_astore_2,
    0x4e    :   interpret_astore_3,
    0xbf    :   interpret_athrow,
    0x33    :   interpret_baload,
    0x54    :   interpret_bastore,
    0x10    :   interpret_bipush,
    0x34    :   interpret_caload,
    0x55    :   interpret_castore,
    0xc0    :   interpret_checkcast,
    0x90    :   interpret_d2f,
    0x8e    :   interpret_d2i,
    0x8f    :   interpret_d2l, 
    0x63    :   interpret_dadd,
    0x31    :   interpret_daload, 
    0x52    :   interpret_dastore,
    0x98    :   interpret_dcmpg,
    0x97    :   interpret_dcmpl,
    0xe     :   interpret_dconst_0, 
    0xf     :   interpret_dconst_1,
    0x6f    :   interpret_ddiv,
    0x18    :   interpret_dload,
    0x26    :   interpret_dload_0,
    0x27    :   interpret_dload_1,
    0x28    :   interpret_dload_2,
    0x29    :   interpret_dload_3,
    0x6b    :   interpret_dmul, 
    0x77    :   interpret_dneg,
    0x73    :   interpret_drem,
    0xaf    :   interpret_dreturn,
    0x39    :   interpret_dstore, 
    0x47    :   interpret_dstore_0,
    0x48    :   interpret_dstore_1,
    0x49    :   interpret_dstore_2,
    0x4a    :   interpret_dstore_3,
    0x67    :   interpret_dsub,
    0x59    :   interpret_dup,
    0x5a    :   interpret_dup_x1,
    0x5b    :   interpret_dup_x2,
    0x5c    :   interpret_dup2,
    0x5d    :   interpret_dup2_x1,
    0x5e    :   interpret_dup2_x2,
    0x8d    :   interpret_f2d,
    0x8b    :   interpret_f2i,
    0x8c    :   interpret_f2l, 
    0x62    :   interpret_fadd,
    0x30    :   interpret_faload, 
    0x51    :   interpret_fastore,
    0x96    :   interpret_fcmpg,
    0x95    :   interpret_fcmpl, 
    0xb     :   interpret_fconst_0,
    0xc     :   interpret_fconst_1, 
    0xd     :   interpret_fconst_2,
    0x6e    :   interpret_fdiv,
    0x17    :   interpret_fload,
    0x22    :   interpret_fload_0,
    0x23    :   interpret_fload_1,
    0x24    :   interpret_fload_2,
    0x25    :   interpret_fload_3,
    0x6a    :   interpret_fmul, 
    0x76    :   interpret_fneg,
    0x72    :   interpret_frem,
    0xae    :   interpret_freturn,
    0x38    :   interpret_fstore,
    0x43    :   interpret_fstore_0,
    0x44    :   interpret_fstore_1,
    0x45    :   interpret_fstore_2,
    0x46    :   interpret_fstore_3,
    0x66    :   interpret_fsub,
    0xb4    :   interpret_getfield,     
    0xb2    :   interpret_getstatic,    
    0xa7    :   interpret_goto,
    0xc8    :   interpret_goto_w, 
    0x91    :   interpret_i2b,
    0x92    :   interpret_i2c,
    0x87    :   interpret_i2d,
    0x86    :   interpret_i2f,
    0x85    :   interpret_i2l,
    0x93    :   interpret_i2s,
    0x60    :   interpret_iadd,
    0x2e    :   interpret_iaload, 
    0x7e    :   interpret_iand, 
    0x4f    :   interpret_iastore,
    0x2     :   interpret_iconst_m1,
    0x3     :   interpret_iconst_0,
    0x4     :   interpret_iconst_1,
    0x5     :   interpret_iconst_2,
    0x6     :   interpret_iconst_3,
    0x7     :   interpret_iconst_4,
    0x8     :   interpret_iconst_5,
    0x6c    :   interpret_idiv,
    0xa5    :   interpret_if_acmpeq, 
    0xa6    :   interpret_if_acmpne,
    0x9f    :   interpret_if_icmpeq,
    0xa0    :   interpret_if_icmpne,
    0xa1    :   interpret_if_icmplt,
    0xa2    :   interpret_if_icmpge,
    0xa3    :   interpret_if_icmpgt,
    0xa4    :   interpret_if_icmple,
    0x99    :   interpret_ifeq,
    0x9a    :   interpret_ifne,
    0x9b    :   interpret_iflt,
    0x9c    :   interpret_ifge,
    0x9d    :   interpret_ifgt,
    0x9e    :   interpret_ifle,
    0xc7    :   interpret_ifnonnull,
    0xc6    :   interpret_ifnull,
    0x84    :   interpret_iinc,
    0x15    :   interpret_iload,
    0x1a    :   interpret_iload_,
    0x1b    :   interpret_iload_1,
    0x1c    :   interpret_iload_2,
    0x1d    :   interpret_iload_3,
    0x68    :   interpret_imul,
    0x74    :   interpret_ineg,
    0xc1    :   interpret_instanceof,       
    0xba    :   interpret_invokedynamic,    
    0xb9    :   interpret_invokeinterface,  
    0xb7    :   interpret_invokespecial,    
    0xb8    :   interpret_invokestatic,     
    0xb6    :   interpret_invokevirtual,    
    0x80    :   interpret_ior,
    0x70    :   interpret_irem,
    0xac    :   interpret_ireturn,
    0x78    :   interpret_ishl,
    0x7a    :   interpret_ishr,
    0x36    :   interpret_istore,
    0x3b    :   interpret_istore_0,
    0x3c    :   interpret_istore_1,
    0x3d    :   interpret_istore_2,
    0x3e    :   interpret_istore_3,
    0x64    :   interpret_isub,
    0x7c    :   interpret_iushr,
    0x82    :   interpret_ixor,
    0xa8    :   interpret_jsr,
    0xc9    :   interpret_jsr_w, 
    0x8a    :   interpret_l2d,
    0x89    :   interpret_l2f,
    0x88    :   interpret_l2i,
    0x61    :   interpret_ladd, 
    0x2f    :   interpret_laload,
    0x7f    :   interpret_land,
    0x50    :   interpret_lastore,
    0x94    :   interpret_lcmp,
    0x9     :   interpret_lconst_0,
    0xa     :   interpret_lconst_1,
    0x12    :   interpret_ldc,          
    0x13    :   interpret_ldc_w,        
    0x14    :   interpret_ldc2_w,       
    0x6d    :   interpret_ldiv,         
    0x16    :   interpret_lload, 
    0x1e    :   interpret_lload_0, 
    0x1f    :   interpret_lload_1, 
    0x20    :   interpret_lload_2, 
    0x21    :   interpret_lload_3, 
    0x69    :   interpret_lmul,
    0x75    :   interpret_lneg,
    0xab    :   interpret_lookupswitch,
    0x81    :   interpret_lor,
    0x71    :   interpret_lrem, 
    0xad    :   interpret_lreturn,
    0x79    :   interpret_lshl,
    0x7b    :   interpret_lshr, 
    0x37    :   interpret_lstore, 
    0x3f    :   interpret_lstore_0,
    0x40    :   interpret_lstore_1,
    0x41    :   interpret_lstore_2,
    0x42    :   interpret_lstore_3,
    0x65    :   interpret_lsub, 
    0x7d    :   interpret_lusr, 
    0x83    :   interpret_lxor,
    0xc2    :   interpret_monitorenter,
    0xc3    :   interpret_monitorexit,
    0xc5    :   interpret_multianewarray,   
    0xbb    :   interpret_new,              
    0xbc    :   interpret_newarray, 
    0x0     :   interpret_nop,
    0x57    :   interpret_pop, 
    0x58    :   interpret_pop2, 
    0xb5    :   interpret_putfield,     
    0xb3    :   interpret_putstatic,    
    0xa9    :   interpret_ret,          
    0xb1    :   interpret_return,
    0x35    :   interpret_saload, 
    0x56    :   interpret_sastore, 
    0x11    :   interpret_sipush, 
    0x5f    :   interpret_swap, 
    0xaa    :   interpret_tableswitch,
    0xc4    :   interpret_wide
}

def interpret(cp, code):
    
    registers = {}
    reset(registers)
    codelen = len(code)
    while pc(registers) < codelen:
        op = code[pc(registers)];
        yield interpreter[op](cp, code, registers)
        step(registers)


