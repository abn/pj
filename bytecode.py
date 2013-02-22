import struct
import classutils

def to_hex(bytes):

    bs = []
    for b in bytes:
        bs.append(hex(b))

    return ''.join(bs)

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

    if cp[index].tag == classutils.CONSTANT_Class:
        name_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, name_index)

    elif cp[index].tag == classutils.CONSTANT_FieldRef:
        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index), cplookup(cp, name_and_type_index)])

    elif cp[index].tag == classutils.CONSTANT_MethodRef:

        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index), cplookup(cp, name_and_type_index)])

    elif cp[index].tag == classutils.CONSTANT_InterfaceMethodref:
        class_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        return ".".join([cplookup(cp, class_index), cplookup(cp, name_and_type_index)])

    elif cp[index].tag == classutils.CONSTANT_String:
        string_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, string_index)

    elif cp[index].tag == classutils.CONSTANT_Integer:
        int_val, = struct.unpack(">h", str(cp[index].info))
        return str(int_val)

    elif cp[index].tag == classutils.CONSTANT_Float:

        bits, = struct.unpack(">h", str(cp[index].info))
        sign = -1
        if bits >> 31 == 0:
            sign = 1

        e = int((bits >> 23) & 0xff);
        m = long(bits & 0x7fffff) | 0x800000
        if e == 0:
            m = long((bits & 0x7fffff) << 1)
        val = float(sign * m * 2 ** (e - 150))
        return str(val)


        return to_hex(cp[index].info)

    elif cp[index].tag == classutils.CONSTANT_Long:
        high_bytes, low_bytes, = struct.unpack(">ii", str(cp[index].info))
        return str(long((high_bytes << 32) + low_bytes))

    elif cp[index].tag == classutils.CONSTANT_Double:

        high_bytes, low_bytes, = struct.unpack(">ii", str(cp[index].info))
        bits = long(high_bytes << 32) + low_bytes
        sign = -1
        if bits >> 63 == 0:
            sign = 1

        e = int((bits >> 52) & 0x7ffL);
        m = (bits & 0xfffffffffffffL) | 0x10000000000000L
        if e == 0:
            m = bits & 0xfffffffffffffL << 1
        val = sign * m * 2 ** (e - 1075)
        return str(val)

    elif cp[index].tag == classutils.CONSTANT_NameAndType:
        name_index, descriptor, = struct.unpack(">HH", str(cp[index].info))
        return ":".join([cplookup(cp, name_index), cplookup(cp, descriptor)])

    elif cp[index].tag == classutils.CONSTANT_Utf8:
        return str(cp[index].info)

    elif cp[index].tag == classutils.CONSTANT_MethodHandle:
        reference_kind, reference_index, = struct.unpack(">HH", str(cp[index].info))
        return ":".join([classutils.REFERENCE_KINDS[reference_kind], cplookup(cp, reference_index)])

    elif cp[index].tag == classutils.CONSTANT_MethodType:
        descriptor_index, = struct.unpack(">H", str(cp[index].info))
        return cplookup(cp, descriptor_index)

    elif cp[index].tag == classutils.CONSTANT_InvokeDynamic:
        boostrap_method_attr_index, name_and_type_index, = struct.unpack(">HH", str(cp[index].info))
        # FIXME (BUG): bootstrap_methods etc.
        return cplookup(cp, name_and_type_index)

    else:
        raise RuntimeError("Unexpected tag")

# opcode types
__OPCODE = 'opcode'
__LCL = 'lcl'
__CPOOL = 'cpool'
__COND = 'cond'

# http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html#jvms-6.5

opcode_dict = {
    0x32    :   ("aaload", __OPCODE),
    0x53    :   ("aastore", __OPCODE),
    0x1     :   ("aconst_null", __OPCODE),
    0x19    :   ("aload", __LCL),
    0x2a    :   ("aload_0", __OPCODE),
    0x2b    :   ("aload_1", __OPCODE),
    0x2c    :   ("aload_2", __OPCODE),
    0x2d    :   ("aload_3", __OPCODE),
    0xbd    :   ("anewarray", __CPOOL),
    0xb0    :   ("areturn", __OPCODE),
    0xbe    :   ("arraylength", __OPCODE),
    0x3a    :   ("astore", __LCL),
    0x4b    :   ("astore_0", __OPCODE),
    0x4c    :   ("astore_1", __OPCODE),
    0x4d    :   ("astore_2", __OPCODE),
    0x4e    :   ("astore_3", __OPCODE),
    0xbf    :   ("athrow", __OPCODE),
    0x33    :   ("baload", __OPCODE),
    0x54    :   ("bastore", __OPCODE),
    0x10    :   ("bipush", None),
    0x34    :   ("caload", __OPCODE),
    0x55    :   ("castore", __OPCODE),
    0xc0    :   ("checkcast", __CPOOL),
    0x90    :   ("d2f", __OPCODE),
    0x8e    :   ("d2i", __OPCODE),
    0x8f    :   ("d2l", __OPCODE),
    0x63    :   ("dadd", __OPCODE),
    0x31    :   ("daload", __OPCODE),
    0x52    :   ("dastore", __OPCODE),
    0x98    :   ("dcmpg", __OPCODE),
    0x97    :   ("dcmpl", __OPCODE),
    0xe     :   ("dconst_0", __OPCODE),
    0xf     :   ("dconst_1", __OPCODE),
    0x6f    :   ("ddiv", __OPCODE),
    0x18    :   ("dload", __LCL),
    0x26    :   ("dload_0", __OPCODE),
    0x27    :   ("dload_1", __OPCODE),
    0x28    :   ("dload_2", __OPCODE),
    0x29    :   ("dload_3", __OPCODE),
    0x6b    :   ("dmul", __OPCODE),
    0x77    :   ("dneg", __OPCODE),
    0x73    :   ("drem", __OPCODE),
    0xaf    :   ("dreturn", __OPCODE),
    0x39    :   ("dstore", __LCL),
    0x47    :   ("dstore_0", __OPCODE),
    0x48    :   ("dstore_1", __OPCODE),
    0x49    :   ("dstore_2", __OPCODE),
    0x4a    :   ("dstore_3", __OPCODE),
    0x67    :   ("dsub", __OPCODE),
    0x59    :   ("dup", __OPCODE),
    0x5a    :   ("dup_x1", __OPCODE),
    0x5b    :   ("dup_x2", __OPCODE),
    0x5c    :   ("dup2", __OPCODE),
    0x5d    :   ("dup2_x1", __OPCODE),
    0x5e    :   ("dup2_x2", __OPCODE),
    0x8d    :   ("f2d", __OPCODE),
    0x8b    :   ("f2i", __OPCODE),
    0x8c    :   ("f2l", __OPCODE),
    0x62    :   ("fadd", __OPCODE),
    0x30    :   ("faload", __OPCODE),
    0x51    :   ("fastore", __OPCODE),
    0x96    :   ("fcmp<g>", __OPCODE),
    0x95    :   ("fcmp<l>", __OPCODE),
    0xb     :   ("fconst_0", __OPCODE),
    0xc     :   ("fconst_1", __OPCODE),
    0xd     :   ("fconst_2", __OPCODE),
    0x6e    :   ("fdiv", __OPCODE),
    0x17    :   ("fload", __LCL),
    0x22    :   ("fload_0", __OPCODE),
    0x23    :   ("fload_1", __OPCODE),
    0x24    :   ("fload_2", __OPCODE),
    0x25    :   ("fload_3", __OPCODE),
    0x6a    :   ("fmul", __OPCODE),
    0x76    :   ("fneg", __OPCODE),
    0x72    :   ("frem", __OPCODE),
    0xae    :   ("freturn", __OPCODE),
    0x38    :   ("fstore", __OPCODE),
    0x43    :   ("fstore_0", __OPCODE),
    0x44    :   ("fstore_1", __OPCODE),
    0x45    :   ("fstore_2", __OPCODE),
    0x46    :   ("fstore_3", __OPCODE),
    0x66    :   ("fsub", __OPCODE),
    0xb4    :   ("getfield", __CPOOL),  # refs constant pool (index byte, index byte)
    0xb2    :   ("getstatic", __CPOOL),  # refs constant pool (index byte, index byte)
    0xa7    :   ("goto", __COND),
    0xc8    :   ("goto_w", None),
    0x91    :   ("i2b", __OPCODE),
    0x92    :   ("i2c", __OPCODE),
    0x87    :   ("i2d", __OPCODE),
    0x86    :   ("i2f", __OPCODE),
    0x85    :   ("i2l", __OPCODE),
    0x93    :   ("i2s", __OPCODE),
    0x60    :   ("iadd", __OPCODE),
    0x2e    :   ("iaload", __OPCODE),
    0x7e    :   ("iand", __OPCODE),
    0x4f    :   ("iastore", __OPCODE),
    0x2     :   ("iconst_m1", __OPCODE),
    0x3     :   ("iconst_0", __OPCODE),
    0x4     :   ("iconst_1", __OPCODE),
    0x5     :   ("iconst_2", __OPCODE),
    0x6     :   ("iconst_3", __OPCODE),
    0x7     :   ("iconst_4", __OPCODE),
    0x8     :   ("iconst_5", __OPCODE),
    0x6c    :   ("idiv", __OPCODE),
    0xa5    :   ("if_acmpeq", __COND),
    0xa6    :   ("if_acmpne", __COND),
    0x9f    :   ("if_icmpeq", __COND),
    0xa0    :   ("if_icmpne", __COND),
    0xa1    :   ("if_icmplt", __COND),
    0xa2    :   ("if_icmpge", __COND),
    0xa3    :   ("if_icmpgt", __COND),
    0xa4    :   ("if_icmple", __COND),
    0x99    :   ("ifeq", __COND),
    0x9a    :   ("ifne", __COND),
    0x9b    :   ("iflt", __COND),
    0x9c    :   ("ifge", __COND),
    0x9d    :   ("ifgt", __COND),
    0x9e    :   ("ifle", __COND),
    0xc7    :   ("ifnonnull", __COND),
    0xc6    :   ("ifnull", __COND),
    0x84    :   ("iinc", None),
    0x15    :   ("iload", __LCL),
    0x1a    :   ("iload_0", None),
    0x1b    :   ("iload_1", __OPCODE),
    0x1c    :   ("iload_2", __OPCODE),
    0x1d    :   ("iload_3", __OPCODE),
    0x68    :   ("imul", __OPCODE),
    0x74    :   ("ineg", __OPCODE),
    0xc1    :   ("instanceof", __CPOOL),  # refs constant pool (index byte, index byte)
    0xba    :   ("invokedynamic", None),  # refs constant pool (index byte, index byte) (more args)
    0xb9    :   ("invokeinterface", None),  # refs constant pool (index byte, index byte) (more args)
    0xb7    :   ("invokespecial", __CPOOL),  # refs constant pool (index byte, index byte)
    0xb8    :   ("invokestatic", __CPOOL),  # refs constant pool (index byte, index byte)
    0xb6    :   ("invokevirtual", __CPOOL),  # refs constnat pool (index byte, index byte)
    0x80    :   ("ior", __OPCODE),
    0x70    :   ("irem", __OPCODE),
    0xac    :   ("ireturn", __OPCODE),
    0x78    :   ("ishl", __OPCODE),
    0x7a    :   ("ishr", __OPCODE),
    0x36    :   ("istore", __LCL),
    0x3b    :   ("istore_0", __OPCODE),
    0x3c    :   ("istore_1", __OPCODE),
    0x3d    :   ("istore_2", __OPCODE),
    0x3e    :   ("istore_3", __OPCODE),
    0x64    :   ("isub", __OPCODE),
    0x7c    :   ("iushr", __OPCODE),
    0x82    :   ("ixor", __OPCODE),
    0xa8    :   ("jsr", __COND),
    0xc9    :   ("jsr_w", None),
    0x8a    :   ("l2d", __OPCODE),
    0x89    :   ("l2f", __OPCODE),
    0x88    :   ("l2i", __OPCODE),
    0x61    :   ("ladd", __OPCODE),
    0x2f    :   ("laload", __OPCODE),
    0x7f    :   ("land", __OPCODE),
    0x50    :   ("lastore", __OPCODE),
    0x94    :   ("lcmp", __OPCODE),
    0x9     :   ("lconst_0", __OPCODE),
    0xa     :   ("lconst_1", __OPCODE),
    0x12    :   ("ldc", None),  # refs constant pool (index)
    0x13    :   ("ldc_w", __CPOOL),  # refs constant pool (index byte, index byte)
    0x14    :   ("ldc2_w", __CPOOL),  # refs constant pool (index byte, index byte)
    0x6d    :   ("ldiv", __OPCODE),
    0x16    :   ("lload", __LCL),
    0x1e    :   ("lload_0", __OPCODE),
    0x1f    :   ("lload_1", __OPCODE),
    0x20    :   ("lload_2", __OPCODE),
    0x21    :   ("lload_3", __OPCODE),
    0x69    :   ("lmul", __OPCODE),
    0x75    :   ("lneg", __OPCODE),
    0xab    :   ("lookupswitch", None),
    0x81    :   ("lor", __OPCODE),
    0x71    :   ("lrem", __OPCODE),
    0xad    :   ("lreturn", __OPCODE),
    0x79    :   ("lshl", __OPCODE),
    0x7b    :   ("lshr", __OPCODE),
    0x37    :   ("lstore", __LCL),
    0x3f    :   ("lstore_0", __OPCODE),
    0x40    :   ("lstore_1", __OPCODE),
    0x41    :   ("lstore_2", __OPCODE),
    0x42    :   ("lstore_3", __OPCODE),
    0x65    :   ("lsub", __OPCODE),
    0x7d    :   ("lusr", __OPCODE),
    0x83    :   ("lxor", __OPCODE),
    0xc2    :   ("monitorenter", __OPCODE),
    0xc3    :   ("monitorexit", __OPCODE),
    0xc5    :   ("multianewarray", None),  # refs constant pool? (index byte, index byte, dimensions)
    0xbb    :   ("new", __CPOOL),  # refs constant pool (index byte, index byte)
    0xbc    :   ("newarray", None),
    0x0     :   ("nop", __OPCODE),
    0x57    :   ("pop", __OPCODE),
    0x58    :   ("pop2", __OPCODE),
    0xb5    :   ("putfield", __CPOOL),  # refs constant pool (index byte, index byte)
    0xb3    :   ("putstatic", __CPOOL),  # refs constant pool (index byte, index byte)
    0xa9    :   ("ret", __LCL),
    0xb1    :   ("return", __OPCODE),
    0x35    :   ("saload", __OPCODE),
    0x56    :   ("sastore", __OPCODE),
    0x11    :   ("sipush", None),
    0x5f    :   ("swap", __OPCODE),
    0xaa    :   ("tableswitch", None),
    0xc4    :   ("wide", None)
}

opcode_str = { key:opcode_dict[key][0] for key in opcode_dict}

class opcode(object):
    """
    Encapsulates a single opcode and
    associated data.
    """
    def __init__(self, op, value=None):
        self.op = op
        self.val = value

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

def get_interpeter_string(otype, ostr):
    if otype == __OPCODE:
        return '''def interpret_%s(cp, code, registers):
    return opcode(code[pc(registers)])''' % (ostr)
    elif otype in [__LCL, __COND, __CPOOL]:
        return '''def interpret_%s(cp, code, registers):
    return %s(cp, code, registers)''' % (ostr, otype)
    else:
        return '''def interpret_%s(cp, code, registers):
    raise RuntimeError("Not Implemented: %s")''' % (ostr, ostr)

def clean_opcode_string(ostr):
    return ostr.replace('<', '').replace('>', '')

for bytecode in opcode_dict:
    ostr, otype = opcode_dict[bytecode]
    exec(get_interpeter_string(otype, clean_opcode_string(ostr)))

def interpret_bipush(cp, code, registers):
    op = code[pc(registers)]
    step(registers); byte_val = code[pc(registers)]
    return opcode(op, { "byte" : byte_val})

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

def interpret_iinc(cp, code, registers):
    op = code[pc(registers)]
    step(registers); index = code[pc(registers)]
    step(registers); const = code[pc(registers)]
    return opcode(op, { "index" : index, "const" : const })

def interpret_invokedynamic(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers);  # 0
    step(registers);  # 0
    return opcode(op, cplookup(cp, cpindex(indexbyte1, indexbyte2)))

def interpret_invokeinterface(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers); count = code[pc(registers)]
    step(registers);  # 0
    return opcode(op, {
        "name"  : cplookup(cp, cpindex(indexbyte1, indexbyte2)),
        "count" : count
    })

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

def interpret_ldc(cp, code, registers):
    op = code[pc(registers)]
    step(registers)
    return opcode(op, cplookup(cp, code[pc(registers)]))

def interpret_multianewarray(cp, code, registers):
    op = code[pc(registers)]
    step(registers); indexbyte1 = code[pc(registers)]
    step(registers); indexbyte2 = code[pc(registers)]
    step(registers); dimensions = code[pc(registers)]
    return opcode(op, {
        "name"      :   cplookup(cpindex(indexbyte1, indexbyte2)),
        "dimensions":   dimensions
    })

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

def interpret_sipush(cp, code, registers):
    op = code[pc(registers)]
    step(registers); byte1 = code[pc(registers)]
    step(registers); byte2 = code[pc(registers)]
    return opcode(op, {
        "byte" :   byte1,
        "byte2":   byte2
    })

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
    if wide_op == 0x84:
        step(registers); val["constbyte1"] = code[pc(registers)]
        step(registers); val["constbyte2"] = code[pc(registers)]

    return opcode(op, val)

interpreter = {
            b : eval('interpret_%s' % clean_opcode_string(opcode_str[b]))
            for b in opcode_str
        }

def interpret(cp, code):
    registers = {}
    reset(registers)
    codelen = len(code)

    while pc(registers) < codelen:
        op = code[pc(registers)];
        yield interpreter[op](cp, code, registers)
        step(registers)


