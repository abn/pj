import io
import struct

# Based off spec: 
# http://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
#
# java = Big Endian 
# u1 = 8-bit
# u2 = 16-bit 
# u4 = 32-bit
# 
#  ClassFile {
#        u4 magic;
#        u2 minor_version;
#        u2 major_version;
#        u2 constant_pool_count;
#        cp_info constant_pool[constant_pool_count-1];
#        u2 access_flags;
#        u2 this_class;
#        u2 super_class;
#        u2 interfaces_count;
#        u2 interfaces[interfaces_count];
#        u2 fields_count;
#        field_info fields[fields_count];
#        u2 methods_count;
#        method_info methods[methods_count];
#        u2 attributes_count;
#        attribute_info attributes[attributes_count];
#}
class ClassData(object):
    
    def __init__(self, f):
        
        self.magic              = read_magic(f)
        self.major, self.minor  = read_version(f)
        self.constant_pool      = read_constant_pool(f)
        self.access_flags       = read_access_flags(f)
        self.this_class         = read_this_class(f)
        self.super_class        = read_super_class(f)
        self.interfaces         = read_interfaces(f)
        self.fields             = read_fields(f)
        self.methods            = read_methods(f)
        self.attributes         = read_attributes(f)

# Magic Number 
def read_magic(f):
    
    fmt = ">4B"
    buf = f.read(struct.calcsize(fmt))
    cafebabe = list(struct.unpack(fmt, buf))
    assert(cafebabe == [ 0xca, 0xfe, 0xba, 0xbe ])
    return cafebabe 


# Java major version
JSE7    = 0x33 
JSE6    = 0x32 
JSE5    = 0x31 
JDK14   = 0x30
JDK13   = 0x2F
JDK12   = 0x2E
JDK11   = 0x2D

def major_version(ver):
    return {
        0x33 : "JSE7",
        0x32 : "JSE6", 
        0x31 : "JSE5", 
        0x30 : "JDK 1.4",
        0x2F : "JDK 1.3",
        0x2E : "JDK 1.2",
        0x2D : "JDK 1.1",
    }.get(ver, "Unkown")
    

def read_version(f): 
    fmt = ">HH"
    buf = f.read(struct.calcsize(fmt))
    minor, major = struct.unpack(fmt, buf)
    return (major, minor)


# Access Kinds 
ACC_PUBLIC      = 0x0001
ACC_PRIVATE     = 0x0002
ACC_PROTECTED   = 0x0004
ACC_STATIC      = 0x0008
ACC_FINAL       = 0x0010
ACC_SUPER       = 0x0020 # Classes
ACC_SYNCHRONIZED= 0x0020 # Methods
ACC_VOLATILE    = 0x0040
ACC_TRANSIENT   = 0x0080
ACC_NATIVE      = 0x0100
ACC_INTERFACE   = 0x0200
ACC_ABSTRACT    = 0x0400
ACC_STRICT      = 0x0800
ACC_SYNTHETIC   = 0x1000
ACC_ANNOTATION  = 0x2000
ACC_ENUM        = 0x4000


def read_access_flags(f): 

    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    flags, = struct.unpack(fmt, buf)

    return flags

def access_flags(flags, is_class=False): 

    flagstr = [] 

    if flags & ACC_PUBLIC == ACC_PUBLIC:
        flagstr.append("public")

    if flags & ACC_PRIVATE == ACC_PRIVATE:
        flagstr.append("private")       

    if flags & ACC_PROTECTED == ACC_PROTECTED:
        flagstr.append("protected")     

    if flags & ACC_STATIC == ACC_STATIC:
        flagstr.append("static")        

    if flags & ACC_FINAL  == ACC_FINAL :
        flagstr.append("final")

    if is_class and (flags & ACC_SUPER == ACC_SUPER):
        flagstr.append("super")         

    if not is_class and (flags & ACC_SYNCHRONIZED == ACC_SYNCHRONIZED):
        flagstr.append("synchronized")  

    if flags & ACC_VOLATILE == ACC_VOLATILE:
        flagstr.append("volatile")      

    if flags & ACC_TRANSIENT == ACC_TRANSIENT:
        flagstr.append("transient")     

    if flags & ACC_NATIVE == ACC_NATIVE:
        flagstr.append("native")        

    if flags & ACC_INTERFACE == ACC_INTERFACE:
        flagstr.append("interface")     

    if flags & ACC_ABSTRACT == ACC_ABSTRACT:
        flagstr.append("abstract")      

    if flags & ACC_STRICT == ACC_STRICT:
        flagstr.append("strict")        

    if flags & ACC_SYNTHETIC == ACC_SYNTHETIC:
        flagstr.append("synthetic")    

    if flags & ACC_ANNOTATION == ACC_ANNOTATION:
        flagstr.append("annotation")    

    if flags & ACC_ENUM == ACC_ENUM:
        flagstr.append("enum")          

    return flagstr


def read_this_class(f):

    fmt = ">H"
    buf = f.read(struct.calcsize(fmt)) 
    idx, = struct.unpack(fmt, buf)

    return idx
    
def read_super_class(f):
    
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    idx, = struct.unpack(fmt, buf)

    return idx


# CONSTANT Tags
CONSTANT_Class              = 7
CONSTANT_FieldRef           = 9 
CONSTANT_MethodRef          = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String             = 8
CONSTANT_Integer            = 3 
CONSTANT_Float              = 4
CONSTANT_Long               = 5
CONSTANT_Double             = 6
CONSTANT_NameAndType        = 12
CONSTANT_Utf8               = 1
CONSTANT_MethodHandle       = 15
CONSTANT_MethodType         = 16
CONSTANT_InvokeDynamic      = 18

# Constant Pool 
def read_constant_pool(f):
    
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    constant_pool_count,  = struct.unpack(fmt, buf)

    # Historic reasons: constant_pool[constant_pool_count-1]
    n = 1 
    constant_pool = {}  

    while n < constant_pool_count :

        info = read_cp_info(f)
        constant_pool[n] = info

        n += 1
        # All 8-byte constants take up two entries in the constant_pool table of the class file
        if info.tag == CONSTANT_Double or info.tag == CONSTANT_Long:
            n += 1 

    return constant_pool

tagname_str = {
    CONSTANT_Class              : "CONSTANT_Class",
    CONSTANT_FieldRef           : "CONSTANT_FieldRef",
    CONSTANT_MethodRef          : "CONSTANT_MethodRef",
    CONSTANT_InterfaceMethodref : "CONSTANT_InterfaceMethodref",
    CONSTANT_String             : "CONSTANT_String" ,
    CONSTANT_Integer            : "CONSTANT_Integer", 
    CONSTANT_Float              : "CONSTANT_Float",  
    CONSTANT_Long               : "CONSTANT_Long",  
    CONSTANT_Double             : "CONSTANT_Double",  
    CONSTANT_NameAndType        : "CONSTANT_NameAndType",
    CONSTANT_Utf8               : "CONSTANT_Utf8",
    CONSTANT_MethodHandle       : "CONSTANT_MethodHandle", 
    CONSTANT_MethodType         : "CONSTANT_MethodType", 
    CONSTANT_InvokeDynamic      : "CONSTANT_InvokeDynamic", 

}


# cp_info { 
#    u1 tag;
#    u1 info[];
# }
class cp_info(object):

    def __init__(self, tag, info):
        self.tag  = tag
        self.info = info

    def __str__(self):
        tagname = tagname_str.get(self.tag, "Unknown")
        info = ''.join(hex(byte) for byte in self.info)
        if self.tag == CONSTANT_Utf8:
            info = str(self.info)

        return "{ tag : %s, info : %s }" % (tagname, info)

def read_cp_info(f):

    tag = ord(f.read(1))
    info = None

    # CONSTANT_Class_info {
    #   u1 tag
    #   u2 name_index
    # }
    if CONSTANT_Class == tag:
        info = bytearray(2)

    # CONSTANT_Fieldref_info {
    #    u1 tag;
    #    u2 class_index;
    #    u2 name_and_type_index;
    # }
    elif CONSTANT_FieldRef == tag: 
        info = bytearray(4)

    # CONSTANT_MethodRefref_info {
    #    u1 tag;
    #    u2 class_index;
    #    u2 name_and_type_index;
    # }
    elif CONSTANT_MethodRef == tag:
        info = bytearray(4)

    # CONSTANT_InterfaceMethodref_info {
    #    u1 tag;
    #    u2 class_index;
    #    u2 name_and_type_index;
    # }
    elif CONSTANT_InterfaceMethodref == tag: 
        info = bytearray(4)

    # CONSTANT_String_info {
    #   u1 tag
    #   u2 string_index
    # }
    elif CONSTANT_String == tag:
        info = bytearray(2)

    # CONSTANT_Integer_info {
    #   u1 tag
    #   u4 bytes
    # }
    elif CONSTANT_Integer == tag:
        info = bytearray(4)

    # CONSTANT_Float_info {
    #   u1 tag
    #   u4 bytes
    # }
    # Float value is converted into an int first then...
    # If bits is 0x7f800000, the float value will be positive infinity.
    # If bits is 0xff800000, the float value will be negative infinity.
    # If bits is in the range 0x7f800001 through 0x7fffffff or in the range 0xff800001 through 0xffffffff, the float value will be NaN.
    # In all other cases, let s, e, and m be three values that might be computed from bits:
    #       int s = ((bits >> 31) == 0) ? 1 : -1;
    #       int e = ((bits >> 23) & 0xff);
    #       int m = (e == 0) ?
    #           (bits & 0x7fffff) << 1 :
    #           (bits & 0x7fffff) | 0x800000;
    elif CONSTANT_Float == tag: 
        info = bytearray(4)

    # CONSTANT_Long_Info {
    #   u1 tag
    #   u4 high_bytes
    #   u4 low_bytes
    #}
    elif CONSTANT_Long == tag: 
        info = bytearray(8)

    # CONSTANT_Double_Info {
    #   u1 tag
    #   u4 high_bytes
    #   u4 low_bytes
    #}
    #
    # The value reprented by the CONSTANT_Double_info structure is determined as follows. 
    # The high_bytes and low_bytes items are first converted into the long constant bits, which is equal 
    # to ((long) high_bytes << 32) + low_bytes. Then:
    # If bits is 0x7ff0000000000000L, the double value will be positive infinity.
    # If bits is 0xfff0000000000000L, the double value will be negative infinity.
    # If bits is in the range 0x7ff0000000000001L through 0x7fffffffffffffffL or in the 
    #    range 0xfff0000000000001L through 0xffffffffffffffffL, the double value will be NaN.
    #
    # In all other cases, let s, e, and m be three values that might be computed from bits:
    #        int s = ((bits >> 63) == 0) ? 1 : -1;
    #        int e = (int)((bits >> 52) & 0x7ffL);
    #        long m = (e == 0) ?
    #        (bits & 0xfffffffffffffL) << 1 :
    #        (bits & 0xfffffffffffffL) | 0x10000000000000L;
    elif CONSTANT_Double == tag: 
        info = bytearray(8)

    # CONSTANT_NameAndType_info {
    #   u1 tag;
    #   u2 name_index;
    #   u2 descriptor_index;
    # }
    elif CONSTANT_NameAndType == tag: 
        info = bytearray(4)

    # CONSTANT_Utf8_info {
    #    u1 tag;
    #    u2 length;
    #    u1 bytes[length];
    # }
    elif CONSTANT_Utf8 == tag: 
        fmt = ">H"
        buf = f.read(struct.calcsize(fmt))
        length, = struct.unpack(fmt, buf) 
        info = bytearray(length)

    # CONSTANT_MethodHandle_info {
    #   u1 tag
    #   u1 reference_kind
    #   u2 reference_index
    # }
    elif CONSTANT_MethodHandle == tag: 
        info = bytearray(3)

    # CONSTANT_MethodType_info {
    #   u1 tag
    #   u2 descriptor_index
    #}
    elif CONSTANT_MethodType == tag:
        info = bytearray(2)

    # CONSTANT_InvokeDynamic_info {
    #   u1 tag 
    #   u2 boostrap_metho_attr_index
    #   u2 name_and_type_index
    #}
    elif CONSTANT_InvokeDynamic == tag:
        info = bytearray(4)

    # barf!
    else:
        print "ERROR: Unknown tag! (", tag, ")"
        assert(tag == None)
        
    # Read in bytes
    if info != None: 
        f.readinto(info)

    return cp_info(tag, info)


#
# Interfaces: 
#
def read_interfaces(f):

    # Read count
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    interface_count, =  struct.unpack(fmt, buf)

    # Read indexes
    fmt = ">%dH" % interface_count
    buf = f.read(struct.calcsize(fmt))
    interfaces = list(struct.unpack(fmt, buf))

    return interfaces

#
# Fields
#

# u2 fields_count;
# field_info fields[fields_count];
def read_fields(f):
    
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    fields_count, = struct.unpack(fmt, buf)

    fields = [] 
    for field in range(0, fields_count):
        fields.append(read_field(f))

    return fields

# field_info {
#   u2 access_flags
#   u2 name_index
#   u2 descriptor_index
#   u2 attribute_count
#   attributes[attribute_count]
# }
class field_info(object):
    
    def __init__(self, flags, name, desc, attributes): 
        self.access_flags   = flags
        self.name_index     = name
        self.attributes     = attributes
        self.descriptor_index = desc

    def __str__(self):

        attributes = "(begin)" 
        for attrib in self.attributes:
            attributes += str(attrib)
            attributes += ","

        attributes += "(end)"

        return """
        Field Information
        { 
            access_flags        : %d, 
            name_index          : %d, 
            descriptor_index    : %d, 
            attributes:         : %s

        }""" % (self.access_flags, self.name_index, self.descriptor_index, attributes)
            
        
def read_field(f):

    fmt = ">HHHH"
    buf = f.read(struct.calcsize(fmt))
    access_flags, name_index, descriptor_index, attribute_count  = struct.unpack(fmt, buf)

    attributes = [] 
    for attribute in range(0, attribute_count):
        attributes.append(read_attribute_info(f))

    return field_info(access_flags, name_index, descriptor_index, attributes)


#
# Methods
#

# u2 methods_count;
# method_info methods[methods_count];
def read_methods(f):
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    method_count, = struct.unpack(fmt, buf)

    methods = [] 
    for method in range(0, method_count):
        methods.append(read_method(f))

    return methods

# method_info {
#   u2 access_flags
#   u2 name_index
#   u2_descriptor_index
#   u2 attribute_count
#    attribute_info attributes[attributes_count]
#   
# }
class method_info(object):
    
    def __init__(self, flags, name, desc, attribs):
        
        self.access_flags       = flags
        self.name_index         = name
        self.descriptor_index   = desc
        self.attributes         = attribs
    
    def __str__(self):

        attributes = "(begin)" 
        for attrib in self.attributes:
            attributes += str(attrib)
            attributes += ","

        attributes += "(end)"
        return """
        Method Information
        { 
            access_flags        : %d, 
            name_index          : %d, 
            descriptor_index    : %d, 
            attributes:         : %s

        }""" % (self.access_flags, self.name_index, self.descriptor_index, attributes)
         


def read_method(f):

    fmt = ">HHHH"
    buf = f.read(struct.calcsize(fmt))
    access_flags, name_index, descriptor_index, attribute_count  = struct.unpack(fmt, buf)

    attributes = [] 
    for attribute in range(0, attribute_count):
        attributes.append(read_attribute_info(f))

    return method_info(access_flags, name_index, descriptor_index, attributes)


#
# Attributes
#

# u2 attributes_count;
# attribute_info attributes[attributes_count];
def read_attributes(f):
    
    fmt = ">H"
    buf = f.read(struct.calcsize(fmt))
    attributes_count, = struct.unpack(fmt, buf)
    
    attributes = []
    for attribute in range(0, attributes_count):
        attributes.append(read_attribute_info(f))

    return attributes


#
# attribute_info {
#   u2 attribute_name_index
#   u4 attribute_length
#   u1 info[attribute_length]
#}

class attribute_info(object):
    
    def __init__(self, name_index, info):
        
        self.attribute_name_index = name_index
        self.info = info
        
    def __str__(self):
        
        info = ''.join(hex(byte) for byte in self.info)
        return """ 
            Attribute: 
            {
                attribute_name_index : %d, 
                info       : %s
            }""" % (self.attribute_name_index, info)


def read_attribute_info(f):

    fmt = ">HI"
    buf = f.read(struct.calcsize(fmt))
    attribute_name_index, attribute_length =  struct.unpack(fmt, buf)
    info = bytearray(attribute_length)    
    f.readinto(info)

    return attribute_info(attribute_name_index, info)


REFERENCE_KINDS = [
   "UNDEFINED",
   "REF_getField",
   "REF_getStatic",
   "REF_putField",
   "REF_putStatic",
   "REF_invokeVirtual",
   "REF_invokeStatic",
   "REF_invokeSpecial",
   "REF_newInvokeSpecial",
   "REF_invokeInterface",
]


# Code_attribute {
#    u2 attribute_name_index;
#    u4 attribute_length;
#    u2 max_stack;
#    u2 max_locals;
#    u4 code_length;
#    u1 code[code_length];
#    u2 exception_table_length;
#    {   
#        u2 start_pc;
#        u2 end_pc;
#        u2 handler_pc;
#        u2 catch_type;
#    } exception_table[exception_table_length];
#    u2 attributes_count;
#    attribute_info attributes[attributes_count];
#}
class code_attribute(object):
    
    def __init__(self, attribute):

        self.attribute_name_index = attribute.attribute_name_index
        f = io.BytesIO(attribute.info) 
        
        fmt = ">H"
        buf = f.read(struct.calcsize(fmt))
        self.max_stack, = struct.unpack(fmt, buf)

        fmt = ">H"
        buf = f.read(struct.calcsize(fmt))
        self.max_locals, = struct.unpack(fmt, buf)

        fmt = ">I"
        buf = f.read(struct.calcsize(fmt))
        self.code_length, = struct.unpack(fmt, buf)

        self.code = bytearray(self.code_length)
        f.readinto(self.code)

        fmt = ">H"
        buf = f.read(struct.calcsize(fmt))
        self.exception_table_length, = struct.unpack(fmt, buf)
        
        self.exception_table = []
        for i in range(0, self.exception_table_length):
            fmt = ">HHHH"
            buf = f.read(struct.calcsize(fmt))
            start_pc, end_pc, handler_pc, catch_type, = struct.unpack(fmt, buf)
            self.exception_table.append({
                "start_pc"  : start_pc, 
                "end_pc"    : end_pc, 
                "handler_pc": handler_pc, 
                "catch_type": catch_type
            })
        
        fmt = ">H"
        buf = f.read(struct.calcsize(fmt))
        self.attributes_count, = struct.unpack(fmt, buf)

        self.attributes = []
        for i in range(0, self.attributes_count):
            self.attributes.append(read_attribute_info(f))


