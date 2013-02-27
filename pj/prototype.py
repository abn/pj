import sys
import hashlib
import javaclass
from clint.textui import puts, columns 

for file in sys.argv[1:]:

    f = open(file)
    j = javaclass.JavaClass(f)
    f.close()
    
    # This is pretty much just javap -verbose
    hash_data = str(j)
    puts(hash_data)

    h = hashlib.new("sha1")
    h.update(hash_data)
    puts(columns([h.hexdigest(), 50], [file, 100]))


