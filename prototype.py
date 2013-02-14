import sys
import hashlib
import javaclass
from clint.textui import puts, columns 

for file in sys.argv[1:]:

    f = open(file)
    j = javaclass.JavaClass(f)
    f.close()

    h = hashlib.new("sha1")
    h.update(str(j))
    puts(columns([h.hexdigest(), 50], [file, 100]))


