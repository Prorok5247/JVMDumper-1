# JVMDumper
Injectable dll to dump classes from the jvm.
Inject this dll file into the java process you want to dump the class files from.
It will hook the ClassLoader and write all dumped classes into 'C:\Dump'. 
If the process it is injected into exits all dumped class files will be packed into a .jar archive.
