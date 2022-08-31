# This script converts circuits given in bristol format (https://homes.esat.kuleuven.be/~nsmart/MPC/)
# into graph in the DOT language (https://www.graphviz.org/doc/info/lang.html). This allows visualization with the graphviz tool (https://www.graphviz.org/)

# How To:
#   1. Execute this script with python3 BristolToDot.py
#   2. Use dot to generate svg: dot -Tsvg dotFile.dot > output.svg
#   3. Open the svg


pathBristolFile = "emp-tool/emp-tool/circuits/files/bristol_format/AES-non-expanded.txt"
#pathBristolFile = "testSimpleBristol.txt"
pathDOTFile = "dotFile.dot"
f = open(pathBristolFile, 'r')

# first line is number of gates and number of wires
l = f.readline()
s = l.split(' ')
nrGates = int(s[0])
nrWires = int(s[1])
## second line is number of inputs and number of wires per input
#l = f.readline()
#s = l.split(' ')
#nrInputWiresTotal = 0
#for i in range(int(s[0])):
    #print(s[i+1])
    #nrInputWiresTotal += int(s[i+1])
## third line is number of outputs and wires per output
#l = f.readline()
#s = l.split(' ')
#nrOutputWiresTotal = 0
#for i in range(int(s[0])):
    #nrOutputWiresTotal += int(s[i+1])

#--- EMP does not follow the actual Bristol format specification
l = f.readline()
s = l.split(' ')
nrInputWiresTotal = int(s[0])+int(s[1])
print(nrInputWiresTotal)
nrOutputWiresTotal = int(s[4])
print(nrOutputWiresTotal)

f.readline() # blank line


outWireToNode = {} # maps outgoing wire numbers to nodes
dot = "digraph { \n"
for g in range(nrGates):
    l = f.readline()
    print(l)
    if l == "\n": continue
    s = l.split(' ')
    print(s)
    nrIns = int(s[0])
    nrOuts = int(s[1])
    # remember name (xor/and) of this node for outgoing edges and add output nodes
    for i in range(nrOuts):
        thisNode = '"' + s[2+nrIns+nrOuts].strip() + " " + str(g) + '"'
        if int(s[2+nrIns+i]) >= nrWires - nrOutputWiresTotal:
            dot += (thisNode + "->" + s[2+nrIns+i] + ";\n") # if output wire, just write number
        else:
            outWireToNode[s[2+nrIns+i]] = thisNode
    # add incoming edges to file
    for i in range(nrIns):
        print("s2i " + s[2+i])
        print(int(s[2+i]))
        if int(s[2+i]) < nrInputWiresTotal:
            a = str(s[2+i]) # if input wire, just write number
        else:
            a = outWireToNode[s[2+i]]
        b = '"' + s[2+nrIns+nrOuts].strip() + " " + str(g) + '"'
        dot += (a + " -> " + b + ";\n")
 
dot += "}"
print(outWireToNode)
print(dot)
o = open(pathDOTFile, 'w')
o.write(dot)



