# Deobfuscate used strings and comment them over the function's codeunit.
# @category: Malware.SpyEye

# EXPERIMENTAL ! Many edge cases not considered.
# Addresses are to be changed accordingly
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import UnsignedLongDataType
from ghidra.program.model.data import UnsignedCharDataType
count=0
# Clear wrong data assignements
currentProgram.getListing().clearCodeUnits(toAddr(0x00405028),toAddr(0x0041502b),False)
currentProgram.getListing().clearCodeUnits(toAddr(0x00405e68),toAddr(0x00415ef8),False)
currentProgram.getListing().clearCodeUnits(toAddr(0x0040502c),toAddr(0x0041502f),False)
currentProgram.getListing().clearCodeUnits(toAddr(0x004050b8),toAddr(0x00415e63),False)

#Create indices Array
currentProgram.getListing().createData(toAddr(0x405028),ArrayDataType(UnsignedLongDataType.dataType,36,4))

# Create Rounds Array
currentProgram.getListing().createData(toAddr(0x405e68),ArrayDataType(UnsignedLongDataType.dataType,36,4))

# Create Obfuscated Strings Array
currentProgram.getListing().createData(toAddr(0x4050b8),ArrayDataType(ArrayDataType(UnsignedCharDataType.dataType,100,1),35,100))

indicesTable = getDataAt(toAddr(0x00405028))

for ref in getReferencesTo(toAddr(0x00401000)):
    refAddr = ref.getFromAddress()
    try:
        prevInstr = currentProgram.getListing().getInstructionBefore(refAddr)
        if prevInstr.toString().startswith("PUSH"):
            prevInstr = prevInstr.toString()
            arg = prevInstr.split(" ")[1]
        elif prevInstr.toString().startswith("RET"):
            pass
        else:
            prevInstr = prevInstr.getPrevious().toString()
            arg = prevInstr.split(" ")[1]
    except:
        continue
    counter = 0
    for i in range(36):
        el = indicesTable.getComponent(i).toString()
        try:
                if int(el.split(" ")[1].rstrip("h"),16) == int(arg,16):
                        break
        except:
                continue
        counter += 1
    rounds = int(getDataAt(toAddr(0x405e68)).getComponent(counter).toString().split(" ")[1].rstrip("h"),16)
    obfString = getDataAt(toAddr(0x4050b8)).getComponent(counter).bytes
    obfString = obfString.tostring()
    deobfString = ""
    for i in range(rounds-1,-1,-1):
        deobfString = chr((ord(obfString[i]) - ord(obfString[i-1]))&0xff) + deobfString
    codeUnit = currentProgram.getListing().getCodeUnitAt(refAddr)
    count+=1
    codeUnit.setComment(codeUnit.PRE_COMMENT, deobfString)

