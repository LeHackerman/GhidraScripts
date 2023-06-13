# Attempts to resolve dynamically loaded API calls and replace the functions's name with the called API name.
# @category: Malware.SpyEye

# EXPERIMENTAL ! Many edge cases not considered.
# Addresses are to be changed accordingly.
# A json file should be created first using the supplied script.  

import json
from ghidra.program.model.symbol import SourceType

jsonMapping = askFile("Choose JSON mapping file","Select")
with open(jsonMapping.getAbsolutePath(),"r") as f:
    apiHashMapping = json.load(f)

for ref in getReferencesTo(toAddr("FUN_004036e4")):
    try:
        refAddr = ref.getFromAddress()
        apiHash = int(currentProgram.getListing().getInstructionBefore(refAddr).getPrevious().toString().split(" ")[1],16)
        func = currentProgram.getFunctionManager().getFunctionContaining(refAddr)
        func.setName(apiHashMapping[hex(apiHash).rstrip("L")],SourceType.ANALYSIS)
    except:
        continue

