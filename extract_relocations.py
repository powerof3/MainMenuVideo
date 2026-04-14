# Extract RELOCATION IDs from Ghidra
# @category Skyrim
# @author Gemini CLI

import yaml
import os
from ghidra.program.model.symbol import SourceTypeType

def run():
    # 1. Find the REL::ID type
    rel_id_type = None
    dtm = currentProgram.getDataTypeManager()
    
    # Try to find REL::ID in various namespaces
    for dt in dtm.getAllDataTypes():
        if dt.getName() == "ID" and "REL" in dt.getPathName():
            rel_id_type = dt
            break
    
    if not rel_id_type:
        print("Error: Could not find REL::ID data type.")
        return

    print("Found REL::ID type: " + rel_id_type.getPathName())

    # 2. Find all data of this type
    results = []
    data_iter = currentProgram.getListing().getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.getDataType().isEquivalent(rel_id_type):
            symbol = currentProgram.getSymbolTable().getPrimarySymbol(data.getAddress())
            if not symbol:
                continue
            
            # The ID value is stored in the 8 bytes at this address
            try:
                id_val = data.getValue().getValue() # For a Scalar or Long
                # If getValue() doesn't work as expected, read bytes directly
                if id_val is None:
                    id_val = getLong(data.getAddress())
                
                results.append({
                    'name': symbol.getName(True),
                    'id': id_val
                })
            except Exception as e:
                print("Error reading ID at " + str(data.getAddress()) + ": " + str(e))

    # 3. Save to YAML
    # We need to distinguish between SE and AE IDs. 
    # Since the user said the first number is 1.5.97, and we are looking at RELOCATIONS,
    # we might have multiple IDs. But if we are in a specific build (AE or SE),
    # the REL::ID will only hold ONE ID.
    
    # User asked for a YAML listing function name and function IDs (for se and ae).
    # This implies we might need to find where both are used.
    # If the user has a source-built PDB, they might have specific structures.
    
    output_path = os.path.join(os.getcwd(), "relocations.yaml")
    with open(output_path, 'w') as f:
        yaml.dump(results, f)
    
    print("Extracted " + str(len(results)) + " relocations to " + output_path)

if __name__ == "__main__":
    run()
