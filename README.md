# Export to JSON Plugin:
This simple plugin iterates through the binary and extracts the MLIL instructions and properties, storing them in a JSON file in tmp.  Runs in non-headless mode through the GUI interface as 'Export to JSON'.

## Disclaimer:
* This currently runs through all functions instead of only select ones. 

## TODO:
 * Taking suggestions.
 
## Example output:
```
{
    "functions": [
        {
            "name": "0x40179c",            
            "basic_blocks": "<block: x86@0x0-0x1>", 
            "blocks": [
                {
                    "name": "0x0-0x1",                    
                    "start": "0x0",                    
                    "end": "0x1", 
                    "instructions": [
                        {
                            "asm_addr": "0x40179c", 
                            "branch_dep_cond": "", 
                            "branch_dep_from": "", 
                            "dest": "GDI32!SetBkMode", 
                            "index": 0, 
                            "instr": "return GDI32!SetBkMode()", 
                            "poss_values": "undetermined", 
                            "src": "", 
                            "vars_read": [], 
                            "vars_read_type": [], 
                            "vars_written": "ecx", 
                            "vars_written_type": "int32_t"
                        }
                    ], 
                }
            ] 
```
