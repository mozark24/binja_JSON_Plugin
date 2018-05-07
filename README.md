# Export to JSON Plugin:
This simple plugin iterates through the binary and extracts the MLIL instructions and properties, storing them in a JSON file in tmp. 

## Disclaimer:
* This currently runs through all functions instead of only select ones. 

## TODO:
 * Replace call instruction addresses with symbol names where applicable.
 * Taking suggestions.
 
## Example output:
```
{
    "functions": [
        {
            "name": "x86@0x401000"
            "blocks": [
                {
                    "name": "x86@0x0-0x4"
                    "instructions": [
                        {
                            "asm_addr": "0x401000", 
                            "index": 0, 
                            "instr": "var_4 = 0"
                        }, 
                        {
                            "asm_addr": "0x401002", 
                            "index": 1, 
                            "instr": "eax = 0x40178a(0)"
                        }, 
```