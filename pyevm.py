#!/usr/bin/env python3
import json
import math
import sha3

def evm(code):
    bytestring = code.hex()
    stack = []
    memory = {}

    highest_accessed_memory = 0

    while len(bytestring) > 0:
        next_inst = int(bytestring[:2], 16)
        bytestring = bytestring[2:]

        if next_inst == 0:
            return stack

        elif next_inst == 1:
            result = overflower(stack[0] + stack[1])
            stack = [result] + stack[2:]
        
        elif next_inst == 2:
            result = overflower(stack[0] * stack[1])
            stack = [result] + stack[2:]
       
        elif next_inst == 3:
            result = overflower(stack[0] - stack[1])
            stack = [result] + stack[2:]
        
        elif next_inst == 4:
            if stack[1] == 0:
                result = 0
            else:
                result = overflower(stack[0] // stack[1])
            stack = [result] + stack[2:]
        
        elif next_inst == 5:
            if stack[1] == 0:
                result = 0
            else:
                result = overflower(twos_comp(stack[0]) // twos_comp(stack[1]))
            stack = [result] + stack[2:]
        
        elif next_inst == 6:
            if stack[1] == 0: result = 0
            else:
                result = stack[0] % stack[1]
            stack = [result] + stack[2:]

        elif next_inst == 7:
            if stack[1] == 0: result = 0
            else:
                result = overflower(twos_comp(stack[0]) % twos_comp(stack[1]))
            stack = [result] + stack[2:]

        elif next_inst == int("10", 16):
            if stack[0] < stack[1]: result = 1
            else: result = 0
            stack = [result] + stack[2:]

        elif next_inst == int("11", 16):
            if stack[0] > stack[1]: result = 1
            else: result = 0
            stack = [result] + stack[2:]

        elif next_inst == int("12", 16):
            if twos_comp(stack[0]) < twos_comp(stack[1]): result = 1
            else: result = 0
            stack = [result] + stack[2:]
        
        elif next_inst == int("13", 16):
            if twos_comp(stack[0]) > twos_comp(stack[1]): result = 1
            else: result = 0
            stack = [result] + stack[2:]
        
        elif next_inst == int("14", 16):
            if stack[0] == stack[1]: result = 1
            else: result = 0
            stack = [result] + stack[2:]
        
        elif next_inst == int("15", 16):
            if stack[0] == 0: result = 1
            else: result = 0
            stack = [result] + stack[1:]

        elif next_inst == int("16", 16):
            result = stack[0] & stack[1]
            stack = [result] + stack[2:]

        elif next_inst == int("17", 16):
            result = stack[0] | stack[1]
            stack = [result] + stack[2:]
        
        elif next_inst == int("18", 16):
            result = stack[0] ^ stack[1]
            stack = [result] + stack[2:]
        
        elif next_inst == int("19", 16):
            result = overflower(~stack[0])
            stack = [result] + stack[1:]
        
        elif next_inst == int("1A", 16):
            if stack[0] > 32: result = 0
            else:
                result = stack[1] >> (248 - (8 * stack[0]))
            stack = [result] + stack[2:]
        
        elif next_inst == int("20", 16):
            value = [memory[i] if i in memory.keys() else 0 for i in range(stack[0], stack[0] + stack[1])]
            if stack[0] + stack[1] > highest_accessed_memory: 
                highest_accessed_memory = math.ceil((stack[0] + stack[1]) / 32) * 32
            hex_value = "".join([hex(i)[2:].zfill(2) for i in value])
            k = sha3.keccak_256()
            k.update(bytes.fromhex(hex_value))
            stack = [int(k.hexdigest(), 16)] + stack[2:]

        
        elif next_inst == int("50", 16):
            stack = stack[1:]
        
        elif next_inst == int("51", 16):
            value = [memory[i] if i in memory.keys() else 0 for i in range(stack[0], stack[0] + 32)]
            if stack[0] + 32 > highest_accessed_memory: 
                highest_accessed_memory = math.ceil((stack[0] + 32) / 32) * 32
            hex_value = "".join([hex(i)[2:].zfill(2) for i in value]) + "00" * (32 - len(value))
            stack = [int(hex_value, 16)] + stack[1:]

        elif next_inst == int("52", 16):
            value = bytes.fromhex(hex(stack[1])[2:].zfill(64))
            for i in range(32):
                memory[stack[0] + i] = value[i] 
            if stack[0] + 32 > highest_accessed_memory: 
                highest_accessed_memory = math.ceil((stack[0] + 32) / 32) * 32
            stack = stack[2:]
        
        elif next_inst == int("53", 16):
            value = bytes.fromhex(hex(stack[1])[-2:])
            memory[stack[0]] = stack[1]
            if stack[0] > highest_accessed_memory: 
                highest_accessed_memory = math.ceil((stack[0]) / 32) * 32
            stack = stack[2:]
        
        elif next_inst == int("56", 16):
            bytestring = code.hex()[stack[0] * 2:]
            stack = stack[1:]
            assert(bytestring[:2] == "5b")
        

        elif next_inst == int("57", 16):
            if stack[1] > 0: 
                bytestring = code.hex()[stack[0] * 2:]
                assert(bytestring[:2] == "5b")
            stack = stack[2:]

        elif next_inst == int("58", 16):
            counter = (len(code.hex()) - (len(bytestring) + 2)) // 2
            stack = [counter] + stack

        elif next_inst == int("59", 16):
            stack = [highest_accessed_memory] + stack
        
        elif next_inst >= int("60", 16) and next_inst <= int("7F", 16):
            bytes_to_append = next_inst - int("60", 16) + 1
            stack = [int(bytestring[0:bytes_to_append * 2], 16)] + stack
            bytestring = bytestring[bytes_to_append * 2:]
            
        elif next_inst >= int("80", 16) and next_inst <= int("8F", 16):
            position_to_duplicate = next_inst - int("80", 16)
            stack = [stack[position_to_duplicate]] + stack

        elif next_inst >= int("90", 16) and next_inst <= int("9F", 16):
            position_to_swap = next_inst - int("90", 16) + 1
            tmp_stack_0 = stack[0]
            stack[0] = stack[position_to_swap]
            stack[position_to_swap] = tmp_stack_0
    
    return stack

def overflower(i, bits=256):
    return i % 2**bits

def twos_comp(val, bits=256):
    if ((val & (1 << (bits - 1))) != 0):
        val = val - (1<<bits)
    return val
   
def test():
    with open('./evm.json') as f:
        data = json.load(f)
        total = len(data)

        for i, test in enumerate(data):
            print("Test #" + str(i + 1), "of", total, test['name'])

            # Note: as the test cases get more complex, you'll need to modify this
            # to pass down more arguments to the evm function
            code = bytes.fromhex(test['code']['bin'])
            stack = evm(code)

            expected_stack = [int(x, 16) if x.startswith("0x") else int(x) for x in test['expect']['stack']]

            if stack != expected_stack:
                print("Stack doesn't match")
                print(" expected:", expected_stack)
                print("   actual:", stack)
                print("")
                print("Test code:")
                print(test['code']['asm'])
                print("")
                print("Progress: " + str(i) + "/" + str(len(data)))
                print("")
                break


if __name__ == '__main__':
    test()