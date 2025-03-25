import argparse
import os
import random
import struct

def update_usage_map(usage_map, offset, size):
    if offset + size < len(usage_map):
        for i in range(size):
            usage_map[offset + i] = 255
    else:
        print("WARNING: Updating the usage map would cause an out of bounds error")

def display_usage_map(usage_map):
    for i, value in enumerate(usage_map):
        if i % 16 == 0:
            # Print the address
            print("{:08x}:".format(i).upper(), end=" ")
        print("{:02x}".format(value).upper(), end=" ")
        if i % 16 == 15:
            print("")

def int_or_hex(value):
    try:
        return int(value)
    except ValueError:
        return int(value, 16)

class MemorySpace:
    def __init__(self, size=1024, base_offset=0, ptr=0):
        self.size = size
        self.data = b'\0' * self.size
        self.base_offset = base_offset
        self.ptr = ptr
        
    def __getitem__(self, key):
        return self.data[key]
        
    def __setitem__(self, key, value):
        self.data = self.data[:key] + value + self.data[key + len(value):]

    def containsAddress(self, address, size=1):
        return self.base_offset <= address and (address + size - 1) < self.base_offset + self.size

class Syscall:
    def __init__(self, address, param_count, unknown_value):
        self.address = address
        self.name = "z_un_{:08x}".format(self.address)
        self.param_count = param_count
        self.unknown_value = unknown_value # This seems be a single flag (True if unknown_value is 0x4000)

def init_syscalls_struct(syscalls_dir_path):
    syscalls_struct = []
    for i in range(2):
        filename = "bd_syscalls_{}.bin".format(i)
        file_path = os.path.join(syscalls_dir_path, filename)
        syscalls = load_syscalls_bin(file_path)
        syscalls_struct.append(syscalls)
    return syscalls_struct
    
def load_syscalls_bin(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    syscalls_count = len(content) // 8
    syscalls = []
    for i in range(syscalls_count):
        read_offset = i * 8
        address = struct.unpack("<I", content[read_offset:read_offset + 4])[0]
        param_count = struct.unpack("<H", content[read_offset + 4:read_offset + 6])[0]
        unknown_value = struct.unpack("<H", content[read_offset + 6:read_offset + 8])[0]
        syscall = Syscall(address, param_count, unknown_value)
        syscalls.append(syscall)
    return syscalls

def writeValueToAddress(value, address, memory_spaces):
    wroteValue = False
    for memory_space in memory_spaces:
        if memory_space.containsAddress(address, size=len(value)):
            memory_space[address - memory_space.base_offset] = value
            wroteValue = True
            break
    if not wroteValue:
        print(f"\tWARNING: Failed to write value to 0x{'{:08x}'.format(address).upper()}")
        
def readValueFromAddress(address, memory_spaces):
    readValue = False
    for memory_space in memory_spaces:
        if memory_space.containsAddress(address, size=len(value)):
            value = memory_space[address - memory_space.base_offset]
            readValue = True
            break
    if not readValue:
        print(f"\tWARNING: Failed to read value from 0x{'{:08x}'.format(address).upper()}")
        return None
    return value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bd_file', help='The input bd file to parse')
    parser.add_argument('syscalls_dir_path', help='The path to the directory containing the syscalls info files')
    parser.add_argument('-p', '--program_counter_display_offset', type=int_or_hex, default=0)
    parser.add_argument('-s', '--stack_ptr_display_offset', type=int_or_hex, default=0)
    parser.add_argument('-t', '--temp_memory_initial_value', type=int_or_hex, default=None)
    parser.add_argument('-w', '--work_ptr_display_offset', type=int_or_hex, default=0)
    parser.add_argument('-I', '--interactive', action="store_true")
    args = parser.parse_args()
    
    # Get the arguments
    pc_display_offset = args.program_counter_display_offset
    stack_ptr_display_offset = args.stack_ptr_display_offset
    if args.temp_memory_initial_value is None:
        temp_memory_initial_value = random.randint(0, 0xFFFFFFFF)
    else:
        temp_memory_initial_value = args.temp_memory_initial_value
    temp_memory_initial_value = temp_memory_initial_value & 0x7FFFFFFC
    work_ptr_display_offset = args.work_ptr_display_offset
    interactive = args.interactive
    input_fn = args.bd_file
    syscalls_path = args.syscalls_dir_path
    
    stack_display_name = "Stack Memory Space"
    temp_display_name = "Temp Memory Space"
    work_display_name = "Work Memory Space"
    
    syscalls = init_syscalls_struct(syscalls_path)
    
    referenced_syscalls = [{}, {}]
    
    print('KH1 BD Parser by Some1fromthedark')
    
    # Read the binary content from the input file
    print(f'Opening {input_fn}')
    with open(input_fn, 'rb') as f:
        bd_content = f.read()
    
    # Initialize file usage map for tracking how much of the bd file is covered by our parser
    file_usage_map = [0 for value in bd_content]
    
    # Parse the BD File
    
    print(f'Parsing {input_fn}')
    
    pc_ptr = 0
    address_stack = []
    stack_memory = MemorySpace(base_offset=stack_ptr_display_offset)
    work_memory = MemorySpace(base_offset=work_ptr_display_offset)
    memory_spaces = [stack_memory, work_memory]
    # Initialize with a value since when a script is initialized it is given a pointer to some struct on the stack
    temp_memory = [temp_memory_initial_value, 4]
    
    return_value = None
    
    # Begin Parsing the bd instructions
    while pc_ptr + 2 <= len(bd_content):
        # Extract the bd instruction info
        instruction_info_bytes = bd_content[pc_ptr: pc_ptr + 2]
        instruction_info = struct.unpack("<H", instruction_info_bytes)[0]
        print("Instruction Info at 0x{}: 0x{}".format("{:08x}".format(pc_ptr + pc_display_offset).upper(), "{:04x}".format(instruction_info).upper()))
        update_usage_map(file_usage_map, pc_ptr, 2)
        pc_ptr += 2
        instruction_type = instruction_info & 0xF
        print(f"\tInstruction Type: {instruction_type}")
        arg_type = (instruction_info >> 4) & 3
        print(f"\tArg Type: {arg_type}")
        augment_type = (instruction_info >> 6) & 3
        print(f"\tAugment Type: {augment_type}")
        sub_instruction_type = (instruction_info >> 8)
        print(f"\tSub-Instruction Type: {sub_instruction_type}")
        if instruction_type == 0:
            if sub_instruction_type < 14:
                if sub_instruction_type == 0:
                    # End of Script?
                    return_value = 0
                    break
                elif sub_instruction_type == 1:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 2:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 3:
                    # pops an address from the stack and jumps to that address
                    pc_ptr = address_stack[-1]
                    address_stack = address_stack[:-1]
                    if pc_ptr == 0:
                        return_value = -1
                        break
                elif sub_instruction_type == 4:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 5:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 6:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 7:
                    # pop value from temp, pop address from temp, write value to address
                    value = temp_memory[-2]
                    address = temp_memory[-4]
                    temp_memory = temp_memory[:-4]
                    print("\tWriting 0x{} to 0x{}".format("{:08x}".format(value).upper(), "{:08x}".format(address).upper()))
                    bin_value = struct.pack("<i", value)
                    writeValueToAddress(bin_value, address, memory_spaces)
                elif sub_instruction_type == 8:
                    return_value = -1
                    break
                elif sub_instruction_type == 9:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 10:
                    raise Exception("Not Implemented")
                elif sub_instruction_type == 11:
                    display_name = temp_display_name
                    if len(temp_memory) > 1:
                        param = temp_memory[-2]
                        print("\tPopping 0x{} from the {}".format("{:08x}".format(param).upper(), display_name))
                        temp_memory = temp_memory[:-2]
                    else:
                        print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                        param = 0
                    value = ~param
                    if value < 0:
                        tmp = struct.pack("<i", value)
                        display_value = struct.unpack("<I", tmp)[0]
                    else:
                        display_value = value
                    print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
                    size = 4
                    temp_memory.append(value)
                    temp_memory.append(size)
                elif sub_instruction_type == 12:
                    # Doesn't do anything?
                    display_name = temp_display_name
                    if len(temp_memory) > 1:
                        param = temp_memory[-2]
                        print("\tPopping 0x{} from the {}".format("{:08x}".format(param).upper(), display_name))
                        temp_memory = temp_memory[:-2]
                    else:
                        print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                        param = 0
                    value = param
                    if value < 0:
                        tmp = struct.pack("<i", value)
                        display_value = struct.unpack("<I", tmp)[0]
                    else:
                        display_value = value
                    print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
                    size = 4
                    temp_memory.append(value)
                    temp_memory.append(size)
                elif sub_instruction_type == 13:
                    raise Exception("Not Implemented")
        elif instruction_type == 1:
            display_name = temp_display_name
            if len(temp_memory) > 1:
                param_1 = temp_memory[-2]
                print("\tPopping 0x{} from the {}".format("{:08x}".format(param_1).upper(), display_name))
                temp_memory = temp_memory[:-2]
            else:
                print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                param_1 = 0
            if len(temp_memory) > 1:
                param_0 = temp_memory[-2]
                print("\tPopping 0x{} from the {}".format("{:08x}".format(param_0).upper(), display_name))
                temp_memory = temp_memory[:-2]
            else:
                print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                param_0 = 0
            value = None
            display_name = temp_display_name
            if arg_type == 0:
                if sub_instruction_type == 0:
                    value = param_0 + param_1
                elif sub_instruction_type == 1:
                    value = param_0 - param_1
                elif sub_instruction_type == 2:
                    value = param_0 * param_1
                elif sub_instruction_type == 3:
                    value = param_0 // param_1
                elif sub_instruction_type == 4:
                    value = param_0 % param_1
                elif sub_instruction_type == 5:
                    value = param_0 & param_1
                elif sub_instruction_type == 6:
                    value = param_0 | param_1
                elif sub_instruction_type == 7:
                    value = param_0 ^ param_1
                elif sub_instruction_type == 8:
                    value = param_0 << (param_1 & 0x1F)
                elif sub_instruction_type == 9:
                    value = param_0 >> (param_1 & 0x1F)
                elif sub_instruction_type == 10:
                    value = 0
                    if param_0 != 0:
                        value = int(param_1 != 0)
                elif sub_instruction_type == 11:
                    if param_0 == 0 and param_1 == 0:
                        value = 0
                    else:
                        value = 1
                else:
                    raise Exception("Invalid Sub-Instruction Type!")
                if value < 0:
                    tmp = struct.pack("<i", value)
                    display_value = struct.unpack("<I", tmp)[0]
                else:
                    display_value = value
                print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
                temp_memory.append(value)
                temp_memory.append(size)
            elif arg_type == 1:
                param_0_type = type(param_0)
                if param_0_type != float:
                    if param_0_type == int:
                        param_0_bytes = struct.pack("<i", param_0)
                    else:
                        raise Exception("Error: Unsupported Conversion")
                    param_0 = struct.unpack("<f", param_0_bytes)[0]
                param_1_type = type(param_1)
                if param_1_type != float:
                    if param_1_type == int:
                        param_1_bytes = struct.pack("<i", param_1)
                    else:
                        raise Exception("Error: Unsupported Conversion")
                    param_1 = struct.unpack("<f", param_1_bytes)[0]
                if sub_instruction_type == 0:
                    value = param_0 + param_1
                elif sub_instruction_type == 1:
                    value = param_0 - param_1
                elif sub_instruction_type == 2:
                    value = param_0 * param_1
                elif sub_instruction_type == 3:
                    value = param_0 / param_1
                else:
                    raise Exception("Invalid Sub-Instruction Type!")
                value_bytes = struct.pack("<f", value)
                display_value = struct.unpack("<I", value_bytes)[0]
                print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
                value = struct.unpack("<i", value_bytes)[0]
            else:
                raise Exception("Invalid Arg Type!")
            size = 4
            temp_memory.append(value)
            temp_memory.append(size)
        elif instruction_type == 2:
            values = []
            if arg_type== 0 or arg_type== 1:
                arg_size = 4
            else: #elif arg_type == 2 or arg_type == 3:
                arg_size = 2
            if pc_ptr + arg_size <= len(bd_content):
                arg_bytes = bd_content[pc_ptr:pc_ptr + arg_size]
                update_usage_map(file_usage_map, pc_ptr, arg_size)
                pc_ptr += arg_size
                if arg_size == 2:
                    arg = struct.unpack("<h", arg_bytes)[0]
                elif arg_size == 4:
                    arg = struct.unpack("<i", arg_bytes)[0]
            if arg_type == 0 or arg_type == 1:
                print("\tReading 0x{} at offset 0x{}".format("{:04x}".format(arg).upper(), "{:08x}".format(pc_ptr - arg_size).upper()))
                values.append((arg, 4))
            elif arg_type == 2:
                if augment_type == 0:
                    value = stack_memory.ptr + stack_memory.base_offset
                elif augment_type == 1:
                    value = work_memory.ptr + work_memory.base_offset
                elif augment_type == 2:
                    data_start_offset = stack_memory.ptr
                    display_name = stack_display_name
                    value = struct.unpack("<i", stack_memory[data_start_offset:data_start_offset + 4])[0]
                    print("\tReading 0x{} from {} at offset 0x{}".format("{:08x}".format(value).upper(), display_name, "{:08x}".format(data_start_offset).upper()))
                else: # elif augment_type == 3:
                    # Add the program counter (from before updating due to reading this argument) to value
                    value = pc_ptr + pc_display_offset - arg_size
                values.append((value + arg, 4))
            else: # elif arg_type == 3:
                if augment_type == 0:
                    data_start_offset = stack_memory.ptr + arg
                    word_count = sub_instruction_type
                    display_name = stack_display_name
                    for i in range(word_count):
                        data_offset = data_start_offset + i * 4
                        value = struct.unpack("<i", stack_memory[data_offset:data_offset + 4])[0]
                        print("\tReading 0x{} from {} at offset 0x{}".format("{:08x}".format(value).upper(), display_name, "{:08x}".format(data_offset).upper()))
                        values.append((value, 4))
                elif augment_type == 1:
                    data_start_offset = work_memory.ptr + arg
                    word_count = sub_instruction_type
                    display_name = work_display_name
                    for i in range(word_count):
                        data_offset = data_start_offset + i * 4
                        value = struct.unpack("<i", work_memory[data_offset:data_offset + 4])[0]
                        print("\tReading 0x{} from {} at offset 0x{}".format("{:08x}".format(value).upper(), display_name, "{:08x}".format(data_offset).upper()))
                        values.append((value, 4))
                elif augment_type == 2:
                    data_start_offset = stack_memory.ptr
                    display_name = stack_display_name
                    value = struct.unpack("<i", stack_memory[data_start_offset:data_start_offset + 4])[0]
                    print("\tReading 0x{} from {} at offset 0x{}".format("{:08x}".format(value).upper(), display_name, "{:08x}".format(data_start_offset).upper()))
                    data_start_offset = value + arg
                    word_count = sub_instruction_type
                    display_name = "Unknown Memory Space"
                    for i in range(word_count):
                        data_offset = data_start_offset + i * 4
                        data_bytes = b''
                        for j in range(4):
                            byte_offset = data_offset + j
                            byte = readValueFromAddress(byte_offset, memory_spaces)
                            data_bytes += byte
                        value = struct.unpack("<i", data_bytes)[0]
                        print("\tReading 0x{} from {} at offset 0x{}".format("{:08x}".format(value).upper(), display_name, "{:08x}".format(data_offset).upper()))
                        values.append((value, 4))
                else: #elif augment_type == 3:
                    raise Exception("ERROR: Invalid Agument Type!")
            display_name = temp_display_name
            for value, size in values:
                if value < 0:
                    tmp = struct.pack("<i", value)
                    display_value = struct.unpack("<I", tmp)[0]
                else:
                    display_value = value
                print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
                temp_memory.append(value)
                temp_memory.append(size)
        elif instruction_type == 3:
            if pc_ptr + 2 <= len(bd_content):
                arg_bytes = bd_content[pc_ptr:pc_ptr + 2]
                update_usage_map(file_usage_map, pc_ptr, 2)
                pc_ptr += 2
                arg = struct.unpack("<h", arg_bytes)[0]
                display_name = "Unknown"
                if augment_type == 0:
                    data_start_offset = stack_memory.ptr + arg
                    data = stack_memory
                    display_offset = stack_memory.base_offset
                    display_name = temp_display_name
                    if len(temp_memory) > 1:
                        value = (temp_memory[-2], temp_memory[-1])
                        print("\tPopping 0x{} from the {}".format("{:08x}".format(value[0]).upper(), display_name))
                        temp_memory = temp_memory[:-2]
                    else:
                        print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                        value = (arg, 2)
                    display_name = stack_display_name
                elif augment_type == 1:
                    data_start_offset = work_memory.ptr + arg
                    data = work_memory
                    display_offset = work_memory.base_offset
                    display_name = temp_display_name
                    if len(temp_memory) > 1:
                        value = (temp_memory[-2], temp_memory[-1])
                        print("\tPopping 0x{} from the {}".format("{:08x}".format(value[0]).upper(), display_name))
                        temp_memory = temp_memory[:-2]
                    else:
                        print("\tWARNING: Missing value on values stack to pop!")
                        value = (arg, 2)
                    display_name = work_display_name
                elif augment_type == 2:
                    data_start_offset = stack_memory.ptr
                    address = stack_memory[data_start_offset]
                    data_start_offset = address + 4
                    data = None
                    for mem_space in memory_spaces:
                        if mem_space.containsAddress(data_start_offset, size=4):
                            data = mem_space
                            break
                    if data is None:
                        data = MemorySpace(size=4, base_offset=data_start_offset)
                        memory_spaces.append(data)
                    display_offset = data.base_offset
                    display_name = temp_display_name
                    if len(temp_memory) > 1:
                        value = (temp_memory[-2], temp_memory[-1])
                        print("\tPopping 0x{} from the {}".format("{:08x}".format(value[0]).upper(), display_name))
                        temp_memory = temp_memory[:-2]
                    else:
                        print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                        value = (arg, 2)
                    display_name = "Unknown Memory Space"
                elif augment_type == 3:
                    raise Exception("ERROR: Invalid Augment Type!")
                value, size = value             
                data_offset = data_start_offset
                if value < 0:
                    tmp = struct.pack("<i", value)
                    display_value = struct.unpack("<I", tmp)[0]
                else:
                    display_value = value
                print("\tWriting 0x{} to {} at offset 0x{}".format("{:08x}".format(display_value).upper(), display_name, "{:08x}".format(data_offset + display_offset).upper()))
                if size == 4:
                    value_data = struct.pack("<i", value)
                else:
                    print("\tWARNING: Unsupported Data Size Encountered on the Stack!")
                    value_data = b"\0" * size
                data[data_offset] = value_data
        elif instruction_type == 4:
            if pc_ptr + 2 <= len(bd_content):
                data_len_bytes = bd_content[pc_ptr:pc_ptr + 2]
                update_usage_map(file_usage_map, pc_ptr, 2)
                pc_ptr += 2
                data_len = struct.unpack("<h", data_len_bytes)[0]
                data_len *= 2
                pc_ptr += data_len
                print("\tJumping to 0x{}".format("{:08x}".format(pc_ptr + pc_display_offset).upper()))
        elif instruction_type == 5:
            if pc_ptr + 2 <= len(bd_content):
                jmp_off_bytes = bd_content[pc_ptr:pc_ptr + 2]
                update_usage_map(file_usage_map, pc_ptr, 2)
                pc_ptr += 2
                jmp_offset = struct.unpack("<h", jmp_off_bytes)[0]
                jmp_offset *= 2
                pc_ptr += jmp_offset
                print("\tJumping to 0x{}".format("{:08x}".format(pc_ptr + pc_display_offset).upper()))
        elif instruction_type == 6:
            raise Exception("Not Implemented")
        elif instruction_type == 7:
            display_name = temp_display_name
            if len(temp_memory) > 1:
                param = temp_memory[-2]
                print("\tPopping 0x{} from the {}".format("{:08x}".format(param).upper(), display_name))
                temp_memory = temp_memory[:-2]
            else:
                print("\tWARNING: Missing value in the Temp Memory Space to pop!")
                param = 0
            if arg_type == 0:
                if sub_instruction_type == 0:
                    value = (param >> 31) & 1
                elif sub_instruction_type == 1:
                    value = int(param < 1)
                elif sub_instruction_type == 2:
                    value = int(param == 0)
                elif sub_instruction_type == 3:
                    value = int(param != 0)
                elif sub_instruction_type == 4:
                    value = ((~param) >> 31) & 1
                elif sub_instruction_type == 5:
                    value = int(0 < param)
                else:
                    raise Exception("Error: Invalid Sub-Instruction Type")
            elif arg_type == 1:
                param_type = type(param)
                if param_type != float:
                    if param_type == int:
                        param_bytes = struct.pack("<i", param)
                    else:
                        raise Exception("Error: Unsupported Conversion")
                    param = struct.unpack("<f", param_bytes)[0]
                if sub_instruction_type == 0:
                    value = 0
                elif sub_instruction_type == 1:
                    value = 0
                elif sub_instruction_type == 2:
                    value = 0
                elif sub_instruction_type == 3:
                    value = 1
                    if param == 0.:
                        value = 0
                elif sub_instruction_type == 4:
                    value = 0
                elif sub_instruction_type == 5:
                    value = 0
                else:
                    raise Exception("Error: Invalid Sub-Instruction Type")
            else:
                raise Exception("Error: Invalid Arg Type!")
            display_name = temp_display_name
            size = 4
            if value < 0:
                tmp = struct.pack("<i", value)
                display_value = struct.unpack("<I", tmp)[0]
            else:
                display_value = value
            print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
            temp_memory.append(value)
            temp_memory.append(size)
        elif instruction_type == 8:
            unk_offset = sub_instruction_type * 4
            if pc_ptr + 2 <= len(bd_content):
                jmp_off_bytes = bd_content[pc_ptr:pc_ptr + 2]
                update_usage_map(file_usage_map, pc_ptr, 2)
                pc_ptr += 2
                jmp_offset = struct.unpack("<h", jmp_off_bytes)[0]
                jmp_offset *= 2
                address_stack.append(pc_ptr)
                pc_ptr += jmp_offset
                print("\tJumping to 0x{}".format("{:08x}".format(pc_ptr + pc_display_offset).upper()))
        elif instruction_type == 9:
            display_name = temp_display_name
            if len(temp_memory) > 1:
                value, size = (temp_memory[-2], temp_memory[-1])
                print("\tPopping 0x{} from the {}".format("{:08x}".format(value).upper(), display_name))
                temp_memory = temp_memory[:-2]
            else:
                print("\tWARNING: Missing value on values stack to pop!")
            arg = sub_instruction_type * 4
            value += arg
            if value < 0:
                tmp = struct.pack("<i", value)
                display_value = struct.unpack("<I", tmp)[0]
            else:
                display_value = value
            print("\tPushing 0x{} to the {}".format("{:08x}".format(display_value).upper(), display_name))
            temp_memory.append(value)
            temp_memory.append(size)
        elif instruction_type == 10:
            display_name = temp_display_name
            if len(temp_memory) > 1:
                value, size = (temp_memory[-2], temp_memory[-1])
                print("\tPopping 0x{} from the {}".format("{:08x}".format(value).upper(), display_name))
                temp_memory = temp_memory[:-2]
            else:
                print("\tWARNING: Missing value on values stack to pop!")
            word_count = sub_instruction_type
            display_name = "Unknown Memory Space"
            values = []
            for i in range(word_count):
                # The value read from temp mem space is a pointer to the unknown memory space
                # val is the value read from that memory space
                # TO-DO: Find a way to get this value instead of hard coding it
                val = 0x0052AF7C
                size = 4
                print("\tReading 0x{} from {}".format("{:08x}".format(val).upper(), display_name))
                values.append((val, size))
            display_name = temp_display_name
            for value, size in values:
                print("\tPushing 0x{} to {}".format("{:08x}".format(value).upper(), display_name))
                temp_memory.append(value)
                temp_memory.append(size)
        elif instruction_type == 11:
            # Determine the syscall to perform
            syscalls_index = arg_type
            syscall_index = sub_instruction_type
            syscall = syscalls[syscalls_index][syscall_index]
            param_count = syscall.param_count
            params = []
            for i in range(param_count):
                if len(temp_memory) > 1:
                    # Pop a value from the stack
                    value, size = (temp_memory[-2], temp_memory[-1])
                    print("\tPopping 0x{} from {}".format("{:08x}".format(value).upper(), temp_display_name))
                    temp_memory = temp_memory[:-2]
                    params.append(value)
                else:
                    print("\tWARNING: Unable to pop a value from {}!".format(temp_display_name))
            # TO-DO: Call the function
            print("\tCalling {}".format(syscall.name))
            print("\tWARNING: Calling syscalls is not yet implemented")
            # Log the syscall
            if syscall_index in referenced_syscalls[syscalls_index]:
                referenced_syscalls[syscalls_index][syscall_index] += 1
            else:
                referenced_syscalls[syscalls_index][syscall_index] = 1
        else:
            print("WARNING: Invalid Instruction Type Encountered!")
        if interactive:
            input("Press 'ENTER' to continue...")
    print(f'Finished parsing {input_fn}')
    print('Usage Map:')
    display_usage_map(file_usage_map)
    # Determine the usage percentage
    count = 0
    for value in file_usage_map:
        if value != 0:
            count += 1
    usage_perc = count / len(file_usage_map) * 100
    print(f"Percentage of File Parsed: {usage_perc}%")
    print("Referenced Syscalls:")
    for syscalls_index in range(len(referenced_syscalls)):
        if len(referenced_syscalls[syscalls_index]) > 0:
            print(f"\t{syscalls_index}:")
            for syscall_index in referenced_syscalls[syscalls_index]:
                print(f"\t\t{syscall_index}: {referenced_syscalls[syscalls_index][syscall_index]}")

if __name__ == '__main__':
    main()