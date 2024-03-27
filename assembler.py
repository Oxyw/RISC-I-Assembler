import sys
import re


opcodes = {
    "NOP": 0, # NOP = "ADD 0, 0, 0"
    "ADD": 0x58, # '1011000'
    "ADDC": 0x5C, # '1011100'
    "SUB": 0x50, # '1010000'
    "SUBC": 0x54, # '1010100'
    "SUBR": 0x52, # '1010010'
    "SUBCR": 0x56, # '1010110'
    "AND": 0x40, # '1000000'
    "OR": 0x48, # '1001000'
    "XOR": 0x44, # '1000100'
    "SLL": 0x10, # '0010000'
    "SRL": 0x18, # '0011000'
    "SRA": 0x1C, # '0011100'
    "LDL":  0x28, # '0101000'
    "LDSU": 0x2C, # '0101100'
    "LDSS": 0x2E, # '0101110'
    "LDBU": 0x24, # '0100100'
    "LDBS": 0x26, # '0100110'
    "STL": 0x38, # '0111000'
    "STS": 0x30, # '0110000'
    "STB": 0x34, # '0110100'
    "JMP": 0x0A, # '0001010'
    "JMPR": 0x0E, # '0001110'
    "CALL": 0x08, # '0001000'
    "CALLR": 0x0C, # '0001100'
    "RET": 0x60, # '1100000'
    "RETINT": 0x64, # '1100100'
    "CALLINT": 0x00, # '0000000'
    "LDHI": 0x70, # '1110000'
    "GTLPC": 0x68, # '1101000'
    "GETPSW": 0x12, # '0010010'
    "PUTPSW": 0x1A  # '0011010'
}

# R: 0~2, LI: 4~6
# op rd rs1 src2  # 0
# op con rs1 src2 # 1
# op rs1 src2 # 2
# op rx imm  # 4
# op con imm # 5
# op rx      # 6
format_type = {
    "NOP": 7,
    "ADD": 0,
    "ADDC": 0,
    "SUB": 0,
    "SUBC": 0,
    "SUBR": 0,
    "SUBCR": 0,
    "AND": 0,
    "OR": 0,
    "XOR": 0,
    "SLL": 0,
    "SRL": 0,
    "SRA": 0,
    "LDL":  0,
    "LDSU": 0,
    "LDSS": 0,
    "LDBU": 0,
    "LDBS": 0,
    "STL": 0,
    "STS": 0,
    "STB": 0,
    "JMP": 1,
    "JMPR": 5,
    "CALL": 0,
    "CALLR": 4,
    "RET": 2,
    "RETINT": 2,
    "CALLINT": 6,
    "LDHI": 4,
    "GTLPC": 6,
    "GETPSW": 6, 
    "PUTPSW": 6
}

conditions = {
    "UN": 0,
    "EQ": 1,
    "NE": 2,
    "LT": 3,
    "GE": 4,
    "LTU": 5,
    "GEU": 6
}

elenum = [4, 4, 3, 0, 3, 3, 2, 1]

# format table
# RR: [OPCODE<31-25> | SCC<24> | DEST<23-19> | SORC1<18-14> | IMF<13> | <12-5> | SORC2<4-0>]
# RI: [OPCODE<31-25> | SCC<24> | DEST<23-19> | SORC1<18-14> | IMF<13> | IMM<12-0>(sign-extended)] 
# LI: [OPCODE<31-25> | SCC<24> | DEST<23-19> | IMM<18-0>]

def process_RR_type(opcode, scc, dest, rs1, rs2):
    opcode_bin = format(opcode, '07b')
    scc_bin = format(scc, '01b')
    dest_bin = format(dest, '05b')
    rs1_bin = format(rs1, '05b')
    imf_bin = format(0, '01b')
    reserved = format(0, '08b')
    rs2_bin = format(rs2, '05b')
    instruction_bin = opcode_bin + scc_bin + dest_bin + rs1_bin + imf_bin + reserved + rs2_bin
    return instruction_bin

def process_RI_type(opcode, scc, dest, rs1, imm):
    opcode_bin = format(opcode, '07b')
    scc_bin = format(scc, '01b')
    dest_bin = format(dest, '05b')
    rs1_bin = format(rs1, '05b')
    imf_bin = format(1, '01b')
    imm_bin = format(imm & 0b1_1111_1111_1111, '013b')
    instruction_bin = opcode_bin + scc_bin + dest_bin + rs1_bin + imf_bin + imm_bin
    return instruction_bin

def process_LI_type(opcode, scc, dest, imm):
    opcode_bin = format(opcode, '07b')
    scc_bin = format(scc, '01b')
    dest_bin = format(dest, '05b')
    imm_bin = format(imm & 0b111_1111_1111_1111_1111, '019b')
    instruction_bin = opcode_bin + scc_bin + dest_bin + imm_bin
    return instruction_bin


def classifier(elements):
    opcodeString = elements[0]
    
    if(opcodeString == "NOP"):
        return process_RR_type(opcodes.get("ADD"), 0, 0, 0, 0)
    
    opcode = opcodes.get(opcodeString)
    type = format_type.get(opcodeString)
    scc = 1
    if (type < 3):
        dest = 0
        if (type == 0):
            dest = int(elements[1][1:])
        elif (type == 1):
            dest = conditions.get(elements[1])
        
        rs1_idx = 2 if (type != 2) else 1
        rs1 = int(elements[rs1_idx][1:])
        
        src2_idx = 3 if (type != 2) else 2
        if (elements[src2_idx][0] == 'r'):
            rs2 = int(elements[src2_idx][1:])
            return process_RR_type(opcode, scc, dest, rs1, rs2)
            #print(opcode, scc, dest, rs1, rs2)
        else:
            imm = int(elements[src2_idx][2:], 16) if "0x" in elements[src2_idx] else int(elements[src2_idx])
            return process_RI_type(opcode, scc, dest, rs1, imm)
            #print(opcode, scc, dest, rs1, imm)
    else:
        imm = 0
        if (type == 5):
            dest = conditions.get(elements[1])
        else:
            dest = int(elements[1][1:])
        if (type != 6):
            imm = int(elements[2][2:], 16) if "0x" in elements[2] else int(elements[2])
        return process_LI_type(opcode, scc, dest, imm)
        #print(opcode, scc, dest, imm)
    

def readFile(fileName):
    out = ""
    try:
        with open(fileName, 'r') as file:
            for line in file:
                out += line
        return out
    except IOError as e:
        raise RuntimeError(e)

def remove_comment(line):
    comment_index = line.find("//")
    if comment_index != -1:
        line = line[:comment_index].strip()
    else:
        line = line.strip()
    return line

def assembler(file):
    bytes_ = bytearray()
    
    lnum = 0
    lines = file.split("\n")
    for line in lines:
        lnum += 1
        if line.replace(" ", "") == "":
            continue
        xline = remove_comment(line)
        if xline == "":
            continue
        #print("line {} being processed:".format(lnum), line)
        #print("after processed:", xline)
        
        elements = [elem for elem in re.split("\s+", xline) if elem != ""]
        opcodeString = elements[0]
        
        if opcodes.get(opcodeString) is None:
            print("illegal operation in line {}: {}".format(lnum, line))
            return None
        
        type = format_type.get(opcodeString)
        if (len(elements) != elenum[type]):
            print("format error in line {}: {}".format(lnum, line))
            return None
        if ((type == 1 or type == 5) and conditions.get(elements[1]) is None):
            print("condition error in line {}: {}".format(lnum, line))
            return None
        if ((type == 0 or type == 2 or type == 4 or type == 6) and elements[1][0] != 'r'
            or (type == 0 or type == 1) and elements[2][0] != 'r'):
            print("register error in line {}: {}".format(lnum, line))
            return None
        
        inst_binstr = classifier(elements)
        #print(inst_binstr)
        #print(format(int(inst_binstr, 2), '032b'))
        inst_bin = int(inst_binstr, 2).to_bytes(4, byteorder='little')
        #print(' '.join(f'{byte:02x}' for byte in inst_bin))
        bytes_.extend(inst_bin)
    
    return bytes_

if __name__ == "__main__":

    asmfile = sys.argv[1] if len(sys.argv) == 2 else input("Enter the name of the file: ")
    f = readFile(asmfile)
    binfile = asmfile.split(".")[0] + ".bin"
    with open(binfile, "wb") as outfile:
        bytesToWrite = assembler(f)
        if bytesToWrite is not None:
            outfile.write(bytesToWrite)

