from binaryninja.architecture import Architecture
from binaryninja.binaryview import *
from binaryninja.function import *
from binaryninja.enums import SegmentFlag
from binaryninja.types import *

use_default_loader_settings = True

# Relocation table class
class RELOCATION():

    # init from data passed to class
    def __init__(self, data, addy):
        self.offset = int.from_bytes(data.read(addy, 2), "little")
        self.segment = int.from_bytes(data.read(addy + 2, 2), "little")

    # print the relocation table
    def print(self):
        print("Relocation:\n")
        print("Offset:                          \t\t", self.offset)
        print("Segment Value:                   \t\t", self.segment)

# DOS Header class
class DOS_HEADER():

    # initialize the dos header based on the data passed
    def __init__(self, data):
        self.signature = data.read(0, 2)
        self.bytes_in_last_block = int.from_bytes(data.read(2, 2), "little")
        self.blocks_in_file = int.from_bytes(data.read(4, 2), "little")
        self.num_relocs = int.from_bytes(data.read(6, 2), "little")
        self.header_paragraphs = int.from_bytes(data.read(8, 2), "little")
        self.min_extra_paragraphs = int.from_bytes(data.read(0xa, 2), "little")
        self.max_extra_paragraphs = int.from_bytes(data.read(0xc, 2), "little")
        self.ss = int.from_bytes(data.read(0xe, 2), "little")
        self.sp = int.from_bytes(data.read(0x10, 2), "little")
        self.checksum = int.from_bytes(data.read(0x12, 2), "little")
        self.ip = int.from_bytes(data.read(0x14, 2), "little")
        self.cs = int.from_bytes(data.read(0x16, 2), "little")
        self.reloc_table_offset = int.from_bytes(data.read(0x18, 2), "little")
        self.overlay_number = int.from_bytes(data.read(0x1a, 2), "little")

        self.len = len(data)

        self.relocations = []

        # initialize all relocations
        for i in range(self.num_relocs):
            self.relocations.append(RELOCATION(data, self.reloc_table_offset + (i * 4)))

    # print the DOS header
    def print(self):
        print("DOS HEADER\n")
        print("Signature:                       \t\t", self.signature)
        print("Bytes in last block:             \t\t", self.bytes_in_last_block)
        print("Blocks in file:                  \t\t", self.blocks_in_file)
        print("Number of relocations:           \t\t", self.num_relocs)
        print("Size of header in paragraphs:    \t\t", self.header_paragraphs)
        print("Minimum extra paragraphs needed: \t\t", self.min_extra_paragraphs)
        print("Maximum extra paragraphs needed: \t\t", self.max_extra_paragraphs)
        print("Initial (relative) SS value:     \t\t", self.ss)
        print("Initial SP value:                \t\t", self.sp)
        print("Checksum:                        \t\t", self.checksum)
        print("Initial IP value:                \t\t", self.ip)
        print("Initial (relative) CS value:     \t\t", self.cs)
        print("File address of relocation table:\t\t", self.reloc_table_offset)
        print("Overlay number:                  \t\t", self.overlay_number)

        print("\nRelocations:\n")
        for relo in self.relocations:
            relo.print()

    # calculates the start address of the code segment
    def calculateStartAddress(self):
        return (512 * self.blocks_in_file) - (16 * self.header_paragraphs)

    # calculates the data size 
    # ds = paragraph offset from start of code
    # offset = offset in paragraph to first data item
    def calculateDataSize(self, ds, offset):
        return self.len - ((ds * 16) + self.calculateStartAddress() + offset) 

    # calculates the size of the code segment
    # ds = paragraph offset from start of code
    # offset = offset in paragraph to first data item
    def calculateCodeSize(self, ds, offset):
        return self.len - self.calculateDataSize(ds, offset) - self.calculateStartAddress()


# Define our view
class MSDOSView(BinaryView):
    name = 'MSDOS'
    long_name = 'MSDOS'

    # check if this is an MSDOS file
    @classmethod
    def is_valid_for_data(self, data):
        return data.read(0,2) == b'\x4D\x5A'

    # intialize the binary view
    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['x86_16'].standalone_platform
        self.arch = Architecture['x86_16']
        self.data = data

    # initialize our view
    def init(self):

        # create header
        header = DOS_HEADER(self.data)

        # prints header
        header.print()

        # calculates the start of the code section
        start = header.calculateStartAddress()

        # initialize ax and ds
        ax = ""
        ds = ""

        # start smallestOffset by largest possible value
        smallestOffset = 16

        # current end of program to check
        end = header.len

        # while we are not at the end of the code
        while start < end:
            # get the next instruction
            text = self.arch.get_instruction_text(self.data.read(start, 20), 0x0)
            
            # add instruction size to start
            start += text[1]

            # get all the instructions
            text = text[0]

            # print out instructions
            for i in range(len(text)):
                print("text ", i, ": ", text[i])

            # if we move data into ax, record that data
            if len(text) == 5 and "mov" == text[0].text and "ax" == text[2].text:
                ax = text[4].text
            # if we move ax into ds, record and change end
            elif len(text) == 5 and "mov" == text[0].text and "ds" == text[2].text and "ax" == text[4].text:
                ds = int(ax[2:], 16)

                # modify end to be at the end of the paragraph containing data segment
                end = (ds * 16) + header.calculateStartAddress() + 16

            # if we have a pointer, find the offset from the start of data paragraph (lets us find first item in data)
            elif len(text) == 10 and "mov" == text[0].text and "]" == text[9].text and "ax":
                val = int(text[8].text[2:], 16)
                if val < smallestOffset:
                    smallestOffset = val
                    end = (ds * 16) + header.calculateStartAddress() + smallestOffset

        # print out data information
        print("Start of data paragraph: ", hex((ds * 16) + header.calculateStartAddress()))
        print("Start of data in paragraph: ", smallestOffset)

        # add the segments
        self.add_auto_segment(ds, header.calculateDataSize(ds, smallestOffset), header.calculateStartAddress() + header.calculateCodeSize(ds, smallestOffset), header.calculateDataSize(ds, smallestOffset), SegmentFlag.SegmentReadable|SegmentFlag.SegmentContainsData|SegmentFlag.SegmentDenyExecute)	
        self.add_auto_segment(header.calculateDataSize(ds, smallestOffset) + ds + smallestOffset, header.calculateCodeSize(ds, smallestOffset), header.calculateStartAddress(), header.calculateCodeSize(ds, smallestOffset), SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_entry_point(header.calculateStartAddress())

        return True
    
    def perform_is_executable(self):
        return True

MSDOSView.register()