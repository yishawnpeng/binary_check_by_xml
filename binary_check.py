import struct
import glob
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

class PSPParser:
    def __init__(self, bin_path=None, platform_config=None):
        """
        Parser for AMD Platform Security Processor (PSP) structures from Binary and XML.
        """
        self.data = None
        self.bin_path = bin_path
        self.platform_config = platform_config

        self.xml_path = None
        self.xml_root = None
        self.xml_psp_l1_dir = None
        self.xml_psp_l2A_dir = None
        self.xml_ISH_dir = None
        self.xml_ISH_Location = None
        self.xml_ISH_PspId = None
        self.xml_psp_l2A_table = None

        self._load_bin()
        if self.platform_config:
            self._load_xml()

    def _load_bin(self):
        """
        Loads the binary file into memory. Auto-detects .bin if no path is provided.
        """
        if self.bin_path is None:
            bin_files = glob.glob("*.bin")
            if not bin_files:
                print("ERROR: No .bin files found in the current directory.")
                return
            self.bin_path = bin_files[0]
        else:
            # Validate if the provided filename has a .bin extension
            if not self.bin_path.lower().endswith('.bin'):
                print(f"ERROR: The file '{self.bin_path}' is not a valid .bin file.")
                return
            
        self.bin_path = Path(self.bin_path)

        # Read the file content into memory
        if not self.bin_path.exists():
            print(f"ERROR: File {self.bin_path} not found.")
            return
        
        try:
            self.data = self.bin_path.read_bytes()
            #print(f"File loaded successfully: {self.bin_path} ({len(self.data)} bytes)")
            print(f"Loaded Binary: {self.bin_path}")
        except Exception as e:
            print(f"ERROR: Failed to read file - {e}")

    def _load_xml(self):
        """
        Finds and parses the BIOSImageDirectory XML based on platform configuration.
        """
        if not self.bin_path or not self.platform_config:
            return

        search_pattern = "BIOSImageDirectory*.xml"
        xml_files = glob.glob(search_pattern)
        print(xml_files)
        platform_key = self.bin_path.name[0:3].upper()
        platform_entry = self.platform_config.get(platform_key)
        
        if not platform_entry:
            return
            
        target_suffix = platform_entry.get("xml_end")
        if not target_suffix:
            return
        
        for f in xml_files:
            if target_suffix in f:
                self.xml_path = Path(f)
                break
        
        if not self.xml_path or not self.xml_path.exists():
            print(f"ERROR: No matching XML found for {self.bin_path.name}")
            return

        try:
            parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
            tree = ET.parse(self.xml_path, parser=parser)
            self.xml_root = tree.getroot()
            print(f"Loaded XML: {self.xml_path.name}")
            #full_xml_str = ET.tostring(self.xml_root, encoding='unicode', method='xml')
            #print(full_xml_str)
        except Exception as e:
            print(f"ERROR: Failed to parse XML structure - {e}")

    def check_bin_value(self, offset: int, expected: int, size: int = 4) -> bool:
        """
        Verifies if data at a specific offset matches the expected value.
        """
        if not self.data or offset + size > len(self.data) :
            print(f"\nERROR: No data loaded or Offset 0x{offset:X} is out of range. ")
            return False

        fmt_map = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
        fmt = fmt_map.get(size, '<I')

        actual_val = struct.unpack(fmt, self.data[offset:offset+size])[0]
        
        is_match = (actual_val == expected)
        status = "[ Success ]" if is_match else "[ Failed ]"
        
        print(f"{status} Addr: 0x{offset:08X}\nExpected: 0x{expected:08X}\nRead: 0x{actual_val:08X}")
        return is_match
    
    def get_tag_Base_form_xml(self, tag):
        """
        Extracts 'Base' address and metadata for tags like PSP_DIR or ISH_HEADER.
        """
        if self.xml_root is None:
            print(f"\nERROR: XML root is empty.")
            return None

        try:
            returned_value = None
            if tag == "PSP_DIR":
                for goal in self.xml_root.findall(tag): 
                    if goal.get('AddressMode') == '0x1':
                        #print("Parameter PSP_DIR so save to xml_psp_l1_dir")
                        self.xml_psp_l1_dir = int(goal.get('Base'), 16)
                        returned_value = self.xml_psp_l1_dir
                        break
            elif tag == "ISH_HEADER":
                platform_key = self.bin_path.name[0:3].upper()
                platform_info = self.platform_config.get(platform_key, {})
                xml_block_comment = platform_info.get("xml_block_comment")
                print(f"Target xml_block_comment : {xml_block_comment} ")
                target_found = False
                for node in self.xml_root:
                    #print(node.tag, node.text)
                    if "Comment" in str(node.tag) and xml_block_comment in (node.text or ""):
                        target_found = True
                        continue
                    # If we already found the comment, the next ISH_HEADER is our target
                    if target_found and node.tag == "ISH_HEADER":
                        self.xml_ISH_dir = int(node.get("Base"), 16)
                        #print(f"Match Found! ISH Base: 0x{self.xml_ISH_dir:08X}")
                        returned_value = self.xml_ISH_dir
                        self.xml_ISH_PspId = int(node.get("PspId"), 16)
                        self.xml_ISH_Location = int(node.get("Location"), 16)
                        break
                    # Optional: Reset if we hit a different comment after finding our target
                    elif target_found and "Comment" in str(node.tag):
                        target_found = False

            if returned_value is not None:
                print(f"We expected {tag} : 0x{returned_value:08X} (from XML)")
            return returned_value
            
        except Exception as e:
            print(f"\nERROR: XML parsing exception - {e}")
            return None

    def get_address_in_2depth_by_level_and_type(self, level="0x1", entry_type=0x48):
        """
        Navigates 2-depth XML structure to find Entry addresses by Level and Type.
        """
        if isinstance(entry_type, int):
            entry_type = f"0x{entry_type:02X}"

        # Specifically searches for the PSP L2A DIR tag and extracts the Address value
        if self.xml_root is None or not self.platform_config:
            print("\nERROR: XML root is empty or platform_config is missing.")
            return None

        # Get target comment for Level 1 filtering
        platform_key = self.bin_path.name[0:3].upper()
        platform_info = self.platform_config.get(platform_key, {})
        xml_block_comment = platform_info.get("xml_block_comment")
        if str(level) == "0x1":
            print(f"Target Level 1 comment : {xml_block_comment}")

        # If searching Level 2, we usually don't need comment filtering unless specified
        target_found = True if str(level) == "2" else False

        # try:
        #     # Iterate through all PSP_DIR tags
        #     for psp_dir in self.xml_root.findall('PSP_DIR'):
        #         if psp_dir.get('Level') == '0x1':
        #             #print(psp_dir.tag, psp_dir.attrib)
        #             # Iterate through all child nodes including comments
        #             for index, node in enumerate(psp_dir):
        #                 # Check if node is a comment
        #                 if "Comment" in str(node.tag):
        #                     #print(node.text)
        #                     if xml_block_comment in node.text:
        #                         print(f"Founded ! {xml_block_comment}")
        #                         target_found = True
        #                         continue
        #                 # If target section is found, look for the specific POINT_ENTRY
        #                 if target_found and node.tag == "POINT_ENTRY":
        #                     if node.get("Type") == entry_type:
        #                         lsA_str = node.get("Address")
        #                         xml_psp_l2A_dir = int(lsA_str, 16)
        #                         print(f"\nWe expected PSP L2A dir : 0x{xml_psp_l2A_dir:08X} (from XML Match Type: {entry_type})")
        #                         return xml_psp_l2A_dir
        try:
            # Iterate through all PSP_DIR tags
            for psp_dir in self.xml_root.findall('PSP_DIR'):
                #print(list(psp_dir))
                # Match the target Level (1 or 2)
                if psp_dir.get('Level') == str(level) or psp_dir.get('Level') == f"0x{int(level):X}":
                    #print(list(psp_dir))
                    # Iterate through nodes inside the PSP_DIR
                    for node in list(psp_dir):
                        #print(node.tag, node.attrib)
                        # --- Level 1 Logic: Identify Comment block ---
                        if str(level) == "0x1" and (callable(node.tag) or "Comment" in str(node.tag)):
                            #print(123123123)
                            if xml_block_comment and xml_block_comment in (node.text or ""):
                                print(f"Founded ! {xml_block_comment}")
                                target_found = True
                                continue
                        
                        # --- Common Logic: Match POINT_ENTRY Type ---
                        if target_found and node.tag == "POINT_ENTRY":
                            if node.get("Type") == entry_type:
                                xml_psp_l2A = int(node.get("Address"), 16)
                                if str(level) == "0x1":
                                    print(f"\nWe expected PSP L2A dir : 0x{xml_psp_l2A:08X} (from XML Match Type: {entry_type})")
                                else:
                                    print(f"\nWe expected PSP L2A table : 0x{xml_psp_l2A:08X} (from XML Match Type: {entry_type})")
                                return xml_psp_l2A
                        
                        # --- Level 1 Reset: If hit next comment, stop searching ---
                        elif str(level) == "0x1" and target_found and callable(node.tag) and "Comment" in str(node.tag):
                            target_found = False

            print(f"\nERROR: Could not find Address for xml_block_comment {xml_block_comment} and Type {entry_type}")
            return None
        except Exception as e:
            print(f"\nERROR: Exception during XML tag parsing - {e}")
            return None

    def return_xml_pspID(self):
        return self.xml_ISH_PspId

    def return_xml_location(self):
        return self.xml_ISH_Location
    
    def return_xml_psp_l2A_table(self):
        return self.xml_psp_l2A_table
    
    def find_next_byte_after_offset(self, start_offset: int, target_byte: int):
        """
        Searches for the first occurrence of a byte after a specific offset.
        """
        if self.data is None or start_offset >= len(self.data):
            return None

        found_index = self.data.find(bytes([target_byte]), start_offset)

        if found_index != -1:
            print(f"[ Found ] Byte 0x{target_byte:02X} at Address: 0x{found_index:08X}")
            return found_index
        return None

if __name__ == "__main__":
    # Check if a filename was provided as a command-line argument
    input_file = None
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    
    # Define platform categories
    # User need to check with xml defined
    PLATFORM_DATA = {
        "Y26": {"type": "AMD", "xml_block_comment":"KRK1", "xml_end": "32M_DDR5_FP8.xml"},
        "Y06": {"type": "AMD", "xml_block_comment":"KRK1", "xml_end": "32M_DDR5_FP8.xml"},
        "Y21": {"type": "Intel", "xml_block_comment":None, "xml_end": None},
        "X26": {"type": "AMD", "xml_block_comment":"KRK1", "xml_end": "32M_DDR5_FP8.xml"},
        "X21": {"type": "Intel", "xml_block_comment":None, "xml_end": None}
    }
    # Initialize parser (will auto-detect bin if no argument passed)
    parser = PSPParser(bin_path=input_file, platform_config=PLATFORM_DATA)

    if parser.data:
        file_name = parser.bin_path.name.upper()
        platform_file_name = file_name[0:3]  # Extract the first 3 characters to identify platform
        # for AMD Platforms
        if platform_file_name in PLATFORM_DATA and PLATFORM_DATA[platform_file_name]["type"] == "AMD":
            print(f"[ Detected AMD Platform: {file_name} ]")
            print("-----------------------------------------------------")
            print("1. First: Verify signature---------------------------")
            # Step 1: Verify Signature
            # Use AMD specific parameters 
            # Verify signature at 0x20000
            sign_OFFSET = 0x20000
            sign_SIGNATURE = 0x55AA55AA # little-endian
            if not parser.check_bin_value(sign_OFFSET, sign_SIGNATURE, size=4):
                print("ERROR: Signature verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)

            print("-----------------------------------------------------")
            print("2. Second: Verify PSP L1 Dir from XML----------------")
            # Step 2: Parse XML Base and find PSP L1 Dir
            # print(f"xml_base_l1: 0x{xml_base_l1:08X}")
            # psp_l1_dir_offset defined in implementation Guide
            psp_l1_dir_offset = 0x14 # defined in implementation Guide
            print(f"psp_l1_dir_offset from implementation Guide : 0x{psp_l1_dir_offset:X}")
            xml_base_l1 = parser.get_tag_Base_form_xml("PSP_DIR")
            print(f"\nCheck PSP Header signature ($PSP) :") # $PSP implementation Guide
            if not parser.check_bin_value(xml_base_l1, 0x50535024, size=4):
                print("ERROR: PSP Header verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)
            #print(xml_base_l1)
            print(f"\nCheck PSP L1 Dir (0x20000 + 0x14) :") 
            if not parser.check_bin_value(sign_OFFSET+psp_l1_dir_offset, xml_base_l1, size=4):
                print("ERROR: PSP L1 Dir verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)
            
            print("-----------------------------------------------------")
            print("3. Third: Verify PSP L2A Dir from XML----------------")
            # Step 3: Parse XML Base and find PSP L2A Dir
            # psp_l2A_dir_offset defined in implementation Guide
            psp_l2A_dir_offset = 0x48 # defined in implementation Guide and can check in xml
            print(f"psp_l2A_dir_offset from implementation Guide : 0x{psp_l2A_dir_offset:X}")
            xml_base_l2A = parser.get_address_in_2depth_by_level_and_type("0x1",psp_l2A_dir_offset)
            print(f"\nCheck PSP L2A Dir (PSP L1 Dir + 0x48) :") 
            if not parser.check_bin_value(xml_base_l1+psp_l2A_dir_offset, xml_base_l2A, size=4):
                print("ERROR: PSP L2A Dir verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)

            print("-----------------------------------------------------")
            print("4. Fourth: Verify ISH(image slot header) Dir from XML")
            xml_ISH = parser.get_tag_Base_form_xml("ISH_HEADER")
            #print("outside",xml_ISH)
            #print(f"ISH_DIR offset from XML : 0x{xml_ISH:08X}")
            psp_location_offset = 0x10 # defined in implementation Guide
            psp_ID_offset = 0x14 # defined in implementation Guide
            print(f"\npsp_location_offset from implementation Guide : 0x{psp_location_offset:X}")
            print(f"Check psp_location(ISH_HEADER+0x{psp_location_offset:X}) :")
            if parser.return_xml_location() and \
              not parser.check_bin_value(xml_ISH+psp_location_offset, parser.return_xml_location(), size=4):
                print("ERROR: ISH PSP Location verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)
            elif parser.return_xml_location() is None:
                print("ISH PSP Location is not specified in XML.")
                print("So STOP All Check !!")
                sys.exit(1)

            print(f"\npsp_ID_offset from implementation Guide : 0x{psp_ID_offset:X}")
            print(f"Check psp_ID(ISH_HEADER+0x{psp_ID_offset:X}) :")
            if parser.return_xml_pspID() and \
              not parser.check_bin_value(xml_ISH+psp_ID_offset, parser.return_xml_pspID(), size=4):
                print("ERROR: ISH PSP ID verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)
            elif parser.return_xml_pspID() is None:
                print("ISH PSP ID is not specified in XML.")
                print("So STOP All Check !!")
                sys.exit(1)

            print("-----------------------------------------------------")
            print("5. Fifth: Verify L2A table exist after ISH header----")
            psp_l2a_table_offset = 0x49 # defined in implementation Guide
            xml_base_psp_l2a_table = parser.get_address_in_2depth_by_level_and_type("2",psp_l2a_table_offset)
            # find next byte 0x49 after ISH header
            print("L2A Directory Table Header is in PSP L2A Entry 0x49")
            byte_after_ISH = parser.find_next_byte_after_offset(xml_ISH, psp_l2a_table_offset)
            #print(f"Check if byte 0x{psp_l2a_table_offset:X} exist after ISH header : 0x{byte_after_ISH:08X}" if byte_after_ISH else f"\nByte 0x{psp_l2a_table_offset} not found after ISH header")
            print(f"and Shift 0x08 then look 4bytes")
            if byte_after_ISH is not None:
                if len(parser.data) > byte_after_ISH + 0x08 + 0x04: # Ensure we have enough data to check the L2A table signature:
                    #print(f"{byte_after_ISH + 0x0B:08X}")
                    if not parser.check_bin_value(byte_after_ISH+0x08, xml_base_psp_l2a_table, size=4):
                        print("ERROR: PSP L2A table verification failed.")
                        print("So STOP All Check !!")
                        sys.exit(1)
                else :
                    print("ERROR: Not enough data to verify PSP L2A table after ISH header.")
                    print("So STOP All Check !!")
                    sys.exit(1)
            else:
                print(f"ERROR: Could not find byte 0x{psp_l2a_table_offset:X} after ISH header.")
                sys.exit(1)
            #print(f"!!!!!!{parser.return_xml_location():X}")
            print("-----------------------------------------------------")
            print("5.1 Fifth-one: Now find $BL2 by L2A table and ISH----")
            parser.xml_psp_l2A_table = parser.return_xml_location() + xml_base_psp_l2a_table
            #print(f"\nxml_location + xml_base_psp_l2a_table : 0x{parser.return_xml_location() + xml_base_psp_l2a_table:08X}")
            dollerBL2 = 0x324C4224 # $BL2 in little-endian
            if not parser.check_bin_value(parser.return_xml_psp_l2A_table() , dollerBL2, size=4):
                print("ERROR: PSP L2A table verification failed.")
                print("So STOP All Check !!")
                sys.exit(1)
            
            print("-----------------------------------------------------")
            print("\nCongraduation !!!! All checks PASSED for AMD platform!\n")
            pause = input("Press Enter to exit...")

        # for Intel Platforms
        elif platform_file_name in PLATFORM_DATA and PLATFORM_DATA[platform_file_name]["type"] == "Intel":
            print(f"[ Detected Intel Platform: {file_name} ]")
            print("INFO: Intel specific check logic is coming soon. Skipping...")
            # Example placeholder:
            # intel_OFFSET = 0x1000
            # intel_SIG = 0xDEADBEEF
            
            
        # 3. Unknown Platform
        else:
            print(f"ERROR: Unknown platform for file {file_name}. No specific checks performed.")
            
        