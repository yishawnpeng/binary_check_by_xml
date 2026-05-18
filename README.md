# binary_check_by_xml

A Python-based BIOS firmware automation tool for verifying AMD Platform Security Processor (PSP) and Image Slot Header (ISH) structures using XML metadata.

> *Note: Intel platform support is planned in the future.*

## Build Status

| Branch / Workflow | Build Status |
| :--- | :---: |
| **Main Branch** | [![Python Build](https://github.com/yishawnpeng/binary_check_by_xml/actions/workflows/Python_build.yml/badge.svg)](https://github.com/yishawnpeng/binary_check_by_xml/actions) |
| **Release Build** | [![binary_check Build Release](https://github.com/yishawnpeng/binary_check_by_xml/actions/workflows/Release-build.yml/badge.svg)](https://github.com/yishawnpeng/binary_check_by_xml/actions) |

---

## Main Functions

This tool automates low-level integrity checks during the BIOS build/release phase:
- **Signature Verification**: Validates the core signature at 0x20000 (0x55AA55AA).
- **PSP Directory Check**: Cross-references Level 1 & Level 2A directories with specialized BIOS XML configurations.
- **ISH Header Validation**: Confirms Image Slot Header location and PSP ID consistency.
- **$BL2 Integrity**: Ensures the target table signature matches architectural requirements.

## Prerequisites & Installation

1. **No External Dependencies Required**: This tool runs entirely on Python's standard libraries (struct, xml, pathlib, argparse).
2. **Clone the repository**:
   git clone https://github.com/yishawnpeng/binary_check_by_xml.git
3. Ensure you have **Python 3.6+** installed.

## How to Use
The script can be executed via Command Line with flexible parameters:

### 1. Default Mode (Auto-detect)
Place your .bin firmware and BIOSImageDirectory*.xml in the same directory and run:
```
python binary_check.py
```

### 2. Manual Configuration
You can explicitly override input files via CLI arguments to verify specific binaries or custom XML snapshots:
#### (I)Specify both files
```python binary_check.py -b ./goal.bin -x ./goal.xml```
#### (II)Specify XML only (auto-detects .bin)
```python binary_check.py -x ./goal.xml```
#### (III)Specify binary only (auto-detects .xml)
```python binary_check.py -b ./goal.bin```

### 3. Check Version (CI/CD integration)
```
python binary_check.py --version
python binary_check.py -v
```

## History
For detailed release history, please refer to /history/HISTORY.txt.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch: git checkout -b feature/AmazingFeature
3. Commit your changes: git commit -m 'Add some AmazingFeature'
4. Push to the branch: git push origin feature/AmazingFeature
5. Open a Pull Request.
