import math
import os
import pefile

# List of highly suspicious API calls often used by ransomware for encryption, injection, etc.
SUSPICIOUS_IMPORTS = [
    b"CryptAcquireContextA", b"CryptAcquireContextW", b"CryptDecrypt", 
    b"CryptEncrypt", b"CryptGenKey", b"VirtualAlloc", b"VirtualAllocEx", 
    b"WriteProcessMemory", b"LoadLibraryA", b"GetProcAddress", b"IsDebuggerPresent"
]

def calculate_entropy(data):
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    
    for count in occurrences:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy

def extract_features(file_path):
    """
    Given a PE file path, extract EMBER-style static features.
    Returns a dictionary of features if successful, or None if invalid/failed.
    """
    if not os.path.exists(file_path):
        return None
        
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return None # Not a valid PE file
        
    features = {}
    
    # 1. Structural features
    features["machine"] = pe.FILE_HEADER.Machine
    features["num_sections"] = pe.FILE_HEADER.NumberOfSections
    features["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    features["characteristics"] = pe.FILE_HEADER.Characteristics
    features["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
    features["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    
    # 2. Section features
    section_entropies = []
    suspicious_section_names = 0
    for section in pe.sections:
        entropy = section.get_entropy()
        section_entropies.append(entropy)
        name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        if name.lower() in [".upx", ".vmp", ".aspack"]:
            suspicious_section_names += 1
            
    features["mean_section_entropy"] = sum(section_entropies) / len(section_entropies) if section_entropies else 0
    features["max_section_entropy"] = max(section_entropies) if section_entropies else 0
    features["min_section_entropy"] = min(section_entropies) if section_entropies else 0
    features["suspicious_sections"] = suspicious_section_names
    
    # 3. Whole file entropy
    with open(file_path, "rb") as f:
        file_data = f.read()
    features["file_entropy"] = calculate_entropy(file_data)
    features["file_size"] = len(file_data)
    
    # 4. Import features
    imported_api_count = 0
    suspicious_import_count = 0
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imported_api_count += 1
                    if imp.name in SUSPICIOUS_IMPORTS:
                        suspicious_import_count += 1
                        
    features["total_imports"] = imported_api_count
    features["suspicious_imports"] = suspicious_import_count
    
    # Feature array ordering needs to be consistent for ML model
    # We will return the ordered list of values
    ordered_keys = [
        "machine", "num_sections", "characteristics", "dll_characteristics", 
        "subsystem", "mean_section_entropy", "max_section_entropy", 
        "min_section_entropy", "suspicious_sections", "file_entropy", 
        "file_size", "total_imports", "suspicious_imports"
    ]
    
    ordered_values = [features[k] for k in ordered_keys]
    return ordered_values, ordered_keys
