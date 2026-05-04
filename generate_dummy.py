import os

# Create the assets directory if it doesn't exist
os.makedirs('assets', exist_ok=True)

# Create a fake binary blob with our target patterns
with open('assets/firmware_blob.bin', 'wb') as f:
    # 1. Add an ELF magic number at the start
    f.write(b'\x7fELF')
    
    # Add some random binary garbage
    f.write(os.urandom(64))
    
    # 2. Add a U-Boot string
    f.write(b'Initializing U-Boot...\n')
    
    # Add more random garbage
    f.write(os.urandom(64))
    
    # 3. Plant the hidden credential for the regex to find
    f.write(b'debug_admin_password=SuperSecretHardwareKey2026!\n')
    
    # Pad the rest
    f.write(os.urandom(64))

print("✅ Dummy firmware created successfully at assets/firmware_blob.bin!")