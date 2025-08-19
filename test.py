# test_write.py
import os

log_dir = 'logs'
file_path = os.path.join(log_dir, 'test_log.txt')

print(f"Attempting to write to: {os.path.abspath(file_path)}")

try:
    # Ensure the 'logs' directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"Created directory: {log_dir}")

    # Try to write to the file
    with open(file_path, 'w') as f:
        f.write("This is a successful test.")
    
    print("\nSUCCESS: File was written correctly.")

except Exception as e:
    print(f"\nFAILURE: An error occurred.")
    print(f"  Error Type: {type(e).__name__}")
    print(f"  Error Details: {e}")