
import sys
import os
# Add utils directory to path dynamically (same logic as fix)
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

try:
    from my_analyzer import analyze_file
    print("SUCCESS: my_analyzer imported successfully")
except ImportError as e:
    print(f"FAILED: {e}")
except Exception as e:
    print(f"ERROR: {e}")
