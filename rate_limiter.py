import time
from collections import defaultdict
import sys
sys.path.append('etc/firewall/')
from config import RATE_LIMIT, TIME_FRAME

# Dictionary to store request counts per IP
request_counts = defaultdict(lambda: {"count": 0, "start_time": time.time()})

# Function to rate limit
def rate_limiter(ip_address):
    current_time = time.time()
    record = request_counts[ip_address]
    
    # If time frame has passed, reset the counter
    if current_time - record["start_time"] > TIME_FRAME:
        record["start_time"] = current_time
        record["count"] = 1
    else:
        record["count"] += 1
    
    # Block the IP if it exceeds the rate limit
    if record["count"] > RATE_LIMIT:
        return False  # Block the request (potential DDoS)
    return True  # Allow the request
