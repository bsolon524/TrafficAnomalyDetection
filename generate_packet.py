# Authored by Seth Canada

import random
import pandas as pd
import time

def generate_traffic_data():
    # Generate synthetic data for normal traffic
    normal_traffic = {
        'packet_size': [random.randint(500, 1000) for _ in range(100)],
        'traffic_volume': [random.randint(80, 120) for _ in range(100)]  # packets per minute
    }

    # Introduce anomalies in the data
    anomalous_traffic = {
        'packet_size': [random.randint(200, 1500) for _ in range(20)],
        'traffic_volume': [random.randint(150, 200) for _ in range(20)]
    }

    # Combine into a DataFrame
    traffic_data = pd.DataFrame(normal_traffic)
    traffic_data = traffic_data.append(pd.DataFrame(anomalous_traffic), ignore_index=True)

    # Shuffle the data
    traffic_data = traffic_data.sample(frac=1).reset_index(drop=True)
    return traffic_data

def continuous_generation():
    try:
        while True:  # Infinite loop to continuously generate packets
            traffic_data = generate_traffic_data()
            for index, row in traffic_data.iterrows():
                print(f"Packet {index}: Size={row['packet_size']}, Volume={row['traffic_volume']}")
                time.sleep(1)  # Wait for 1 second to mimic real-time packet generation
    except KeyboardInterrupt:
        print("Stopped packet generation.")
