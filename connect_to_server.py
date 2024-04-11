# Authored by Seth Canada

import socket
import random
import time
import pandas as pd

def generate_traffic_data():
    # Example feature names, adjust these to match the actual features of your model
    feature_names = ['packet_size', 'traffic_volume'] + [f'feature_{i}' for i in range(3, 41)]
    
    # Generate synthetic data for normal traffic
    normal_traffic = {
        feature: [random.randint(50, 100) for _ in range(100)] if feature in ['packet_size', 'traffic_volume']
        else [random.random() for _ in range(100)]  # Random float for other features
        for feature in feature_names
    }

    # Introduce anomalies in the data
    anomalous_traffic = {
        feature: [random.randint(30, 150) for _ in range(20)] if feature in ['packet_size', 'traffic_volume']
        else [random.random() * 2 for _ in range(20)]  # Scaled random float for other features
        for feature in feature_names
    }

    # Create DataFrames from the dictionaries
    df_normal_traffic = pd.DataFrame(normal_traffic)
    df_anomalous_traffic = pd.DataFrame(anomalous_traffic)

    # Combine into a single DataFrame using pd.concat
    traffic_data = pd.concat([df_normal_traffic, df_anomalous_traffic], ignore_index=True)

    # Shuffle the data
    traffic_data = traffic_data.sample(frac=1).reset_index(drop=True)
    # Add a 'label' column
    traffic_data['label'] = ['normal'] * 100 + ['anomaly'] * 20

    return traffic_data

def send_data(host='127.0.0.1', port=65432, data="Hello, server!"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            while True:  # Infinite loop to continuously generate packets
                traffic_data = generate_traffic_data()
                for index, row in traffic_data.iterrows():
                    packet_message = f"Packet {index}: Size={row['packet_size']}, Volume={row['traffic_volume']}"
                    s.sendto(packet_message.encode(), (host, port))
                    print(f"Sent: {packet_message}")
                    time.sleep(1)  # Wait for 1 second to mimic real-time packet generation
        except KeyboardInterrupt:
            print("Stopped packet generation.")

if __name__ == "__main__":
    send_data(data="This is a UDP test packet.")