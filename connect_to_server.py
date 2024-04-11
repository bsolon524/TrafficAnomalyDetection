import socket
import random
import time
import pandas as pd

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

     # Create DataFrames from the dictionaries
    df_normal_traffic = pd.DataFrame(normal_traffic)
    df_anomalous_traffic = pd.DataFrame(anomalous_traffic)

    # Combine into a single DataFrame using pd.concat
    traffic_data = pd.concat([df_normal_traffic, df_anomalous_traffic], ignore_index=True)

    # Shuffle the data
    traffic_data = traffic_data.sample(frac=1).reset_index(drop=True)
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