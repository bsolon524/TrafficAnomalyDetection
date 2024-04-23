# Authored by Seth Canada

import socket
import random
import time
import pandas as pd

def generate_traffic_data():
    # Example feature names, adjust these to match the actual features of your model
    feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]
    # Generate synthetic data for normal traffic
    normal_traffic = {
        feature: [random.randint(50, 100) for _ in range(100)] if feature in ['src_bytes', 'dst_bytes']  # Example for byte sizes
        else [random.randint(0, 1) for _ in range(100)] if feature in ['land', 'logged_in', 'root_shell', 'su_attempted']  # Binary features
        else [random.choice(['HTTP', 'FTP', 'SSH', 'TELNET']) for _ in range(100)] if feature == 'service'  # Example for service types
        else [random.random() for _ in range(100)]  # Random float for other numeric features
        for feature in feature_names
    }

    # Introduce anomalies in the data
    anomalous_traffic = {
        feature: [random.randint(150, 300) for _ in range(20)] if feature in ['src_bytes', 'dst_bytes']
        else [random.randint(0, 1) for _ in range(20)] if feature in ['land', 'logged_in', 'root_shell', 'su_attempted']
        else [random.choice(['HTTP', 'FTP', 'SSH', 'TELNET']) for _ in range(20)] if feature == 'service'
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
                    packet_message = f"Packet {index}: {row.to_json(indent=4)}"
                    s.sendto(packet_message.encode(), (host, port))
                    print(f"Sent: {packet_message}")
                    time.sleep(1)  # Wait for 1 second to mimic real-time packet generation
        except KeyboardInterrupt:
            print("Stopped packet generation.")

if __name__ == "__main__":
    send_data(data="This is a UDP test packet.")