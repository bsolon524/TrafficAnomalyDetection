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
    normal_traffic = {
    'duration': [random.randint(0, 3600) for _ in range(80)],  # Random duration up to an hour
    'protocol_type': ['tcp' for _ in range(80)],  # All 'tcp' since the example is tcp
    'service': ['ftp_data' for _ in range(80)],  # All 'ftp_data' reflecting the example
    'flag': ['SF' for _ in range(80)],  # All 'SF' flags as in the example
    'src_bytes': [random.randint(0, 600) for _ in range(80)],  # Range adjusted based on typical values
    'dst_bytes': [0 for _ in range(80)],  # Most at 0 to match the example
    'land': [0 for _ in range(80)],  # No land attack as per the example
    'wrong_fragment': [0 for _ in range(80)],  # No wrong fragments
    'urgent': [0 for _ in range(80)],  # No urgent packets
    'hot': [0 for _ in range(80)],  # No hot indicators
    'num_failed_logins': [0 for _ in range(80)],  # No failed logins
    'logged_in': [1 for _ in range(80)],  # Logged in as per the example
    'num_compromised': [0 for _ in range(80)],  # No compromised accounts
    'root_shell': [0 for _ in range(80)],  # No root shell
    'su_attempted': [0 for _ in range(80)],  # No su attempts
    'num_root': [0 for _ in range(80)],  # No root operations
    'num_file_creations': [0 for _ in range(80)],  # No file creations
    'num_shells': [0 for _ in range(80)],  # No shell prompts
    'num_access_files': [0 for _ in range(80)],  # No access to critical files
    'num_outbound_cmds': [0 for _ in range(80)],  # No outbound commands
    'is_host_login': [0 for _ in range(80)],  # No host logins
    'is_guest_login': [0 for _ in range(80)],  # No guest logins
    'count': [random.randint(1, 3) for _ in range(80)],  # Low connection count as per example
    'srv_count': [random.randint(1, 3) for _ in range(80)],  # Low service count
    'serror_rate': [random.uniform(0, 0.1) for _ in range(80)],  # Low error rates
    'srv_serror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'rerror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'srv_rerror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'same_srv_rate': [random.uniform(0.9, 1.0) for _ in range(80)],  # High same service rate
    'diff_srv_rate': [random.uniform(0, 0.1) for _ in range(80)],  # Low different service rate
    'srv_diff_host_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_count': [random.randint(20, 30) for _ in range(80)],  # Moderate host counts
    'dst_host_srv_count': [random.randint(20, 30) for _ in range(80)],
    'dst_host_same_srv_rate': [random.uniform(0.8, 1.0) for _ in range(80)],
    'dst_host_diff_srv_rate': [random.uniform(0, 0.2) for _ in range(80)],
    'dst_host_same_src_port_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_srv_diff_host_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_serror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_srv_serror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_rerror_rate': [random.uniform(0, 0.1) for _ in range(80)],
    'dst_host_srv_rerror_rate': [random.uniform(0, 0.1) for _ in range(80)]
}

    anomalous_traffic = {
    'duration': [0 for _ in range(40)],  # Anomalies often occur with short or zero duration
    'protocol_type': ['tcp' if random.random() < 0.8 else 'icmp' for _ in range(40)],  # Mainly TCP, some ICMP
    'service': [random.choice(['private', 'http', 'ftp_data', 'eco_i']) for _ in range(40)],  # Varied services
    'flag': ['S0' if random.random() > 0.5 else 'SF' for _ in range(40)],  # Mostly 'S0' and 'SF'
    'src_bytes': [0 if random.random() > 0.5 else random.randint(100, 300) for _ in range(40)],  # Zero or moderate src_bytes
    'dst_bytes': [0 for _ in range(40)],  # Zero dst_bytes common in anomalies
    'land': [1 if random.random() > 0.9 else 0 for _ in range(40)],  # Rare land attacks
    'wrong_fragment': [random.randint(0, 1) for _ in range(40)],  # Some packet fragmentation
    'urgent': [1 if random.random() > 0.95 else 0 for _ in range(40)],  # Rare urgent packets
    'hot': [1 if random.random() > 0.9 else 0 for _ in range(40)],  # Occasional hot indicators
    'num_failed_logins': [random.randint(0, 2) for _ in range(40)],  # Some failed logins
    'logged_in': [0 for _ in range(40)],  # Not logged in for most anomalies
    'num_compromised': [0 if random.random() > 0.8 else 1 for _ in range(40)],  # Rarely compromised
    'root_shell': [0 for _ in range(40)],
    'su_attempted': [0 for _ in range(40)],
    'num_root': [0 for _ in range(40)],
    'num_file_creations': [0 if random.random() > 0.8 else 1 for _ in range(40)],  # Rare file creations
    'num_shells': [0 for _ in range(40)],
    'num_access_files': [0 if random.random() > 0.8 else 1 for _ in range(40)],  # Rare access to files
    'num_outbound_cmds': [0 for _ in range(40)],  # No outbound commands
    'is_host_login': [0 for _ in range(40)],
    'is_guest_login': [0 for _ in range(40)],
    'count': [random.randint(50, 200) for _ in range(40)],  # Higher counts in anomalies
    'srv_count': [random.randint(1, 20) for _ in range(40)],  # Varied service counts
    'serror_rate': [random.uniform(0.5, 1.0) for _ in range(40)],  # Higher error rates
    'srv_serror_rate': [random.uniform(0.5, 1.0) for _ in range(40)],
    'rerror_rate': [random.uniform(0, 0.1) for _ in range(40)],
    'srv_rerror_rate': [random.uniform(0, 0.1) for _ in range(40)],
    'same_srv_rate': [random.uniform(0, 0.2) for _ in range(40)],  # Low same-service rates
    'diff_srv_rate': [random.uniform(0.8, 1.0) for _ in range(40)],  # High different-service rates
    'srv_diff_host_rate': [random.uniform(0, 0.2) for _ in range(40)],
    'dst_host_count': [255 for _ in range(40)],  # High destination host counts
    'dst_host_srv_count': [random.randint(1, 5) for _ in range(40)],  # Low service host counts
    'dst_host_same_srv_rate': [random.uniform(0.0, 0.1) for _ in range(40)],
    'dst_host_diff_srv_rate': [random.uniform(0.9, 1.0) for _ in range(40)],
    'dst_host_same_src_port_rate': [random.uniform(0.0, 0.5) for _ in range(40)],
    'dst_host_srv_diff_host_rate': [random.uniform(0.1, 0.5) for _ in range(40)],  # Higher rates can indicate scanning or spreading activity
    'dst_host_serror_rate': [random.uniform(0.5, 1.0) for _ in range(40)],  # High serror rates often indicate denial of service attacks
    'dst_host_srv_serror_rate': [random.uniform(0.5, 1.0) for _ in range(40)],  # Similarly, high service error rates suggest targeted service disruptions
    'dst_host_rerror_rate': [random.uniform(0.1, 0.5) for _ in range(40)],  # Moderate rejection rates could indicate port scans or other unauthorized access attempts
    'dst_host_srv_rerror_rate': [random.uniform(0.1, 0.5) for _ in range(40)]  # Reflects errors in service-specific traffic, possibly due to probing or attacks
}

    # Create DataFrames from the dictionaries
    df_normal_traffic = pd.DataFrame(normal_traffic)
    df_anomalous_traffic = pd.DataFrame(anomalous_traffic)

    df_normal_traffic['label'] = 'normal'
    df_anomalous_traffic['label'] = 'anomaly'

    # Combine into a single DataFrame using pd.concat
    traffic_data = pd.concat([df_normal_traffic, df_anomalous_traffic], ignore_index=True)

    # Shuffle the data
    traffic_data = traffic_data.sample(frac=1).reset_index(drop=True)
    # Add a 'label' column

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