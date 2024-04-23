# Authored by Seth Canada

import pyshark
from joblib import load
import numpy as np
import json
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

# Placeholder for simplicity - replace with your actual feature extraction, prediction, and labeling logic
packet_features = []  # To store features of each packet
true_labels = []  # To store the true label of each packet (1 for normal, -1 for anomaly)
predicted_labels = []  # To store the predicted label of each packet
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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

def extract_features(packet):
    features = []
    try:
        raw_data = str(packet.udp.payload, 'utf-8')
        print("Raw payload data:", raw_data)
    except AttributeError as e:
        print("Failed to access TCP payload:", e)

    try:
        payload = str(packet.udp.payload, 'utf-8')  # Assuming the payload is in the tcp layer
        data = json.loads(payload)  # Parse JSON payload
        features = [data.get(feature, 0) for feature in feature_names]
        if not features:
            print("No features extracted. Data might be empty or malformed:", data)
    except (json.JSONDecodeError, AttributeError) as e:
        print("Failed to decode JSON or access TCP payload:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)
    
    # # Basic features
    # features.append(float(getattr(packet, 'duration', 0)))  # Convert duration to float for consistency
    
    # # Encode protocol_type as integers (TCP: 1, UDP: 2, Others: 0)
    # protocol_map = {'TCP': 1, 'UDP': 2}  # Add other protocols as necessary
    # protocol_type = protocol_map.get(getattr(packet, 'protocol_type', '').upper(), 0)
    # features.append(protocol_type)
    
    # # Encode service and flag using predefined mappings if many unique values
    # service_map = {'http': 1, 'ftp': 2, 'smtp': 3, 'telnet': 4, 'unknown': 0}  # Extend as needed
    # flag_map = {'SF': 1, 'S0': 2, 'REJ': 3, 'RST': 4, 'unknown': 0}  # Extend as needed
    
    # features.append(service_map.get(getattr(packet, 'service', 'unknown'), 0))
    # features.append(flag_map.get(getattr(packet, 'flag', 'unknown'), 0))
    
    # # Continue for other direct observable features, ensuring all are numerically encoded
    # features.append(int(getattr(packet, 'src_bytes', 0)))
    # features.append(int(getattr(packet, 'dst_bytes', 0)))
    # features.append(1 if getattr(packet, 'land', False) else 0)
    # features.append(int(getattr(packet, 'wrong_fragment', 0)))
    # features.append(int(getattr(packet, 'urgent', 0)))
    
    # # Continue adding other features as integers or floats as appropriate
    # features.extend([
    #     int(getattr(packet, 'hot', 0)),
    #     int(getattr(packet, 'num_failed_logins', 0)),
    #     int(getattr(packet, 'logged_in', 0)),
    #     int(getattr(packet, 'num_compromised', 0)),
    #     int(getattr(packet, 'root_shell', 0)),
    #     int(getattr(packet, 'su_attempted', 0)),
    #     int(getattr(packet, 'num_root', 0)),
    #     int(getattr(packet, 'num_file_creations', 0)),
    #     int(getattr(packet, 'num_shells', 0)),
    #     int(getattr(packet, 'num_access_files', 0)),
    #     int(getattr(packet, 'num_outbound_cmds', 0)),
    #     int(getattr(packet, 'is_host_login', 0)),
    #     int(getattr(packet, 'is_guest_login', 0))
    # ])

    # # For traffic and host-based traffic features, ensure all numeric types are consistent
    # features.extend([
    #     int(getattr(packet, 'count', 0)),
    #     int(getattr(packet, 'srv_count', 0)),
    #     float(getattr(packet, 'serror_rate', 0.0)),
    #     float(getattr(packet, 'srv_serror_rate', 0.0)),
    #     float(getattr(packet, 'rerror_rate', 0.0)),
    #     float(getattr(packet, 'srv_rerror_rate', 0.0)),
    #     float(getattr(packet, 'same_srv_rate', 0.0)),
    #     float(getattr(packet, 'diff_srv_rate', 0.0)),
    #     float(getattr(packet, 'srv_diff_host_rate', 0.0)),
    #     int(getattr(packet, 'dst_host_count', 0)),
    #     int(getattr(packet, 'dst_host_srv_count', 0)),
    #     float(getattr(packet, 'dst_host_same_srv_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_diff_srv_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_same_src_port_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_srv_diff_host_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_serror_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_srv_serror_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_rerror_rate', 0.0)),
    #     float(getattr(packet, 'dst_host_srv_rerror_rate', 0.0))
    # ])

    return features


def determine_anomaly_type(features):
    anomaly_descriptions = []

    # Basic features
    if features[0] > 3600:  # Duration too long
        anomaly_descriptions.append("Excessive Duration")
    if features[1] not in [1, 2, 3]:  # Unusual protocol type
        anomaly_descriptions.append("Uncommon Protocol Type")
    if features[2] in ['other']:  # Unusual service
        anomaly_descriptions.append("Uncommon Service")
    if features[3] not in ['SF', 'S0', 'REJ', 'RST']:  # Flag check
        anomaly_descriptions.append("Suspicious Connection Flags")
    if features[4] > 5000 or features[5] > 5000:  # src_bytes and dst_bytes
        anomaly_descriptions.append("Large Data Transfer")
    if features[6] == 1:  # land
        anomaly_descriptions.append("Land Attack Detected")
    if features[7] > 0:  # wrong_fragment
        anomaly_descriptions.append("Fragmentation Anomaly")
    if features[8] > 0:  # urgent
        anomaly_descriptions.append("Urgent Packets Present")

    # Content-related features
    if features[9] > 0:  # hot indicators
        anomaly_descriptions.append("Hot Indicators")
    if features[10] > 3:  # num_failed_logins
        anomaly_descriptions.append("Multiple Failed Logins")
    if features[11] == 0:  # logged_in
        anomaly_descriptions.append("Login Failed")
    if features[12] > 0:  # num_compromised
        anomaly_descriptions.append("Compromised Security")
    if features[13] == 1:  # root_shell
        anomaly_descriptions.append("Root Shell Obtained")
    if features[14] > 0:  # su_attempted
        anomaly_descriptions.append("Su Command Attempt")
    if features[15] > 1:  # num_root
        anomaly_descriptions.append("Root Access from Multiple Hosts")
    if features[16] > 0:  # num_file_creations
        anomaly_descriptions.append("File Creation Activities")
    if features[17] > 0:  # num_shells
        anomaly_descriptions.append("Shell Prompts Opened")
    if features[18] > 0:  # num_access_files
        anomaly_descriptions.append("Access to Critical Files")
    if features[19] > 0:  # num_outbound_cmds
        anomaly_descriptions.append("Outbound Commands Detected")
    if features[20]:  # is_host_login
        anomaly_descriptions.append("Host Login Detected")
    if features[21]:  # is_guest_login
        anomaly_descriptions.append("Guest Login Detected")

    # Time-based traffic features
    if features[22] > 50:  # count
        anomaly_descriptions.append("High Same Host Connection Rate")
    if features[23] > 50:  # srv_count
        anomaly_descriptions.append("High Same Service Connection Rate")
    if features[24] > 0.5:  # serror_rate
        anomaly_descriptions.append("High SYN Error Rate")
    if features[25] > 0.5:  # srv_serror_rate
        anomaly_descriptions.append("High Service SYN Error Rate")
    if features[26] > 0.5:  # rerror_rate
        anomaly_descriptions.append("High REJ Error Rate")
    if features[27] > 0.5:  # srv_rerror_rate
        anomaly_descriptions.append("High Service REJ Error Rate")
    if features[28] < 0.2:  # same_srv_rate
        anomaly_descriptions.append("Low Same-Service Rate")
    if features[29] > 0.8:  # diff_srv_rate
        anomaly_descriptions.append("High Different-Service Rate")
    if features[30] > 0.5:  # srv_diff_host_rate
        anomaly_descriptions.append("High Service to Different Host Rate")

    # Host-based traffic features
    if features[31] > 100:  # dst_host_count
        anomaly_descriptions.append("High Destination Host Count")
    if features[32] > 100:  # dst_host_srv_count
        anomaly_descriptions.append("High Destination Service Count")
    if features[33] < 0.2:  # dst_host_same_srv_rate
        anomaly_descriptions.append("Low Same-Service Rate to Destination")
    if features[34] > 0.8:  # dst_host_diff_srv_rate
        anomaly_descriptions.append("High Different-Service Rate to Destination")
    if features[35] > 0.5:  # dst_host_same_src_port_rate
        anomaly_descriptions.append("High Same Source Port Rate")
    if features[36] > 0.5:  # dst_host_srv_diff_host_rate
        anomaly_descriptions.append("High Service on Different Hosts Rate")
    if features[37] > 0.5:  # dst_host_serror_rate
        anomaly_descriptions.append("High Destination Host SYN Error Rate")
    if features[38] > 0.5:  # dst_host_srv_serror_rate
        anomaly_descriptions.append("High Destination Service SYN Error Rate")
    if features[39] > 0.5:  # dst_host_rerror_rate
        anomaly_descriptions.append("High Destination Host REJ Error Rate")
    if features[40] > 0.5:  # dst_host_srv_rerror_rate
        anomaly_descriptions.append("High Destination Service REJ Error Rate")

    return ", ".join(anomaly_descriptions) if anomaly_descriptions else "No Anomaly Detected"

def log_anomaly(packet_info, anomaly_description):
    packet_info['anomaly_description'] = anomaly_description
    filename = 'anomalies_log.json'
    
    # Append the new anomaly to the JSON file, pretty-printed for readability
    with open(filename, 'a') as file:
        file.write(json.dumps(packet_info, indent=4, sort_keys=True))
        file.write(',\n')  # Add comma and newline for separation and readability

# Load your pre-trained model and scaler
model = load('isolation_forest_pipeline.joblib')
scaler = load('scaler.joblib')
def analyze_packet(packet):
    features = extract_features(packet)  # Ensure this function is properly defined to return the features as a list
    # print(features)
    # print("")
    # print([item for item in features])
    # features = np.array(features)
    # features = features.reshape(1, -1)
    features_scaled = scaler.transform([features])  # Scale the features before prediction
    print(features_scaled)
    prediction = model.predict(features_scaled)[0]  # Predict using the scaled features

    # Initialize lists for logging (make sure these are defined outside this function if they need to be accessed later)
    packet_features, predicted_labels, true_labels = [], [], []

    if prediction == -1:
        true_label = -1
        print(f"Anomaly detected: {packet}")

        anomaly_type = determine_anomaly_type(features)  # Use the comprehensive check for anomalies

        # Collect packet info for logging
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'highest_layer': packet.highest_layer,
            'length': packet.length,
            'anomaly_type': anomaly_type  # Include anomaly type in the logged information
        }

        # Add IP and port information if available
        if hasattr(packet, 'ip'):
            packet_info.update({
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
            })
        if hasattr(packet, packet.transport_layer):
            layer = getattr(packet, packet.transport_layer.lower(), None)
            if layer:
                packet_info.update({
                    'src_port': layer.srcport,
                    'dst_port': layer.dstport,
                })

        log_anomaly(packet_info, anomaly_description=anomaly_type)  # Assume a function to log anomalies is defined
    else:
        true_label = 1
        # print(f"Normal traffic: {packet}")

    # Append data to your lists for further analysis or logging
    packet_features.append(features)
    predicted_labels.append(prediction)
    true_labels.append(true_label)  # Assuming you have a way to set true_label for each packet

    # This function now fully integrates anomaly detection
def capture_packets():
    capture = pyshark.LiveCapture(interface='Loopback', display_filter='ip.addr==udp')
    for packet in capture.sniff_continuously(packet_count=50):
        with open('packet_info.json', 'a') as f:
            json.dump(packet, f, indent=4)
        try:
            # If payload data extraction is needed:
            if hasattr(packet.udp, 'payload'):
                payload_data = packet.udp.payload
                print("Payload data:", payload_data)
        except AttributeError as e:
            print("Error accessing packet data:", e)
        # print('Just captured a packet:', packet)
        analyze_packet(packet=packet)

    # Evaluate metrics
    accuracy = accuracy_score(true_labels, predicted_labels)
    precision = precision_score(true_labels, predicted_labels, pos_label=-1, zero_division=1)  # Assuming -1 is the label for anomalies
    recall = recall_score(true_labels, predicted_labels, pos_label=-1, zero_division=1)
    f1 = f1_score(true_labels, predicted_labels, pos_label=-1, zero_division=1)

    # Print the evaluation metrics
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")

if __name__ == "__main__":
    capture_packets()  # Replace with actual network interface