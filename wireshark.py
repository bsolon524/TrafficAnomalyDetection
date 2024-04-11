import pyshark
from joblib import load
import numpy as np
import json
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Placeholder for simplicity - replace with your actual feature extraction, prediction, and labeling logic
packet_features = []  # To store features of each packet
true_labels = []  # To store the true label of each packet (1 for normal, -1 for anomaly)
predicted_labels = []  # To store the predicted label of each packet

def extract_features(packet):
    features = []

    # Feature 1: Packet Length
    packet_length = int(packet.length)
    features.append(packet_length)

    # Feature 2: Protocol Type (1 for TCP, 2 for UDP, 0 for others)
    if 'TCP' in packet:
        protocol_type = 1
    elif 'UDP' in packet:
        protocol_type = 2
    else:
        protocol_type = 0
    features.append(protocol_type)

    # Features 3 & 4: Source and Destination Ports (set to 0 for non-TCP/UDP packets)
    src_port = dst_port = 0
    if protocol_type in [1, 2]:  # Check if TCP or UDP
        src_port = int(packet[packet.transport_layer].srcport)
        dst_port = int(packet[packet.transport_layer].dstport)
    features.extend([src_port, dst_port])  # Add src and dst ports to the features list

    return features

def determine_anomaly_type(features):
    # Simplified heuristics to determine anomaly type based on static packet features
    anomaly_descriptions = []

    # Check for large packet size
    if features[2] > 1000:  # Assuming the first feature is packet size
        anomaly_descriptions.append("Large Packet Size")

    # Check for uncommon port usage (as an example of simple anomaly detection)
    if features[3] in [6667, 22]:  # Assuming the fourth feature is the destination port
        anomaly_descriptions.append("Uncommon Port Usage")

    # The concept of "High Frequency" cannot be determined from static features of a single packet
    # and would require temporal analysis of traffic patterns.

    return ", ".join(anomaly_descriptions) if anomaly_descriptions else "No Anomaly Detected"


def log_anomaly(packet_info, anomaly_description):
    packet_info['anomaly_description'] = anomaly_description
    filename = 'anomalies_log.json'
    
    # Append the new anomaly to the JSON file, pretty-printed for readability
    with open(filename, 'a') as file:
        file.write(json.dumps(packet_info, indent=4, sort_keys=True))
        file.write(',\n')  # Add comma and newline for separation and readability

# Load your pre-trained model and scaler
model = load('isolation_forest_model.joblib')
scaler = load('scaler.joblib')

def analyze_packet(packet):
    features = extract_features(packet)
    features_scaled = scaler.transform([features])

    prediction = model.predict(features_scaled)[0]

    if prediction == -1:
        true_label = -1
        print(f"Anomaly detected: {packet}")

        anomaly_type = determine_anomaly_type(features)

        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'highest_layer': packet.highest_layer,
            'length': packet.length,
            'anomaly_type': anomaly_type,  # Include anomaly type in the logged information
        }
        if hasattr(packet, 'ip'):
            packet_info.update({
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
            })
        if hasattr(packet, packet.transport_layer):
            layer = getattr(packet, packet.transport_layer.lower())
            packet_info.update({
                'src_port': layer.srcport,
                'dst_port': layer.dstport,
            })

        log_anomaly(packet_info, anomaly_type)  # Pass anomaly_type to log_anomaly function
    else:
        true_label = 1
        print(f"Normal traffic: {packet}")

    # Append data to your lists - assuming you can determine true_label here
    packet_features.append(features)
    predicted_labels.append(prediction)
    true_labels.append(true_label)  # Assuming you have a way to set true_label for each packet
        
def capture_packets():
    capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', display_filter='ip.addr==127.0.0.1')
    for packet in capture.sniff_continuously(packet_count=50):  # Adjust as needed
        print('Just captured a packet:', packet)
        analyze_packet(packet=packet)

    # Evaluate metrics
    accuracy = accuracy_score(true_labels, predicted_labels)
    precision = precision_score(true_labels, predicted_labels, pos_label=-1)  # Assuming -1 is the label for anomalies
    recall = recall_score(true_labels, predicted_labels, pos_label=-1)
    f1 = f1_score(true_labels, predicted_labels, pos_label=-1)

    # Print the evaluation metrics
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")

if __name__ == "__main__":
    capture_packets()  # Replace with actual network interface