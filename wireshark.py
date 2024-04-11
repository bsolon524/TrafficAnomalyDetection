# Authored by Seth Canada

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

    # Direct observations or calculations based on the packet
    features.append(packet.duration)  # 1. Duration
    features.append(1 if packet.protocol_type == 'TCP' else 2 if packet.protocol_type == 'UDP' else 0)  # 2. Protocol_type
    features.append(packet.service)  # 3. Service (You'll need a mapping from service to integers)
    features.append(packet.flag)  # 4. Flag (Similarly, you'll need a mapping from flag status to integers)
    features.append(packet.src_bytes)  # 5. Src_bytes
    features.append(packet.dst_bytes)  # 6. Dst_bytes
    features.append(1 if packet.land else 0)  # 7. Land
    features.append(packet.wrong_fragment)  # 8. Wrong_fragment
    features.append(packet.urgent)  # 9. Urgent

    # Placeholder values for content-related features
    # You might need custom logic to extract these based on packet content
    features.extend([0] * 13)  # 10. Hot to 22. Is_guest_login

    # Placeholder values for time-related features
    # Actual implementation should calculate these based on connection history
    features.extend([0] * 9)  # 23. Count to 31. Srv_diff_host_rate

    # Placeholder values for host-based traffic features
    # Similar to time-related, these require historical data analysis
    features.extend([0] * 11)  # 32. Dst_host_count to 42. Dst_host_srv_rerror_rate

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
print(type(scaler))
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
    capture = pyshark.LiveCapture(interface='loopback', display_filter='ip.addr==127.0.0.1')
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