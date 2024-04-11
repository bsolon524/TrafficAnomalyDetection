# Step 1: Generate synthetic network traffic data
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump

# Generating synthetic data
np.random.seed(24)  # For reproducibility #original data is 42!!!!!
n_features = 4  # Example features: duration, protocol_type, packet_size, flag_status
n_samples = 200  # Total samples
n_anomalies = 20  # Number of anomalies

# Normal traffic
data_normal = np.random.normal(loc=0, scale=1, size=(n_samples - n_anomalies, n_features))
# Anomalous traffic
data_anomalies = np.random.uniform(low=-6, high=6, size=(n_anomalies, n_features))

data = np.concatenate([data_normal, data_anomalies], axis=0)
labels = np.array([1] * (n_samples - n_anomalies) + [-1] * n_anomalies)  # 1 for normal, -1 for anomaly

# Shuffle data
indices = np.arange(n_samples)
np.random.shuffle(indices)
data = data[indices]
labels = labels[indices]

# Step 2: Preprocessing
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data)

# Step 3: Train the Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=float(n_anomalies)/n_samples, random_state=42)
model.fit(data_scaled)

# Predictions
predictions = model.predict(data_scaled)

dump(model, 'isolation_forest_model.joblib')
dump(scaler, 'scaler.joblib')