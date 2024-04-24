import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from joblib import dump

# Load training data
df = pd.read_csv('./archive/Train.txt', sep=',', header=None)
protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'unknown': 0}
service_map = {'http': 1, 'ftp': 2, 'smtp': 3, 'telnet': 4, 'unknown': 0}
flag_map = {'SF': 1, 'S0': 2, 'REJ': 3, 'RST': 4, 'unknown': 0}

# Assuming the correct indices for protocol_type, service, and flag are 0, 1, and 2 respectively
df.iloc[:, 1] = df.iloc[:, 0].map(protocol_map).fillna(0)
df.iloc[:, 2] = df.iloc[:, 1].map(service_map).fillna(0)
df.iloc[:, 3] = df.iloc[:, 2].map(flag_map).fillna(0)

# Assuming the last column is the label
y = df.iloc[:, -2]
X = df.drop(df.columns[[-2, -1]], axis=1)  # Drop the label and the last column, which might not be a feature

# Define categorical and numerical columns
numerical_cols = list(range(X.shape[1]))  # Treat all columns as numerical
# Preprocessor for numerical and categorical data
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_cols),
    ],
    remainder='passthrough')

# Define the IsolationForest model
model = IsolationForest(n_estimators=1000000, random_state=42, contamination='auto')

# Create a pipeline that combines preprocessing with the model
pipeline = Pipeline([
    ('preprocessor', preprocessor),
    ('model', model)
])
preprocessor.fit_transform(X)
X_transformed = preprocessor.transform(X)
print(X_transformed.shape)
# Fit the model
pipeline.fit(X, y)

# Optionally save the model to disk
dump(pipeline, 'isolation_forest_pipeline.joblib')
dump(preprocessor, 'scaler.joblib')
