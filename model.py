# Authored by Seth Canada

# Step 1: Generate synthetic network traffic data
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump

df = pd.read_csv('./archive/Train.txt', sep=',', header=None)
test_df = pd.read_csv('./archive/Test.txt', sep=',', header=None)
label_encoder = LabelEncoder()
# Identify categorical columns - these are just examples based on your screenshot
# You will need to adjust the indices according to actual columns in your dataset
categorical_cols = [1, 2, 3]  # Change these indices to match the categorical columns in your dataset

# All other columns are assumed to be numerical
numerical_cols = [i for i in range(df.shape[1] - 2) if i not in categorical_cols]

# Labels are in the second last column
y_train = df.iloc[:, -2]
X_train = df.drop(df.columns[[-2, -1]], axis=1)  # Drop the label and the last column, which might not be a feature
print(type(X_train))
# Preprocessing for numerical data: scaling
numerical_transformer = StandardScaler()
# X_train_scaled = numerical_transformer.fit_transform(X_train)

# Preprocessing for categorical data: one-hot encoding
categorical_transformer = OneHotEncoder(handle_unknown='ignore')
preprocessor_scale = ColumnTransformer(
    transformers=[
        ('cat', OneHotEncoder(), categorical_cols)
    ],
    remainder='passthrough'  # This keeps all other columns unchanged
)
X_train_scaled = preprocessor_scale.fit_transform(X_train)
print(type(X_train_scaled))
# Bundle preprocessing for numerical and categorical data
preprocessor = ColumnTransformer(
    transformers=[
        ('num', numerical_transformer, numerical_cols),
        ('cat', categorical_transformer, categorical_cols)
    ])

# Define the model
model = IsolationForest(n_estimators=100000, contamination=0.5, random_state=42, max_samples='auto', max_features=1.0)

# Bundle preprocessing and modeling code in a pipeline
clf = Pipeline(steps=[('preprocessor', preprocessor),
                      ('model', model)])

# # Map all non-'normal' labels to 'anomaly'
# y_train_binary = ['normal' if label == 'normal' else 'anomaly' for label in y_train]
# # Initialize the LabelEncoder and fit it to the binary y_train
# label_encoder = label_encoder.fit(y_train_binary)
# # unique_labels = y.unique().tolist()
# # print(unique_labels)
# # label_encoder = label_encoder.fit(unique_labels)
# y_train_encoded = label_encoder.transform(y_train_binary)
# # Preprocessing of training data, fit model 
# clf.fit(X_train, y_train_encoded)
# X_test = test_df.iloc[:, :-2]
# y_test = test_df.iloc[:, -2]
# y_test_binary = ['normal' if label == 'normal' else 'anomaly' for label in y_test]
# y_test_encoded = label_encoder.transform(y_test_binary)
# # Preprocessing of test data, get predictions
# y_pred = clf.predict(X_test)

# # Convert prediction output to align with the label format
# y_pred_labels = label_encoder.inverse_transform(
#     [(1 if i == 1 else 0) for i in y_pred]  # Assuming 'normal' was encoded as 1 and 'anomaly' as 0
# )
# y_pred_encoded = label_encoder.transform(y_pred_labels)
# # Apply preprocessing steps
# # Assuming the preprocessing steps have already been fit to the training data
# X_test_new = test_df.iloc[:, :-2]  # Features
# y_test_new = test_df.iloc[:, -2]   # Labels

# # Convert all non-'normal' labels to 'anomaly' in the test labels
# y_test_new_binary = ['normal' if label == 'normal' else 'anomaly' for label in y_test_new]

# # Use the LabelEncoder fitted on the training labels to encode the test labels
# y_test_new_encoded = label_encoder.transform(y_test_new_binary)
# # Create the preprocessor
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', StandardScaler(), numerical_features),
#         ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
#     ])

# # Create the pipeline
# clf = Pipeline(steps=[('preprocessor', preprocessor),
#                       ('model', IsolationForest(n_estimators=100, random_state=42, contamination='auto'))])

# # Fit the pipeline to the training data
# clf.fit(X_train, y_train_encoded)

# # Apply the same ColumnTransformer or other preprocessing steps to the test features
# X_test_new_processed = preprocessor.transform(X_test_new)
# clf.fit(X_train, y_train_encoded)
# # Predict on the test data
# y_pred_new = clf.predict(X_test_new_processed)

# # Since Isolation Forest outputs -1 for anomalies and 1 for normal, convert this to match the LabelEncoder classes
# y_pred_new_adjusted = label_encoder.inverse_transform(
#     [(1 if i == 1 else 0) for i in y_pred_new]  # Assuming 'normal' was encoded as 1 and 'anomaly' as 0
# )

# # Evaluate the model performance
# print(confusion_matrix(y_test_new_encoded, y_pred_new_adjusted))
# print(classification_report(y_test_new_encoded, y_pred_new_adjusted))

# Evaluation
# print(confusion_matrix(y_test_encoded, y_pred_encoded))
# print(classification_report(y_test_encoded, y_pred_encoded))
# # Assume the last column is the label and the rest are features
# X = df.iloc[:, :-1]
# y = df.iloc[:, -1]
# df.select_dtypes(include=['object'])
# df_encoded = pd.get_dummies(df)

# X = df_encoded.iloc[:, :-1]
# y = df_encoded.iloc[:, -1]

# # Scaling features
# scaler = StandardScaler()
# print("Head")
# print(X.head())
# print("end of head")
# print("")
# print("shape")
# print(X.shape)
# print("End of shape")
# X_scaled = scaler.fit_transform(X)
# X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
# # Generating synthetic data
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

# predictions = model.predict(data_scaled)

# dump(model, 'isolation_forest_model.joblib')
dump(preprocessor_scale, 'scaler.joblib')