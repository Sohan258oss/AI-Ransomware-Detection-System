import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import pickle
import os

# Load dataset
data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'behavior_logs.csv')
df = pd.read_csv(data_path)

print(f"[*] Dataset loaded: {df.shape[0]} rows")
print(f"[*] Class distribution:\n{df['Class'].value_counts()}")

# Use the most relevant behavioral features from this dataset
FEATURES = [
    'registry_read',
    'registry_write', 
    'registry_delete',
    'registry_total',
    'network_threats',
    'network_dns',
    'network_http',
    'network_connections',
    'processes_malicious',
    'processes_suspicious',
    'processes_monitored',
    'total_processes',
    'files_malicious',
    'files_suspicious',
    'files_text',
    'files_unknown',
    'dlls_calls',
    'apis'
]

# Drop rows with missing values in our feature columns
df = df.dropna(subset=FEATURES)

X = df[FEATURES]

# Convert Class column to binary: 0 = Benign, 1 = Ransomware
le = LabelEncoder()
y = le.fit_transform(df['Class'])  # Benign=0, Ransomware=1

print(f"[*] Classes found: {le.classes_}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"[*] Training on {len(X_train)} samples...")

model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print("\n=== Model Performance ===")
print(classification_report(y_test, model.predict(X_test), target_names=le.classes_))

# Save model and label encoder
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
encoder_path = os.path.join(os.path.dirname(__file__), 'encoder.pkl')

with open(model_path, 'wb') as f:
    pickle.dump(model, f)

with open(encoder_path, 'wb') as f:
    pickle.dump(le, f)

print("[+] Model saved to ml/model.pkl")
print("[+] Encoder saved to ml/encoder.pkl")