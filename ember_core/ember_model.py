import os
import json
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# 13 features from feature_extractor.py
# "machine", "num_sections", "characteristics", "dll_characteristics", 
# "subsystem", "mean_section_entropy", "max_section_entropy", 
# "min_section_entropy", "suspicious_sections", "file_entropy", 
# "file_size", "total_imports", "suspicious_imports"

def generate_synthetic_data(num_samples=1000):
    """
    Generates synthetic PE feature data to train the static classifier.
    In a real-world enterprise setting, you would extract these features 
    from thousands of real ransomware and benign .exe files.
    """
    X = []
    y = []
    
    # Generate Benign samples (label = 0)
    for _ in range(num_samples // 2):
        machine = 34404  # AMD64
        num_sections = int(np.random.normal(5, 1))
        characteristics = 258
        dll_chars = 33088
        subsystem = 2  # GUI
        mean_ent = np.random.uniform(3.5, 6.0)
        max_ent = np.random.uniform(mean_ent, 6.8)
        min_ent = np.random.uniform(1.0, mean_ent)
        suspicious_sec = 0
        file_ent = np.random.uniform(4.0, 6.9)
        file_size = int(np.random.uniform(50000, 5000000))
        total_imp = int(np.random.uniform(50, 300))
        suspicious_imp = int(np.random.uniform(0, 2))
        
        X.append([machine, num_sections, characteristics, dll_chars, subsystem, 
                  mean_ent, max_ent, min_ent, suspicious_sec, file_ent, 
                  file_size, total_imp, suspicious_imp])
        y.append(0)

    # Generate Ransomware samples (label = 1)
    for _ in range(num_samples // 2):
        machine = 34404
        num_sections = int(np.random.normal(4, 1))
        characteristics = 258
        dll_chars = 33088
        subsystem = 2
        # Ransomware is often packed or encrypted, leading to high entropy
        mean_ent = np.random.uniform(6.5, 7.8)
        max_ent = np.random.uniform(7.0, 8.0)
        min_ent = np.random.uniform(4.0, mean_ent)
        suspicious_sec = int(np.random.uniform(0, 3))  # Maybe a .upx section
        file_ent = np.random.uniform(7.2, 8.0)  # High overall entropy
        file_size = int(np.random.uniform(20000, 2000000))
        total_imp = int(np.random.uniform(10, 150)) # Packed files have fewer total imports
        suspicious_imp = int(np.random.uniform(3, 10)) # High use of crypto APIs
        
        X.append([machine, max(1, num_sections), characteristics, dll_chars, subsystem, 
                  mean_ent, max_ent, min_ent, suspicious_sec, file_ent, 
                  file_size, max(1, total_imp), suspicious_imp])
        y.append(1)
        
    return np.array(X), np.array(y)

def train_ember_model():
    print("Generating synthetic static PE feature dataset...")
    X, y = generate_synthetic_data(2000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Static XGBoost Model (EMBER style)...")
    model = XGBClassifier(
        n_estimators=100, 
        learning_rate=0.1, 
        max_depth=5, 
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Static Model Accuracy on test set: {acc * 100:.2f}%")
    
    # Ensure models dir exists
    model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, "ember_static_model.pkl")
    joblib.dump(model, model_path)
    print(f"Static model saved to {model_path}")
    
if __name__ == "__main__":
    train_ember_model()
