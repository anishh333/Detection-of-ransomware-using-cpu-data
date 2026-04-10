import os
import joblib
try:
    from ember_core.feature_extractor import extract_features
except ImportError:
    from feature_extractor import extract_features

def scan_file_static(file_path):
    """
    Scans a file using the EMBER-style static ML model.
    Returns:
        dict: containing prediction ('Benign' or 'Malicious'), risk_score, and extracted features
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}
        
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "ember_static_model.pkl")
    if not os.path.exists(model_path):
        return {"error": "Static model not found. Train the model first."}
        
    # 1. Extract PE features
    extraction_result = extract_features(file_path)
    if not extraction_result:
        return {"error": "Not a valid Windows PE file (.exe, .dll)"}
        
    features_ordered, feature_keys = extraction_result
    
    # 2. Predict with Model
    try:
        model = joblib.load(model_path)
        # XGBoost requires a 2D array
        prob = model.predict_proba([features_ordered])[0][1]
        
        is_malicious = prob >= 0.5
        
        feature_dict = dict(zip(feature_keys, features_ordered))
        
        return {
            "prediction": "Malicious" if is_malicious else "Benign",
            "risk_score": float(prob * 100),
            "features": {
                "Entropy": round(feature_dict["file_entropy"], 2),
                "Suspicious Imports": feature_dict["suspicious_imports"],
                "Sections": feature_dict["num_sections"]
            }
        }
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}

if __name__ == "__main__":
    # Test on a generic Windows system binary
    test_file = r"C:\Windows\System32\notepad.exe"
    result = scan_file_static(test_file)
    print(f"Test Scan of {test_file}:")
    print(result)
