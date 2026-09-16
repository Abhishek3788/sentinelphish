import json
import os
from pathlib import Path
import sys

# Ensure root project directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import random
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import xgboost as xgb
import lightgbm as lgb
from app.models.feature_engineering import extract_url_features

ARTIFACTS_DIR = Path(__file__).parent.parent / "app" / "models" / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_synthetic_dataset(num_samples: int = 1500):
    print("Generating synthetic URL dataset...")
    legit_domains = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
        "github.com", "youtube.com", "linkedin.com", "twitter.com", "facebook.com",
        "reddit.com", "netflix.com", "adobe.com", "wordpress.org", "cloudflare.com"
    ]
    
    phishing_templates = [
        "http://paypal-secure-login-{id}.xyz/verify/account",
        "http://{brand}-security-update-notice-{id}.top/login.php",
        "http://192.168.1.{id}/auth/banking/signin",
        "https://account-verify-{brand}-{id}.work/user-confirm",
        "http://{brand}.com.verify-login-{id}.cfd/auth"
    ]
    
    data = []
    
    # Legit URLs
    for i in range(num_samples // 2):
        domain = random.choice(legit_domains)
        path = random.choice(["", "/about", "/login", "/search?q=test", "/docs/guide", "/user/profile"])
        scheme = "https" if random.random() > 0.1 else "http"
        url = f"{scheme}://{domain}{path}"
        feats = extract_url_features(url)
        feats["label"] = 0  # Safe
        data.append(feats)

    # Phishing URLs
    for i in range(num_samples // 2):
        tpl = random.choice(phishing_templates)
        brand = random.choice(["paypal", "apple", "chase", "binance", "metamask", "microsoft"])
        url = tpl.format(brand=brand, id=random.randint(100, 9999))
        feats = extract_url_features(url)
        feats["label"] = 1  # Phishing
        data.append(feats)

    df = pd.DataFrame(data)
    return df


def train_models():
    df = generate_synthetic_dataset()
    X = df.drop(columns=["label"])
    y = df["label"]

    feature_names = list(X.columns)
    with open(ARTIFACTS_DIR / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, ARTIFACTS_DIR / "scaler.joblib")

    # 1. Random Forest
    print("\nTraining Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf.fit(X_train_scaled, y_train)
    rf_preds = rf.predict(X_test_scaled)
    print("Random Forest Accuracy:", round(accuracy_score(y_test, rf_preds), 4))
    joblib.dump(rf, ARTIFACTS_DIR / "random_forest.joblib")

    # 2. XGBoost
    print("\nTraining XGBoost Classifier...")
    xgb_model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42)
    xgb_model.fit(X_train_scaled, y_train)
    xgb_preds = xgb_model.predict(X_test_scaled)
    print("XGBoost Accuracy:", round(accuracy_score(y_test, xgb_preds), 4))
    joblib.dump(xgb_model, ARTIFACTS_DIR / "xgboost.joblib")

    # 3. LightGBM
    print("\nTraining LightGBM Classifier...")
    lgbm_model = lgb.LGBMClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, verbose=-1)
    lgbm_model.fit(X_train_scaled, y_train)
    lgbm_preds = lgbm_model.predict(X_test_scaled)
    print("LightGBM Accuracy:", round(accuracy_score(y_test, lgbm_preds), 4))
    joblib.dump(lgbm_model, ARTIFACTS_DIR / "lightgbm.joblib")

    print("\nModel training complete. All model artifacts saved to app/models/artifacts/")


if __name__ == "__main__":
    train_models()
