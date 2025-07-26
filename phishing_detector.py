import pandas as pd
import numpy as np
import re
import tkinter as tk
from tkinter import messagebox, ttk
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse
import joblib
import os

class PhishingDetector:
    def __init__(self):
        self.model = None
        self.features = [
            'url_length',
            'has_ip_address',
            'has_at_symbol',
            'has_double_slash_redirect',
            'has_dash_in_domain',
            'has_multiple_subdomains',
            'uses_https',
            'domain_registration_length',
            'has_suspicious_words',
            'url_shortening_service'
        ]
    
    def extract_features(self, url):
        """Extract features from a URL"""
        features = {}
        
        # URL length (phishing URLs tend to be longer)
        features['url_length'] = len(url)
        
        # Check for IP address in URL (e.g., http://123.123.123.123/...)
        features['has_ip_address'] = 1 if re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))',
            url
        ) else 0
        
        # Check for @ symbol in URL
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # Check for double slash redirect
        features['has_double_slash_redirect'] = 1 if '//' in url[8:] else 0
        
        # Check for dash in domain
        domain = urlparse(url).netloc
        features['has_dash_in_domain'] = 1 if '-' in domain else 0
        
        # Check for multiple subdomains
        subdomain_count = domain.count('.')
        features['has_multiple_subdomains'] = 1 if subdomain_count > 1 else 0
        
        # Check if HTTPS is used
        features['uses_https'] = 1 if url.startswith('https') else 0
        
        # Domain registration length (simplified - just a placeholder value)
        # In a real implementation, this would check WHOIS data
        features['domain_registration_length'] = 1  # Placeholder
        
        # Check for suspicious words
        suspicious_words = [
            'paypal', 'login', 'signin', 'bank', 'account', 'update', 'confirm',
            'verify', 'secure', 'webscr', 'service', 'notification', 'access'
        ]
        features['has_suspicious_words'] = 0
        for word in suspicious_words:
            if word in url.lower():
                features['has_suspicious_words'] = 1
                break
        
        # Check for URL shortening service
        shortening_services = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'tr.im',
            'is.gd', 'cli.gs', 'ow.ly', 'bit.do', 'j.mp', 'cutt.ly'
        ]
        features['url_shortening_service'] = 0
        for service in shortening_services:
            if service in url.lower():
                features['url_shortening_service'] = 1
                break
        
        return features
    
    def train(self, dataset_path):
        """Train the model using the provided dataset"""
        try:
            # Load dataset
            df = pd.read_csv(dataset_path)
            
            # Prepare features and target
            X = df[self.features]
            y = df['is_phishing']
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred)
            
            print(f"Model trained with accuracy: {accuracy:.2f}")
            print("Classification Report:")
            print(report)
            
            # Save model
            joblib.dump(self.model, 'phishing_model.pkl')
            print("Model saved as 'phishing_model.pkl'")
            
            return True
        
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def load_model(self, model_path):
        """Load a trained model"""
        try:
            self.model = joblib.load(model_path)
            print(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        if self.model is None:
            return "Error: Model not loaded"
        
        # Extract features
        features_dict = self.extract_features(url)
        
        # Convert to DataFrame
        features_df = pd.DataFrame([features_dict])
        
        # Ensure all required features are present
        for feature in self.features:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Select only the features used by the model
        features_df = features_df[self.features]
        
        # Make prediction
        prediction = self.model.predict(features_df)[0]
        probability = self.model.predict_proba(features_df)[0]
        
        # Get confidence score
        confidence = probability[1] if prediction == 1 else probability[0]
        
        result = "Phishing URL" if prediction == 1 else "Legitimate URL"
        return f"{result} (Confidence: {confidence:.2f})"
    
    def run_gui(self):
        """Run the GUI application"""
        # Create the main window
        root = tk.Tk()
        root.title("Phishing URL Detector")
        root.geometry("600x500")
        root.configure(bg="#f0f0f0")
        
        # Set styles
        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 12), background="#f0f0f0")
        style.configure("TButton", font=("Arial", 12))
        style.configure("TEntry", font=("Arial", 12))
        
        # Create header
        header_frame = tk.Frame(root, bg="#4a6cf7", padx=20, pady=20)
        header_frame.pack(fill="x")
        
        header_label = tk.Label(
            header_frame,
            text="Phishing URL Detector",
            font=("Arial", 20, "bold"),
            fg="white",
            bg="#4a6cf7"
        )
        header_label.pack()
        
        # Create main content frame
        content_frame = tk.Frame(root, bg="#f0f0f0", padx=20, pady=20)
        content_frame.pack(fill="both", expand=True)
        
        # URL input
        url_label = ttk.Label(content_frame, text="Enter URL to check:")
        url_label.pack(pady=(0, 5), anchor="w")
        
        url_entry = ttk.Entry(content_frame, width=50)
        url_entry.pack(pady=(0, 20), fill="x")
        
        # Buttons frame
        buttons_frame = tk.Frame(content_frame, bg="#f0f0f0")
        buttons_frame.pack(pady=(0, 20))
        
        # Check button
        check_button = ttk.Button(
            buttons_frame,
            text="Check URL",
            command=lambda: self._check_url(url_entry.get(), result_label)
        )
        check_button.pack(side="left", padx=5)
        
        # Train button
        train_button = ttk.Button(
            buttons_frame,
            text="Train Model",
            command=lambda: self._train_model(result_label)
        )
        train_button.pack(side="left", padx=5)
        
        # Result display
        result_frame = tk.Frame(content_frame, bg="white", padx=15, pady=15, bd=1, relief="solid")
        result_frame.pack(fill="x")
        
        result_label = tk.Label(
            result_frame,
            text="Enter a URL and click 'Check URL' to analyze",
            font=("Arial", 12),
            bg="white",
            justify="left",
            wraplength=550
        )
        result_label.pack(anchor="w")
        
        # Footer
        footer_frame = tk.Frame(root, bg="#e0e0e0", padx=20, pady=10)
        footer_frame.pack(fill="x", side="bottom")
        
        footer_label = tk.Label(
            footer_frame,
            text="© 2023 Phishing URL Detector",
            font=("Arial", 10),
            bg="#e0e0e0"
        )
        footer_label.pack()
        
        # Start the GUI event loop
        root.mainloop()
    
    def _check_url(self, url, result_label):
        """Check a URL and update the result label"""
        if not url:
            result_label.config(text="Please enter a URL")
            return
        
        # Add http:// if not present
        if not url.startswith('http'):
            url = 'http://' + url
        
        try:
            # Check if model is loaded
            if self.model is None:
                if os.path.exists('phishing_model.pkl'):
                    self.load_model('phishing_model.pkl')
                else:
                    result_label.config(
                        text="No model loaded. Please train a model first."
                    )
                    return
            
            # Extract features
            features = self.extract_features(url)
            features_text = "\n\nFeatures:\n"
            for feature, value in features.items():
                features_text += f"- {feature}: {value}\n"
            
            # Make prediction
            result = self.predict(url)
            
            # Update result label
            result_label.config(
                text=f"URL: {url}\n\nResult: {result}{features_text}"
            )
            
        except Exception as e:
            result_label.config(text=f"Error: {str(e)}")
    
    def _train_model(self, result_label):
        """Train the model and update the result label"""
        try:
            # Check if dataset exists
            if not os.path.exists('phishing_dataset.csv'):
                result_label.config(
                    text="No dataset found. Please create a dataset first."
                )
                return
            
            # Train model
            result_label.config(text="Training model... Please wait.")
            success = self.train('phishing_dataset.csv')
            
            if success:
                result_label.config(
                    text="Model trained successfully and saved as 'phishing_model.pkl'"
                )
            else:
                result_label.config(text="Failed to train model")
                
        except Exception as e:
            result_label.config(text=f"Error: {str(e)}")


# If run directly, start the GUI
if __name__ == "__main__":
    detector = PhishingDetector()
    
    # Load model if it exists
    if os.path.exists('phishing_model.pkl'):
        detector.load_model('phishing_model.pkl')
    
    # Run the GUI
    detector.run_gui()