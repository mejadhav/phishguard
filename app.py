from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import sys
import json
from phishing_detector import PhishingDetector

# Configure Flask to serve static files from the current directory
app = Flask(__name__, static_folder='.', template_folder='.')

# Initialize the phishing detector
detector = PhishingDetector()

# Load the model if it exists
if os.path.exists('phishing_model.pkl'):
    detector.load_model('phishing_model.pkl')

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

# Routes for static files - these will serve files directly from the root directory
@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')

@app.route('/script.js')
def serve_js():
    return send_from_directory('.', 'script.js')

@app.route('/shield.svg')
def serve_shield():
    return send_from_directory('.', 'shield.svg')

@app.route('/phishing.svg')
def serve_phishing():
    return send_from_directory('.', 'phishing.svg')

@app.route('/api/check_url', methods=['POST'])
def check_url():
    """API endpoint to check a URL"""
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Add http:// if not present
    if not url.startswith('http'):
        url = 'http://' + url
    
    try:
        # Check if model is loaded
        if detector.model is None:
            if os.path.exists('phishing_model.pkl'):
                detector.load_model('phishing_model.pkl')
            else:
                # If no model exists, train a simple one with a small dataset
                try:
                    from generate_dataset import generate_dataset
                    print("No model found. Generating a small dataset and training a model...")
                    df = generate_dataset(num_samples=500, phishing_ratio=0.5)
                    df.to_csv('small_phishing_dataset.csv', index=False)
                    detector.train('small_phishing_dataset.csv')
                except Exception as e:
                    print(f"Error generating dataset and training model: {e}")
                    return jsonify({
                        'error': 'No model available. Please train a model first.'
                    }), 500
        
        # Extract features
        features = detector.extract_features(url)
        
        # Make prediction
        result = detector.predict(url)
        
        # Parse the prediction result
        is_phishing = 'Phishing' in result
        confidence_str = result.split('Confidence: ')[1].strip(')')
        confidence = float(confidence_str)
        
        # Return the result
        return jsonify({
            'prediction': 'Phishing URL' if is_phishing else 'Legitimate URL',
            'confidence': confidence,
            'features': features
        })
    
    except Exception as e:
        print(f"Error checking URL: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/train', methods=['POST'])
def train_model():
    """API endpoint to train the model"""
    try:
        # Generate a dataset if needed
        if not os.path.exists('phishing_dataset.csv'):
            try:
                from generate_dataset import generate_dataset
                print("Generating dataset...")
                df = generate_dataset(num_samples=2000, phishing_ratio=0.5)
                df.to_csv('phishing_dataset.csv', index=False)
            except Exception as e:
                print(f"Error generating dataset: {e}")
                return jsonify({'error': 'Failed to generate dataset'}), 500
        
        # Train the model
        success = detector.train('phishing_dataset.csv')
        
        if success:
            return jsonify({'message': 'Model trained successfully'})
        else:
            return jsonify({'error': 'Failed to train model'}), 500
    
    except Exception as e:
        print(f"Error training model: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)