import argparse
import os
import sys
from phishing_detector import PhishingDetector

def main():
    parser = argparse.ArgumentParser(description='Phishing URL Detector CLI')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the model')
    train_parser.add_argument('--dataset', '-d', required=True, help='Path to the dataset CSV file')
    train_parser.add_argument('--output', '-o', default='phishing_model.pkl', help='Output model file path')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check a URL')
    check_parser.add_argument('--url', '-u', required=True, help='URL to check')
    check_parser.add_argument('--model', '-m', default='phishing_model.pkl', help='Path to the model file')
    check_parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed features')
    
    # Batch check command
    batch_parser = subparsers.add_parser('batch', help='Check multiple URLs from a file')
    batch_parser.add_argument('--input', '-i', required=True, help='Input file with one URL per line')
    batch_parser.add_argument('--output', '-o', default='results.csv', help='Output CSV file for results')
    batch_parser.add_argument('--model', '-m', default='phishing_model.pkl', help='Path to the model file')
    
    # Generate dataset command
    generate_parser = subparsers.add_parser('generate', help='Generate a synthetic dataset')
    generate_parser.add_argument('--samples', '-s', type=int, default=2000, help='Number of samples to generate')
    generate_parser.add_argument('--ratio', '-r', type=float, default=0.5, help='Ratio of phishing URLs (0.0-1.0)')
    generate_parser.add_argument('--output', '-o', default='phishing_dataset.csv', help='Output CSV file')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return
    
    detector = PhishingDetector()
    
    if args.command == 'train':
        print(f"Training model using dataset: {args.dataset}")
        if not os.path.exists(args.dataset):
            print(f"Error: Dataset file not found: {args.dataset}")
            return
        
        success = detector.train(args.dataset)
        if success:
            print(f"Model trained successfully and saved to {args.output}")
        else:
            print("Failed to train model")
    
    elif args.command == 'check':
        if not os.path.exists(args.model):
            print(f"Error: Model file not found: {args.model}")
            return
        
        detector.load_model(args.model)
        url = args.url
        
        # Add http:// if not present
        if not url.startswith('http'):
            url = 'http://' + url
        
        print(f"Checking URL: {url}")
        
        # Extract features
        features = detector.extract_features(url)
        
        # Make prediction
        result = detector.predict(url)
        print(f"Result: {result}")
        
        # Show features if verbose
        if args.verbose:
            print("\nFeatures:")
            for feature, value in features.items():
                print(f"- {feature}: {value}")
    
    elif args.command == 'batch':
        if not os.path.exists(args.model):
            print(f"Error: Model file not found: {args.model}")
            return
        
        if not os.path.exists(args.input):
            print(f"Error: Input file not found: {args.input}")
            return
        
        detector.load_model(args.model)
        
        # Read URLs from file
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"Processing {len(urls)} URLs...")
        
        # Process each URL
        results = []
        for url in urls:
            # Add http:// if not present
            if not url.startswith('http'):
                url = 'http://' + url
            
            # Make prediction
            prediction = detector.predict(url)
            is_phishing = 'Phishing' in prediction
            confidence = float(prediction.split('Confidence: ')[1].strip(')'))
            
            results.append({
                'url': url,
                'is_phishing': is_phishing,
                'confidence': confidence
            })
        
        # Save results to CSV
        import pandas as pd
        df = pd.DataFrame(results)
        df.to_csv(args.output, index=False)
        
        print(f"Results saved to {args.output}")
        print(f"Summary: {df['is_phishing'].sum()} phishing, {len(df) - df['is_phishing'].sum()} legitimate")
    
    elif args.command == 'generate':
        try:
            from generate_dataset import generate_dataset
            
            print(f"Generating dataset with {args.samples} samples ({args.ratio * 100}% phishing)...")
            df = generate_dataset(num_samples=args.samples, phishing_ratio=args.ratio)
            
            # Save to CSV
            df.to_csv(args.output, index=False)
            print(f"Dataset saved to {args.output}")
            
        except Exception as e:
            print(f"Error generating dataset: {e}")

if __name__ == "__main__":
    main()