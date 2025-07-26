import pandas as pd
import numpy as np
import random
from urllib.parse import urlparse
import os

# List of common TLDs
tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.info', '.biz']

# List of common words for domain names
common_words = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'twitter', 'instagram',
    'linkedin', 'github', 'youtube', 'netflix', 'spotify', 'paypal', 'ebay',
    'walmart', 'target', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa',
    'mastercard', 'discover', 'account', 'login', 'signin', 'secure', 'update',
    'verify', 'confirm', 'password', 'user', 'profile', 'dashboard', 'admin'
]

# List of suspicious words often found in phishing URLs
suspicious_words = [
    'secure', 'account', 'banking', 'login', 'signin', 'verify', 'paypal',
    'password', 'update', 'confirm', 'verify', 'authenticate', 'wallet',
    'alert', 'notification', 'access', 'limited', 'suspended', 'unusual',
    'activity', 'security', 'important', 'urgent', 'official'
]

# URL shortening services
shortening_services = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'tr.im', 'is.gd', 'cli.gs', 'ow.ly'
]

def generate_legitimate_url():
    """Generate a legitimate URL"""
    protocol = random.choice(['http://', 'https://'])
    
    # 80% chance of using www
    www = 'www.' if random.random() < 0.8 else ''
    
    # Choose a common word for the domain
    domain = random.choice(common_words)
    
    # 10% chance of having a dash in domain
    if random.random() < 0.1:
        domain += '-' + random.choice(common_words)
    
    # 20% chance of having a subdomain
    if random.random() < 0.2:
        subdomain = random.choice(common_words)
        domain = f"{subdomain}.{domain}"
    
    # Choose a TLD
    tld = random.choice(tlds)
    
    # Generate path
    path = ''
    if random.random() < 0.7:  # 70% chance of having a path
        path_length = random.randint(1, 3)
        path_parts = [random.choice(common_words) for _ in range(path_length)]
        path = '/' + '/'.join(path_parts)
        
        # 30% chance of having a file extension
        if random.random() < 0.3:
            extensions = ['.html', '.php', '.aspx', '.jsp', '.do']
            path += random.choice(extensions)
    
    # Generate query parameters
    query = ''
    if random.random() < 0.4:  # 40% chance of having query parameters
        num_params = random.randint(1, 3)
        params = []
        for _ in range(num_params):
            param_name = random.choice(common_words)
            param_value = random.choice(common_words)
            params.append(f"{param_name}={param_value}")
        query = '?' + '&'.join(params)
    
    # Construct the URL
    url = f"{protocol}{www}{domain}{tld}{path}{query}"
    
    return url

def generate_phishing_url():
    """Generate a phishing URL"""
    protocol = random.choice(['http://', 'https://'])
    
    # Decide on the type of phishing URL to generate
    phishing_type = random.randint(1, 5)
    
    if phishing_type == 1:
        # Type 1: Misspelled domain of popular website
        target_domain = random.choice(common_words[:15])  # Choose from popular sites
        misspelling_type = random.randint(1, 3)
        
        if misspelling_type == 1:  # Character replacement
            char_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 'l': '1'}
            for char, replacement in char_map.items():
                if char in target_domain and random.random() < 0.3:
                    target_domain = target_domain.replace(char, replacement)
        
        elif misspelling_type == 2:  # Character insertion
            pos = random.randint(1, len(target_domain) - 1)
            char = random.choice('abcdefghijklmnopqrstuvwxyz')
            target_domain = target_domain[:pos] + char + target_domain[pos:]
        
        else:  # Character transposition
            if len(target_domain) > 3:
                pos = random.randint(1, len(target_domain) - 2)
                target_domain = target_domain[:pos] + target_domain[pos+1] + target_domain[pos] + target_domain[pos+2:]
        
        domain = target_domain
    
    elif phishing_type == 2:
        # Type 2: Suspicious subdomain
        real_domain = random.choice(common_words[:15])
        fake_domain = random.choice(common_words[15:]) + random.choice(['-secure', '-login', '-account'])
        domain = f"{real_domain}.{fake_domain}"
    
    elif phishing_type == 3:
        # Type 3: URL with suspicious words
        domain = random.choice(common_words)
        if random.random() < 0.5:
            domain += '-' + random.choice(suspicious_words)
    
    elif phishing_type == 4:
        # Type 4: IP address instead of domain
        ip_parts = [str(random.randint(1, 255)) for _ in range(4)]
        return f"{protocol}{'.'.join(ip_parts)}/login.php"
    
    else:
        # Type 5: URL shortening service with suspicious path
        service = random.choice(shortening_services)
        return f"{protocol}{service}/{random.choice('abcdefghijklmnopqrstuvwxyz0123456789')}"
    
    # Choose a TLD
    tld = random.choice(tlds)
    
    # Generate path with suspicious words
    path = ''
    if random.random() < 0.9:  # 90% chance of having a path for phishing URLs
        path_parts = [random.choice(suspicious_words)]
        if random.random() < 0.5:
            path_parts.append(random.choice(suspicious_words))
        path = '/' + '/'.join(path_parts)
        
        # 60% chance of having a file extension
        if random.random() < 0.6:
            extensions = ['.php', '.html', '.aspx', '.do']
            path += random.choice(extensions)
    
    # Generate query parameters with suspicious words
    query = ''
    if random.random() < 0.7:  # 70% chance of having query parameters
        num_params = random.randint(1, 3)
        params = []
        for _ in range(num_params):
            param_name = random.choice(suspicious_words)
            param_value = random.choice(['true', 'yes', '1', 'redirect'])
            params.append(f"{param_name}={param_value}")
        query = '?' + '&'.join(params)
    
    # Add @ symbol occasionally
    if random.random() < 0.2:
        username = random.choice(common_words)
        password = random.choice(common_words)
        domain = f"{username}:{password}@{domain}"
    
    # Construct the URL
    url = f"{protocol}{domain}{tld}{path}{query}"
    
    return url

def extract_features(url):
    """Extract features from a URL"""
    features = {}
    
    # URL length
    features['url_length'] = len(url)
    
    # Check for IP address in URL
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
    features['domain_registration_length'] = 1  # Placeholder
    
    # Check for suspicious words
    features['has_suspicious_words'] = 0
    for word in suspicious_words:
        if word in url.lower():
            features['has_suspicious_words'] = 1
            break
    
    # Check for URL shortening service
    features['url_shortening_service'] = 0
    for service in shortening_services:
        if service in url.lower():
            features['url_shortening_service'] = 1
            break
    
    return features

def generate_dataset(num_samples=2000, phishing_ratio=0.5):
    """Generate a synthetic dataset of URLs with features"""
    # Calculate number of each type
    num_phishing = int(num_samples * phishing_ratio)
    num_legitimate = num_samples - num_phishing
    
    # Generate URLs
    legitimate_urls = [generate_legitimate_url() for _ in range(num_legitimate)]
    phishing_urls = [generate_phishing_url() for _ in range(num_phishing)]
    
    # Create lists to store data
    urls = []
    features_list = []
    labels = []
    
    # Process legitimate URLs
    for url in legitimate_urls:
        urls.append(url)
        try:
            features = extract_features(url)
            features_list.append(features)
            labels.append(0)  # 0 = legitimate
        except Exception as e:
            print(f"Error processing URL {url}: {e}")
    
    # Process phishing URLs
    for url in phishing_urls:
        urls.append(url)
        try:
            features = extract_features(url)
            features_list.append(features)
            labels.append(1)  # 1 = phishing
        except Exception as e:
            print(f"Error processing URL {url}: {e}")
    
    # Create DataFrame
    df = pd.DataFrame(features_list)
    df['url'] = urls
    df['is_phishing'] = labels
    
    # Reorder columns
    cols = ['url', 'is_phishing'] + list(df.columns[:-2])
    df = df[cols]
    
    print(f"Generated dataset with {len(df)} URLs ({df['is_phishing'].sum()} phishing, {len(df) - df['is_phishing'].sum()} legitimate)")
    
    return df

# If run directly, generate a dataset and save it
if __name__ == "__main__":
    import re  # Import re here for extract_features
    
    print("Generating phishing URL dataset...")
    df = generate_dataset(num_samples=2000, phishing_ratio=0.5)
    
    # Save to CSV
    output_file = 'phishing_dataset.csv'
    df.to_csv(output_file, index=False)
    print(f"Dataset saved to {output_file}")