document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const resultSection = document.getElementById('result-section');
    const resultCard = document.getElementById('result-card');
    const resultStatus = document.getElementById('result-status');
    const urlDisplay = document.getElementById('url-display');
    const confidenceBar = document.getElementById('confidence-bar');
    const confidenceValue = document.getElementById('confidence-value');
    const featuresTable = document.getElementById('features-table').querySelector('tbody');
    const closeResult = document.getElementById('close-result');

    // Feature descriptions for tooltips
    const featureDescriptions = {
        'url_length': 'Total length of the URL. Longer URLs are sometimes associated with phishing attempts.',
        'has_ip_address': 'Whether the URL contains an IP address instead of a domain name.',
        'has_at_symbol': 'Presence of @ symbol in the URL, which can be used to hide the actual destination.',
        'has_double_slash_redirect': 'Presence of // in the path, which might indicate a redirect.',
        'has_dash_in_domain': 'Whether the domain contains dashes, which are sometimes used in phishing domains.',
        'has_multiple_subdomains': 'Excessive number of subdomains, which can be suspicious.',
        'uses_https': 'Whether the URL uses HTTPS protocol, which is generally more secure.',
        'domain_registration_length': 'How long the domain has been registered. Newer domains might be more suspicious.',
        'has_suspicious_words': 'Presence of words commonly found in phishing URLs.',
        'url_shortening_service': 'Whether a URL shortening service is used, which can hide the actual destination.'
    };

    // Risk levels for features
    const featureRiskLevels = {
        'url_length': (value) => value > 75 ? 'high' : value > 50 ? 'medium' : 'low',
        'has_ip_address': (value) => value === 1 ? 'high' : 'low',
        'has_at_symbol': (value) => value === 1 ? 'high' : 'low',
        'has_double_slash_redirect': (value) => value === 1 ? 'high' : 'low',
        'has_dash_in_domain': (value) => value === 1 ? 'medium' : 'low',
        'has_multiple_subdomains': (value) => value === 1 ? 'medium' : 'low',
        'uses_https': (value) => value === 0 ? 'medium' : 'low',
        'domain_registration_length': (value) => value === 0 ? 'medium' : 'low',
        'has_suspicious_words': (value) => value === 1 ? 'high' : 'low',
        'url_shortening_service': (value) => value === 1 ? 'high' : 'low'
    };

    // Handle form submission
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const url = urlInput.value.trim();
        
        if (url) {
            checkUrl(url);
        }
    });

    // Close result card
    closeResult.addEventListener('click', function() {
        resultSection.classList.remove('active');
    });

    // Function to check URL
    async function checkUrl(url) {
        // Show loading state
        resultStatus.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing URL...';
        resultStatus.className = 'result-status';
        urlDisplay.textContent = url;
        confidenceBar.style.width = '0%';
        confidenceValue.textContent = '0%';
        featuresTable.innerHTML = '';
        resultSection.classList.add('active');

        try {
            // Make API call to backend
            const response = await fetch('/api/check_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            displayResult(data);
        } catch (error) {
            console.error('Error:', error);
            resultStatus.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error analyzing URL. Please try again.';
            resultStatus.className = 'result-status danger';
        }
    }

    // Function to display result
    function displayResult(data) {
        // For demo purposes, we'll simulate a response
        // In a real implementation, this would use the actual API response
        
        // Simulate API response if needed
        if (!data) {
            // This is just for testing when no backend is available
            const isPhishing = Math.random() > 0.5;
            const confidence = Math.floor(Math.random() * 30) + 70;
            
            data = {
                prediction: isPhishing ? 'Phishing URL' : 'Legitimate URL',
                confidence: isPhishing ? confidence / 100 : confidence / 100,
                features: {
                    url_length: urlInput.value.length,
                    has_ip_address: Math.random() > 0.8 ? 1 : 0,
                    has_at_symbol: urlInput.value.includes('@') ? 1 : 0,
                    has_double_slash_redirect: urlInput.value.includes('//') ? 1 : 0,
                    has_dash_in_domain: Math.random() > 0.7 ? 1 : 0,
                    has_multiple_subdomains: Math.random() > 0.6 ? 1 : 0,
                    uses_https: urlInput.value.startsWith('https') ? 1 : 0,
                    domain_registration_length: Math.random() > 0.5 ? 1 : 0,
                    has_suspicious_words: Math.random() > 0.7 ? 1 : 0,
                    url_shortening_service: Math.random() > 0.9 ? 1 : 0
                }
            };
        }

        // Update result status
        const isPhishing = data.prediction.includes('Phishing');
        resultStatus.innerHTML = isPhishing ? 
            '<i class="fas fa-exclamation-triangle"></i> Potential Phishing URL Detected!' : 
            '<i class="fas fa-check-circle"></i> Legitimate URL';
        resultStatus.className = isPhishing ? 'result-status danger' : 'result-status safe';

        // Update confidence meter
        const confidencePercent = Math.round(data.confidence * 100);
        confidenceBar.style.width = `${confidencePercent}%`;
        confidenceBar.className = isPhishing ? 'meter-bar danger' : 'meter-bar safe';
        confidenceValue.textContent = `${confidencePercent}%`;

        // Update features table
        featuresTable.innerHTML = '';
        for (const [feature, value] of Object.entries(data.features)) {
            const row = document.createElement('tr');
            
            // Feature name cell
            const featureCell = document.createElement('td');
            const featureName = feature.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            featureCell.textContent = featureName;
            featureCell.title = featureDescriptions[feature] || '';
            row.appendChild(featureCell);
            
            // Value cell
            const valueCell = document.createElement('td');
            valueCell.textContent = feature === 'url_length' ? value : value === 1 ? 'Yes' : 'No';
            row.appendChild(valueCell);
            
            // Risk level cell
            const riskCell = document.createElement('td');
            const riskLevel = featureRiskLevels[feature] ? featureRiskLevels[feature](value) : 'low';
            riskCell.textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
            riskCell.className = `risk-${riskLevel}`;
            row.appendChild(riskCell);
            
            featuresTable.appendChild(row);
        }
    }

    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 100,
                    behavior: 'smooth'
                });
            }
        });
    });
});