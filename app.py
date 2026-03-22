from flask import Flask, request, render_template
import pickle
import re
import requests
import dns.resolver
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

app = Flask(__name__)
model = pickle.load(open("model.pkl", "rb"))

COMMON_BRANDS = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal', 
                 'netflix', 'instagram', 'twitter', 'linkedin', 'yahoo', 'ebay']
SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
PHISH_HINTS = ['secure', 'account', 'login', 'verify', 'update', 'banking', 
               'confirm', 'password', 'credential', 'signin', 'payment']

def get_page(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        return BeautifulSoup(r.text, 'html.parser'), r
    except:
        return None, None

def word_stats(text):
    words = re.split(r'[.\-_/=?@&]', text)
    words = [w for w in words if w]
    if not words:
        return 0, 0, 0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths)/len(lengths)

def extract_features(url):
    features = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    scheme = parsed.scheme or ""
    
    soup, response = get_page(url)
    
    try:
        w = whois.whois(hostname)
    except:
        w = None

    # 1. length_url
    features.append(len(url))
    
    # 2. length_hostname
    features.append(len(hostname))
    
    # 3. ip
    features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0)
    
    # 4. nb_dots
    features.append(url.count('.'))
    
    # 5. nb_hyphens
    features.append(url.count('-'))
    
    # 6. nb_at
    features.append(url.count('@'))
    
    # 7. nb_qm
    features.append(url.count('?'))
    
    # 8. nb_and
    features.append(url.count('&'))
    
    # 9. nb_or
    features.append(url.count('|'))
    
    # 10. nb_eq
    features.append(url.count('='))
    
    # 11. nb_underscore
    features.append(url.count('_'))
    
    # 12. nb_tilde
    features.append(url.count('~'))
    
    # 13. nb_percent
    features.append(url.count('%'))
    
    # 14. nb_slash
    features.append(url.count('/'))
    
    # 15. nb_star
    features.append(url.count('*'))
    
    # 16. nb_colon
    features.append(url.count(':'))
    
    # 17. nb_comma
    features.append(url.count(','))
    
    # 18. nb_semicolumn
    features.append(url.count(';'))
    
    # 19. nb_dollar
    features.append(url.count('$'))
    
    # 20. nb_space
    features.append(url.count(' '))
    
    # 21. nb_www
    features.append(url.count('www'))
    
    # 22. nb_com
    features.append(url.count('.com'))
    
    # 23. nb_dslash
    features.append(url.count('//'))
    
    # 24. http_in_path
    features.append(1 if 'http' in path else 0)
    
    # 25. https_token
    features.append(1 if scheme == 'https' else 0)
    
    # 26. ratio_digits_url
    digits = sum(c.isdigit() for c in url)
    features.append(digits / len(url) if len(url) > 0 else 0)
    
    # 27. ratio_digits_host
    digits_host = sum(c.isdigit() for c in hostname)
    features.append(digits_host / len(hostname) if len(hostname) > 0 else 0)
    
    # 28. punycode
    features.append(1 if 'xn--' in hostname else 0)
    
    # 29. port
    features.append(1 if parsed.port else 0)
    
    # 30. tld_in_path
    common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
    features.append(1 if any(t in path for t in common_tlds) else 0)
    
    # 31. tld_in_subdomain
    parts = hostname.split('.')
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    features.append(1 if any(t.strip('.') in subdomain for t in common_tlds) else 0)
    
    # 32. abnormal_subdomain
    features.append(1 if re.search(r'(w[0-9]|web[0-9])', subdomain) else 0)
    
    # 33. nb_subdomains
    features.append(max(0, len(parts) - 2))
    
    # 34. prefix_suffix
    features.append(1 if '-' in hostname else 0)
    
    # 35. random_domain
    consonants = sum(1 for c in hostname if c in 'bcdfghjklmnpqrstvwxyz')
    features.append(1 if len(hostname) > 0 and consonants/len(hostname) > 0.6 else 0)
    
    # 36. shortening_service
    features.append(1 if any(s in url for s in SHORTENERS) else 0)
    
    # 37. path_extension
    extensions = ['.php', '.html', '.asp', '.jsp', '.cgi', '.exe']
    features.append(1 if any(ext in path for ext in extensions) else 0)
    
    # 38. nb_redirection
    try:
        r2 = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        features.append(len(r2.history))
    except:
        features.append(0)
    
    # 39. nb_external_redirection
    try:
        external = sum(1 for r3 in r2.history if urlparse(r3.headers.get('Location','')).hostname != hostname)
        features.append(external)
    except:
        features.append(0)
    
    # Word-based features
    all_words = re.split(r'[.\-_/=?@&]', url)
    all_words = [w for w in all_words if w]
    host_words = re.split(r'[.\-_]', hostname)
    host_words = [w for w in host_words if w]
    path_words = re.split(r'[/\-_=?&]', path)
    path_words = [w for w in path_words if w]
    
    # 40. length_words_raw
    features.append(len(all_words))
    
    # 41. char_repeat
    features.append(max([url.count(c) for c in set(url)]) if url else 0)
    
    # 42. shortest_words_raw
    features.append(min([len(w) for w in all_words]) if all_words else 0)
    
    # 43. shortest_word_host
    features.append(min([len(w) for w in host_words]) if host_words else 0)
    
    # 44. shortest_word_path
    features.append(min([len(w) for w in path_words]) if path_words else 0)
    
    # 45. longest_words_raw
    features.append(max([len(w) for w in all_words]) if all_words else 0)
    
    # 46. longest_word_host
    features.append(max([len(w) for w in host_words]) if host_words else 0)
    
    # 47. longest_word_path
    features.append(max([len(w) for w in path_words]) if path_words else 0)
    
    # 48. avg_words_raw
    features.append(sum(len(w) for w in all_words)/len(all_words) if all_words else 0)
    
    # 49. avg_word_host
    features.append(sum(len(w) for w in host_words)/len(host_words) if host_words else 0)
    
    # 50. avg_word_path
    features.append(sum(len(w) for w in path_words)/len(path_words) if path_words else 0)
    
    # 51. phish_hints
    features.append(sum(1 for h in PHISH_HINTS if h in url.lower()))
    
    # 52. domain_in_brand
    features.append(1 if any(b in hostname for b in COMMON_BRANDS) else 0)
    
    # 53. brand_in_subdomain
    features.append(1 if any(b in subdomain for b in COMMON_BRANDS) else 0)
    
    # 54. brand_in_path
    features.append(1 if any(b in path for b in COMMON_BRANDS) else 0)
    
    # 55. suspecious_tld
    features.append(1 if any(url.endswith(t) for t in SUSPICIOUS_TLDS) else 0)
    
    # 56. statistical_report
    features.append(0)  # requires external blacklist API

    # Page-based features (need soup)
    if soup:
        all_links = soup.find_all('a', href=True)
        total_links = len(all_links)
        
        int_links = [a for a in all_links if hostname in a['href']]
        ext_links = [a for a in all_links if hostname not in a['href'] and a['href'].startswith('http')]
        null_links = [a for a in all_links if a['href'] in ['#', '', 'javascript:void(0)']]

        # 57. nb_hyperlinks
        features.append(total_links)
        
        # 58. ratio_intHyperlinks
        features.append(len(int_links)/total_links if total_links > 0 else 0)
        
        # 59. ratio_extHyperlinks
        features.append(len(ext_links)/total_links if total_links > 0 else 0)
        
        # 60. ratio_nullHyperlinks
        features.append(len(null_links)/total_links if total_links > 0 else 0)
        
        # 61. nb_extCSS
        css_links = soup.find_all('link', rel='stylesheet')
        ext_css = [c for c in css_links if c.get('href','').startswith('http') and hostname not in c.get('href','')]
        features.append(len(ext_css))
        
        # 62. ratio_intRedirection
        features.append(len(int_links)/total_links if total_links > 0 else 0)
        
        # 63. ratio_extRedirection
        features.append(len(ext_links)/total_links if total_links > 0 else 0)
        
        # 64. ratio_intErrors
        broken_int = sum(1 for a in int_links if not a.get('href'))
        features.append(broken_int/total_links if total_links > 0 else 0)
        
        # 65. ratio_extErrors
        broken_ext = sum(1 for a in ext_links if not a.get('href'))
        features.append(broken_ext/total_links if total_links > 0 else 0)
        
        # 66. login_form
        forms = soup.find_all('form')
        login = any('login' in str(f).lower() or 'password' in str(f).lower() for f in forms)
        features.append(1 if login else 0)
        
        # 67. external_favicon
        favicon = soup.find('link', rel=re.compile('icon', re.I))
        ext_fav = 1 if favicon and favicon.get('href','').startswith('http') and hostname not in favicon.get('href','') else 0
        features.append(ext_fav)
        
        # 68. links_in_tags
        meta_links = soup.find_all(['meta', 'script', 'link'])
        features.append(len(meta_links))
        
        # 69. submit_email
        features.append(1 if 'mailto:' in str(soup) else 0)
        
        # 70. ratio_intMedia
        media = soup.find_all(['img', 'video', 'audio'])
        int_media = [m for m in media if hostname in m.get('src','')]
        features.append(len(int_media)/len(media) if media else 0)
        
        # 71. ratio_extMedia
        ext_media = [m for m in media if m.get('src','').startswith('http') and hostname not in m.get('src','')]
        features.append(len(ext_media)/len(media) if media else 0)
        
        # 72. sfh (suspicious form handler)
        sfh = any(f.get('action','') in ['', '#', 'about:blank'] for f in forms)
        features.append(1 if sfh else 0)
        
        # 73. iframe
        features.append(1 if soup.find('iframe') else 0)
        
        # 74. popup_window
        features.append(1 if 'window.open' in str(soup) else 0)
        
        # 75. safe_anchor
        unsafe = sum(1 for a in all_links if a.get('href','') in ['#', 'javascript:void(0)'])
        features.append(unsafe/total_links if total_links > 0 else 0)
        
        # 76. onmouseover
        features.append(1 if 'onmouseover' in str(soup) else 0)
        
        # 77. right_clic
        features.append(1 if 'contextmenu' in str(soup) or 'right_click' in str(soup) else 0)
        
        # 78. empty_title
        title = soup.find('title')
        features.append(1 if not title or not title.text.strip() else 0)
        
        # 79. domain_in_title
        features.append(1 if title and hostname.split('.')[0] in title.text.lower() else 0)
        
        # 80. domain_with_copyright
        features.append(1 if hostname.split('.')[0] in str(soup).lower() and '©' in str(soup) else 0)
    
    else:
        # page not reachable — fill with 0s
        features.extend([0] * 24)

    # WHOIS features
    # 81. whois_registered_domain
    features.append(1 if w else 0)
    
    # 82. domain_registration_length
    try:
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        reg = w.creation_date
        if isinstance(reg, list): reg = reg[0]
        features.append((exp - reg).days if exp and reg else 0)
    except:
        features.append(0)
    
    # 83. domain_age
    try:
        reg = w.creation_date
        if isinstance(reg, list): reg = reg[0]
        features.append((datetime.now() - reg).days if reg else 0)
    except:
        features.append(0)
    
    # 84. web_traffic (approximation using response time)
    try:
        features.append(1 if response and response.elapsed.total_seconds() < 2 else 0)
    except:
        features.append(0)
    
    # 85. dns_record
    try:
        dns.resolver.resolve(hostname, 'A')
        features.append(1)
    except:
        features.append(0)
    
    # 86. google_index
    try:
        r_google = requests.get(f"https://www.google.com/search?q=site:{hostname}", timeout=5)
        features.append(0 if 'did not match any documents' in r_google.text else 1)
    except:
        features.append(0)
    
    # 87. page_rank (approximation)
    try:
        features.append(1 if response and response.status_code == 200 else 0)
    except:
        features.append(0)

    return features

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        features = extract_features(url)
        import pandas as pd
        import numpy as np
        feature_names = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
            'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
            'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
            'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
            'nb_subdomains', 'prefix_suffix', 'random_domain',
            'shortening_service', 'path_extension', 'nb_redirection',
            'nb_external_redirection', 'length_words_raw', 'char_repeat',
            'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
            'longest_words_raw', 'longest_word_host', 'longest_word_path',
            'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
            'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
            'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
            'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
            'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
            'ratio_intErrors', 'ratio_extErrors', 'login_form',
            'external_favicon', 'links_in_tags', 'submit_email',
            'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
            'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
            'empty_title', 'domain_in_title', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length',
            'domain_age', 'web_traffic', 'dns_record', 'google_index',
            'page_rank'
        ]
        df_input = pd.DataFrame([features], columns=feature_names)
        prediction = model.predict(df_input)[0]
        result = "🚨 PHISHING" if prediction == 1 else "✅ LEGITIMATE"
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)