from flask import Flask, request, jsonify
import asyncio, json, binascii, requests, aiohttp, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO ,URLS_LIKE,FILES
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def load_tokens(server):
    files = FILES
    try:
        return json.load(open(f"tokens/{files.get(server,'token_bd.json')}", 'r'))
    except FileNotFoundError:
        # Fallback to IND tokens if server-specific file doesn't exist
        return json.load(open("tokens/token_ind.json", 'r'))

def get_headers(token):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51",
    }

def encrypt_message(data):
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return binascii.hexlify(encrypted).decode()

def decrypt_message(data):
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    decrypted = cipher.decrypt(binascii.unhexlify(data))
    return unpad(decrypted, AES.block_size)

def create_like(uid, region):
    m = like_pb2.like()
    m.uid = int(uid)
    m.region = region
    return m.SerializeToString()

def create_uid(uid):
    m = uid_generator_pb2.uid_generator()
    m.saturn_ = int(uid)
    m.garena = 1
    return m.SerializeToString()

async def send_like(token, url, data):
    headers = get_headers(token)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(data), headers=headers, timeout=10) as response:
                if response.status == 200:
                    return await response.read()
                else:
                    return None
    except Exception as e:
        print(f"Error sending like: {e}")
        return None

async def send_likes_concurrently(uid, server, url, token_batch):
    enc = encrypt_message(create_like(uid, server))
    tasks = []
    for token in token_batch:
        tasks.append(send_like(token['token'], url, enc))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results

def get_player_info(uid, server, token):
    """Get player information with proper error handling"""
    try:
        urls = URLS_INFO
        url = urls.get(server, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        
        # Create and encrypt the UID request
        uid_data = create_uid(uid)
        enc_data = encrypt_message(uid_data)
        
        headers = get_headers(token)
        
        # Make the request with timeout
        response = requests.post(
            url, 
            data=bytes.fromhex(enc_data), 
            headers=headers, 
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            try:
                # Decrypt the response first
                decrypted = decrypt_message(response.content.hex())
                
                # Try to parse with like_count_pb2
                info = like_count_pb2.Info()
                info.ParseFromString(decrypted)
                return info
            except (DecodeError, ValueError, binascii.Error) as e:
                print(f"Decryption/parsing error: {e}")
                # Try direct parsing without decryption (some endpoints might not encrypt)
                try:
                    info = like_count_pb2.Info()
                    info.ParseFromString(response.content)
                    return info
                except DecodeError:
                    return None
        else:
            print(f"API request failed with status: {response.status_code}")
            return None
            
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

@app.route("/like", methods=["GET"])
def like():
    uid = request.args.get("uid")
    server = request.args.get("server", "").upper()
    
    if not uid:
        return jsonify({"error": "UID is required"}), 400
    if not server:
        return jsonify({"error": "Server is required (IND, BR, US, SAC, NA)"}), 400
    
    try:
        # Validate UID is numeric
        uid_int = int(uid)
    except ValueError:
        return jsonify({"error": "UID must be a valid number"}), 400
    
    # Load tokens for the server
    try:
        tokens = load_tokens(server)
        if not tokens:
            return jsonify({"error": f"No tokens found for server: {server}"}), 500
    except Exception as e:
        return jsonify({"error": f"Failed to load tokens: {str(e)}"}), 500
    
    # Get initial likes count
    before_info = None
    valid_token = None
    
    # Try multiple tokens to find one that works
    for token_data in tokens[:5]:  # Try first 5 tokens
        before_info = get_player_info(uid, server, token_data["token"])
        if before_info:
            valid_token = token_data["token"]
            break
    
    if not before_info:
        return jsonify({
            "error": "Player not found or tokens expired",
            "message": "The UID might be invalid, or all tokens for this server are expired."
        }), 404
    
    # Get initial likes count
    try:
        before_json = json.loads(MessageToJson(before_info))
        before_likes = int(before_json.get('AccountInfo', {}).get('Likes', 0))
        player_name = before_json.get('AccountInfo', {}).get('PlayerNickname', 'Unknown')
    except (KeyError, ValueError, AttributeError) as e:
        print(f"Error parsing initial data: {e}")
        before_likes = 0
        player_name = "Unknown"
    
    # Send likes concurrently (limit to reasonable number to avoid rate limiting)
    urls = URLS_LIKE
    url = urls.get(server, "https://clientbp.ggblueshark.com/LikeProfile")
    
    # Use a smaller batch size for testing
    like_batch_size = 50
    token_batch = tokens[:like_batch_size] if len(tokens) > like_batch_size else tokens
    
    try:
        # Run the async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            send_likes_concurrently(uid, server, url, token_batch)
        )
        loop.close()
        
        # Count successful likes
        successful_likes = sum(1 for result in results if result is not None)
        
        # Get updated likes count
        after_info = get_player_info(uid, server, valid_token) if valid_token else None
        
        if after_info:
            try:
                after_json = json.loads(MessageToJson(after_info))
                after_likes = int(after_json.get('AccountInfo', {}).get('Likes', 0))
            except (KeyError, ValueError, AttributeError):
                after_likes = before_likes
        else:
            after_likes = before_likes
        
        likes_added = after_likes - before_likes
        
        return jsonify({
            "credits": "great.thug4ff.com",
            "likes_added": likes_added,
            "likes_before": before_likes,
            "likes_after": after_likes,
            "player": player_name,
            "uid": uid,
            "server": server,
            "successful_requests": successful_likes,
            "status": 1 if likes_added > 0 else 2,
            "message": f"Successfully sent {successful_likes} like requests"
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Failed to send likes: {str(e)}",
            "credits": "great.thug4ff.com",
            "uid": uid,
            "server": server
        }), 500

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "Free Fire Like API",
        "usage": "/like?uid=YOUR_UID&server=SERVER_CODE",
        "available_servers": ["IND", "BR", "US", "SAC", "NA"],
        "credits": "great.thug4ff.com"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
