from flask import Flask, request, jsonify
import asyncio, json, binascii, requests, aiohttp, urllib3, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO, URLS_LIKE, FILES
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

def load_tokens(server):
    files = FILES
    return json.load(open(f"tokens/{files.get(server,'token_bd.json')}"))

def get_headers(token):
    return {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51",
        }

def encrypt_message(data):
    cipher = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return binascii.hexlify(cipher.encrypt(pad(data, AES.block_size))).decode()

def create_like(uid, region):
    m = like_pb2.like(); m.uid, m.region = int(uid), region
    return m.SerializeToString()

def create_uid(uid):
    m = uid_generator_pb2.uid_generator(); m.saturn_, m.garena = int(uid), 1
    return m.SerializeToString()

async def send(token, url, data):
    headers = get_headers(token)
    async with aiohttp.ClientSession() as s:
        async with s.post(url, data=bytes.fromhex(data), headers=headers) as r:
            text = await r.text()
            if r.status == 200:
                return text  # Success (usually empty or "OK")
            else:
                print(f"Error {r.status} for token {token[:20]}...: {text}")  # Log error
                return None

def get_info(enc, server, token):
    urls = URLS_INFO
    r = requests.post(urls.get(server,"https://clientbp.ggblueshark.com/GetPlayerPersonalShow"),
                      data=bytes.fromhex(enc), headers=get_headers(token), verify=False)
    try: 
        p = like_count_pb2.Info(); 
        p.ParseFromString(r.content); 
        return p
    except DecodeError: 
        return None

async def multi(uid, server, url, max_attempts=100, batch_size=20):
    enc = encrypt_message(create_like(uid, server))
    tokens = load_tokens(server)
    if not tokens:
        return 0
    added = 0
    for i in range(0, max_attempts, batch_size):
        if added >= max_attempts:
            break
        batch_tokens = [tokens[j % len(tokens)]['token'] for j in range(i, min(i + batch_size, max_attempts))]
        batch_results = await asyncio.gather(*[send(t, url, enc) for t in batch_tokens])
        successes = sum(1 for res in batch_results if res is not None)
        added += successes
        time.sleep(1)  # Throttle to avoid rate limits
    return added

@app.route("/like")
def like():
    uid, server = request.args.get("uid"), request.args.get("server","").upper()
    if not uid or not server: 
        return jsonify(error="UID and server required"),400
    tokens = load_tokens(server)
    if not tokens: 
        return jsonify(error="No tokens available"),500
    enc_uid = encrypt_message(create_uid(uid))

    # Get initial count
    before, tok = None, None
    for t in tokens[:10]:
        before = get_info(enc_uid, server, t["token"])
        if before: 
            tok = t["token"]; 
            break
    if not before: 
        return jsonify(error="Player not found"),500
    before_like = int(json.loads(MessageToJson(before)).get('AccountInfo',{}).get('Likes',0))
    
    # Estimate remaining slots (daily reset is 100)
    remaining = 100 - (before_like % 100)
    if remaining == 100:
        remaining = 100  # Full day available

    urls = URLS_LIKE
    like_url = urls.get(server,"https://clientbp.ggblueshark.com/LikeProfile")
    asyncio.run(multi(uid, server, like_url, remaining))
    
    # Get after count
    after_proto = get_info(enc_uid, server, tok)
    if not after_proto:
        return jsonify(error="Failed to fetch after info"),500
    after = json.loads(MessageToJson(after_proto))
    after_like = int(after.get('AccountInfo',{}).get('Likes',0))
    actual_added = after_like - before_like

    return jsonify({
        "credits":"great.thug4ff.com",
        "likes_added": actual_added,
        "likes_before": before_like,
        "likes_after": after_like,
        "player": after.get('AccountInfo',{}).get('PlayerNickname',''),
        "uid": after.get('AccountInfo',{}).get('UID',0),
        "status": 1 if actual_added > 0 else 2,
        "note": f"Max 100 new likes/day per UID. Attempted up to {remaining}, added {actual_added}."
    })

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
