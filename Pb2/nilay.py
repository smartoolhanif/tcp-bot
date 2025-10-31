import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import random
import asyncio

REGION = "IND" 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# VariabLes dyli 
#------------------------------------------#
online_writer = None
whisper_writer = None
Spy = False
Chat_Leave = False
loop_task = None
loop_active = False
evoloop_task = None
evoloop_active = False
#------------------------------------------#

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "FF0000", "00FF00", "0000FF", "FFFF00", "FF00FF", "00FFFF", "FFFFFF", "FFA500",
        "A52A2A", "800080", "808080", "C0C0C0", "FFC0CB", "FFD700", "ADD8E6",
        "90EE90", "D2691E", "DC143C", "00CED1", "9400D3", "F08080", "20B2AA", "FF1493",
        "7CFC00", "B22222", "FF4500", "DAA520", "00BFFF", "00FF7F", "4682B4", "6495ED",
        "5F9EA0", "DDA0DD", "E6E6FA", "B0C4DE", "556B2F", "8FBC8F", "2E8B57", "3CB371",
        "6B8E23", "808000", "B8860B", "CD5C5C", "8B0000", "FF6347", "FF8C00", "BDB76B",
        "9932CC", "8A2BE2", "4B0082", "6A5ACD", "7B68EE", "4169E1", "1E90FF", "191970"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.114.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

def get_major_login_url(region):
    if region.upper() == "ME":
        return "https://loginbp.common.ggbluefox.com/MajorLogin"
    else:
        return "https://loginbp.ggblueshark.com/MajorLogin"

async def MajorLogin(payload, region):
    url = get_major_login_url(region)
    login_headers = Hr.copy()
    login_headers["Host"] = url.split('/')[2]
    
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=login_headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            print(f"MajorLogin Failed! Status: {response.status}, Response: {await response.text()}")
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: 
        whisper_writer.write(PacKeT) 
        await whisper_writer.drain()
    elif TypE == 'OnLine' and OnLinE: 
        online_writer.write(PacKeT) 
        await online_writer.drain()
    else: 
        if TypE == 'OnLine' and not OnLinE:
            print("Error: online_writer is not available.")
        return 'Unsupported Type or Writer not available!' 

# ==================== FUNCTIONS TO READ FROM FILES ====================
def read_ids_from_file(filename, default_content):
    """A generic function to read IDs from a file."""
    try:
        with open(filename, "r") as f:
            lines = f.readlines()
        return [int(line.strip()) for line in lines if line.strip()]
    except FileNotFoundError:
        with open(filename, "w") as f:
            f.write(default_content)
        print(f"[WARNING] {filename} not found. A default one has been created.")
        return read_ids_from_file(filename, default_content)
    except (ValueError, IndexError):
        return []

def get_emote_from_file(line_number):
    ids = read_ids_from_file("emote.txt", "5000234\n5000109\n")
    return ids[line_number - 1] if 0 < line_number <= len(ids) else None

def get_evo_from_file(line_number):
    ids = read_ids_from_file("evo.txt", "5000234\n5000109\n")
    return ids[line_number - 1] if 0 < line_number <= len(ids) else None

def get_random_loop_item():
    ids = read_ids_from_file("loop.txt", "5000234\n1010360\n5000109\n")
    return random.choice(ids) if ids else None

def get_random_evoloop_item():
    ids = read_ids_from_file("evoloop.txt", "5000234\n1010360\n5000109\n")
    return random.choice(ids) if ids else None    

def parse_space_uids(msg_parts):
    """Parse space-separated UIDs from message parts - last element is emote_id/team_code"""
    try:
        # All parts except the last one are UIDs
        uids = []
        for part in msg_parts[1:-1]:
            try:
                uids.append(int(part))
            except ValueError:
                continue
        return uids
    except Exception as e:
        print(f"Error parsing UIDs: {e}")
        return []

def get_last_param(msg_parts):
    """Get the last parameter (emote_id or team_code)"""
    return msg_parts[-1] if msg_parts else None
# =====================================================================

# ==================== BACKGROUND TASK FUNCTIONS ====================
async def loop_function(uid, chat_id, target_uids, team_code, key, iv):
    """The main function for the /loop command with TERGET ID"""
    global loop_active, online_writer, whisper_writer
    try:
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
        await asyncio.sleep(1)

        message = f"[B][C][00FF00]Loop started on {len(target_uids)} UIDs. Use /stop to end."
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

        while loop_active:
            item_id = get_random_loop_item()
            if item_id:
                for target_uid in target_uids:
                    if not loop_active:  # Check if loop is still active
                        break
                    emote_packet = await Emote_k(target_uid, item_id, key, iv)
                    await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
                    await asyncio.sleep(0.5)  # Small delay between emotes
            await asyncio.sleep(3)  # Delay between cycles

    except asyncio.CancelledError:
        print("Loop cancelled.")
    except Exception as e:
        print(f"Error in loop function: {e}")
    finally:
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
        print("Loop finished, left squad.")
        
async def evoloop_function(uid, chat_id, target_uids, team_code, key, iv):
    """The main function for the /evoloop command with TERGET ID"""
    global evoloop_active, online_writer, whisper_writer
    try:
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
        await asyncio.sleep(1)

        message = f"[B][C][00FF00]Evolution loop started on {len(target_uids)} UIDs. Use /stop to end."
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

        while evoloop_active:
            item_id = get_random_evoloop_item()
            if item_id:
                for target_uid in target_uids:
                    if not evoloop_active:  # Check if loop is still active
                        break
                    emote_packet = await Emote_k(target_uid, item_id, key, iv)
                    await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
                    await asyncio.sleep(0.5)  # Small delay between emotes
            await asyncio.sleep(3)  # Delay between cycles

    except asyncio.CancelledError:
        print("Evolution loop cancelled.")
    except Exception as e:
        print(f"Error in evoloop function: {e}")
    finally:
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
        print("Evolution loop finished, left squad.")

async def fun_function(uid, chat_id, target_uids, emote_id, key, iv):
    """Function for /fun command - spams emote 200 times on TERGET ID"""
    try:
        message = f"[B][C][00FF00]Fun spam started with emote {emote_id} on {len(target_uids)} UIDs"
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
        
        for i in range(200):
            for target_uid in target_uids:
                emote_packet = await Emote_k(target_uid, emote_id, key, iv)
                await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
                await asyncio.sleep(0.05)  # Small delay to avoid flooding
            
        completion_message = f"[B][C][00FF00]Fun spam completed on {len(target_uids)} UIDs!"
        P_done = await SEndMsG(2, completion_message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P_done)
        
    except Exception as e:
        print(f"Error in fun function: {e}")

async def proxy_private_function(uid, chat_id, team_code, uids, emote_id, key, iv):
    """Function for /proxy command in private - joins, emotes, leaves"""
    try:
        # Join squad
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
        await asyncio.sleep(0.3)
        
        # Emote on all UIDs
        for target_uid in uids:
            emote_packet = await Emote_k(target_uid, emote_id, key, iv)
            await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
            await asyncio.sleep(0.3)
        
        # Leave squad
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
        
        message = f"[B][C][00FF00]Proxy completed on {len(uids)} UIDs"
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
        
    except Exception as e:
        print(f"Error in proxy private function: {e}")

async def emote_multiple_function(uid, chat_id, target_uids, team_code, emote_id, key, iv):
    """Function to handle emote commands with TERGET ID"""
    try:
        # Join squad
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
        await asyncio.sleep(0.3)
        
        # Emote on all UIDs
        for target_uid in target_uids:
            emote_packet = await Emote_k(target_uid, emote_id, key, iv)
            await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
            await asyncio.sleep(0.3)
        
        # Leave squad
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
        
        message = f"[B][C][00FF00]Emote {emote_id} used on {len(target_uids)} UIDs"
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
        
    except Exception as e:
        print(f"Error in emote multiple function: {e}")

async def evo_multiple_function(uid, chat_id, target_uids, team_code, evo_id, key, iv):
    """Function to handle evo commands with TERGET ID"""
    try:
        # Join squad
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
        await asyncio.sleep(0.3)
        
        # Emote on all UIDs
        for target_uid in target_uids:
            emote_packet = await Emote_k(target_uid, evo_id, key, iv)
            await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
            await asyncio.sleep(0.3)
        
        # Leave squad
        leave_packet = await ExiT(None, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
        
        message = f"[B][C][00FF00]Evo item {evo_id} used on {len(target_uids)} UIDs"
        P = await SEndMsG(2, message, uid, chat_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
        
    except Exception as e:
        print(f"Error in evo multiple function: {e}")

async def proxy_squad_function(uid, chat_id, target_uids, emote_id, key, iv):
    """Function for /proxy command in squad - emotes on TERGET ID without joining/leaving"""
    try:
        message = f'[B][C]{get_random_color()}\nPROXY START EMOTE {emote_id} on {len(target_uids)} UIDs\n'
        P = await SEndMsG(0, message, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

        # Emote on all UIDs
        for target_uid in target_uids:
            emote_packet = await Emote_k(target_uid, emote_id, key, iv)
            await SEndPacKeT(online_writer, whisper_writer, 'OnLine', emote_packet)
            await asyncio.sleep(0.2)  # Small delay between emotes
        
        completion_message = f"[B][C][00FF00]Proxy completed on {len(target_uids)} UIDs"
        P_done = await SEndMsG(0, completion_message, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P_done)
        
    except Exception as e:
        print(f"Error in proxy squad function: {e}")
# =====================================================================
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer , whisper_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        packet_json = json.loads(packet)
                        OwNer_UiD, CHaT_CoDe, _ = await GeTSQDaTa(packet_json)

                        JoinCHaT = await AutH_Chat(3, OwNer_UiD, CHaT_CoDe, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', JoinCHaT)
                        
                        # Only send one notification message
                        notification_msg = f"[B][C][{get_random_color()}] FOLLOW ME INSTAGRAM @NR_CODRX"
                        P = await SEndMsG(0, notification_msg, OwNer_UiD, OwNer_UiD, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    except Exception as e:
                        print(f"Error processing squad join/invite: {e}")

            online_writer.close(); await online_writer.wait_closed(); online_writer = None
        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}"); online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, reconnect_delay=0.5):
    global whisper_writer, online_writer, loop_task, loop_active, evoloop_task, evoloop_active
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print(f'\n - BoT ConnEcTed WiTh CLan ChaT: {clan_id}')
                pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                if whisper_writer: whisper_writer.write(pK); await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        chat_type = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower().strip()
                        msg_parts = inPuTMsG.split()
                        command = msg_parts[0] if msg_parts else ""
                        
                        msg_json = json.loads(await DeCode_PackEt(data.hex()[10:]))
                        is_private_chat = '5' in msg_json and 'data' in msg_json['5'] and '16' in msg_json['5']['data']
                    except Exception:
                        continue

                    # --- COMMAND HANDLING ---
                    
                    if command == '/help':
                        # First message part - Automated Commands
                        menu_text1 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]    AUTOMATED COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸loop [uid1 uid2] [code] -> [FFFF00]Randomly emotes loop on TERGET ID\n\n"
                            f"[B][C][FFFFFF]/💸evoloop [uid1 uid2] [code] -> [FFFF00] Only play evo emote\n\n"
                            f"[B][C][FFFFFF]/💸stop -> [FFFF00]Stops all active loops"
                        )
                        P1 = await SEndMsG(chat_type, menu_text1, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P1)
                        await asyncio.sleep(1)
                        
                        # Second message part - Emote Commands 1
                        menu_text2 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸proxy [uid1 uid2] [emote_id] -> [FFFF00]Play emote by emote id\n\n"
                            f"[B][C][FFFFFF]/💸fun [uid1 uid2] [emote_id] -> [FFFF00] Spams an emote 200x on TERGET ID\n\n"
                            f"[B][C][FFFFFF]/💸e1 [uid1 uid2] [code] -> [FFFF00]100 Gloo Sculpture\n\n"
                            f"[B][C][FFFFFF]/💸e2 [uid1 uid2] [code] -> [FFFF00]Flowers of Love"
                        )
                        P2 = await SEndMsG(chat_type, menu_text2, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P2)
                        await asyncio.sleep(1)
                        
                        # Third message part - Emote Commands 2
                        menu_text3 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸e3 [uid1 uid2] [code] -> [FFFF00]Devil's Move\n\n"
                            f"[B][C][FFFFFF]/💸e4 [uid1 uid2] [code] -> [FFFF00]Push-up\n\n"
                            f"[B][C][FFFFFF]/💸e5 [uid1 uid2] [code] -> [FFFF00]FFWC Throne\n\n"
                            f"[B][C][FFFFFF]/💸e6 [uid1 uid2] [code] -> [FFFF00]Pirate's Flag"
                        )
                        P3 = await SEndMsG(chat_type, menu_text3, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P3)
                        await asyncio.sleep(1)
                        
                        # Fourth message part - Emote Commands 3
                        menu_text4 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸e7 [uid1 uid2] [code] -> [FFFF00]Forward, Backward\n\n"
                            f"[B][C][FFFFFF]/💸e8 [uid1 uid2] [code] -> [FFFF00]Tea Time\n\n"
                            f"[B][C][FFFFFF]/💸e9 [uid1 uid2] [code] -> [FFFF00]AK MAX\n\n"
                            f"[B][C][FFFFFF]/💸e10 [uid1 uid2] [code] -> [FFFF00]SCAR MAX"
                        )
                        P4 = await SEndMsG(chat_type, menu_text4, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P4)
                        await asyncio.sleep(1)
                        
                        # Fifth message part - Emote Commands 4
                        menu_text5 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸e11 [uid1 uid2] [code] -> [FFFF00]MP40 MAX\n\n"
                            f"[B][C][FFFFFF]/💸e12 [uid1 uid2] [code] -> [FFFF00]M10 MAX\n\n"
                            f"[B][C][FFFFFF]/💸e13 [uid1 uid2] [code] -> [FFFF00]FAMAS MAX\n\n"
                            f"[B][C][FFFFFF]/💸e14 [uid1 uid2] [code] -> [FFFF00]XM8 MAX"
                        )
                        P5 = await SEndMsG(chat_type, menu_text5, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P5)
                        await asyncio.sleep(1)
                        
                        # Sixth message part - Emote Commands 5
                        menu_text6 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸e15 [uid1 uid2] [code] -> [FFFF00]UMP MAX\n\n"
                            f"[B][C][FFFFFF]/💸e16 [uid1 uid2] [code] -> [FFFF00]M1887 MAX\n\n"
                            f"[B][C][FFFFFF]/💸e17 [uid1 uid2] [code] -> [FFFF00]EVO BOOK\n\n"
                            f"[B][C][FFFFFF]/💸e18 [uid1 uid2] [code] -> [FFFF00]CUT ALL"
                        )
                        P6 = await SEndMsG(chat_type, menu_text6, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P6)
                        await asyncio.sleep(1)
                        
                        # Seventh message part - Emote Commands 6 and Evolution
                        menu_text7 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           EMOTE COMMANDS[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸e19 [uid1 uid2] [code] -> [FFFF00]TOMATO PLAY\n\n"
                            f"[B][C][FFFFFF]/💸e20 [uid1 uid2] [code] -> [FFFF00]BROKEN THRONE\n\n")
                        P7 = await SEndMsG(chat_type, menu_text7, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P7)
                        await asyncio.sleep(1)
                        
                        # Eighth message part - Squad Management and Footer
                        menu_text8 = (
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[C][B][{get_random_color()}]           SQUAD MANAGEMENT[/B][/C]\n"
                            f"[C][B][{get_random_color()}]━━━━━━━━━━━━[/B][/C]\n"
                            f"[B][C][FFFFFF]/💸come [code] -> [FFFF00]Joins a squad\n\n"
                            f"[B][C][FFFFFF]/💸solo -> [FFFF00]Leaves the current squad\n\n")
                        P8 = await SEndMsG(chat_type, menu_text8, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P8)
                    
                    elif command == '/loop':
                        if is_private_chat:
                            if loop_active or evoloop_active:
                                message = f"[B][C][FF0000]Another process is already running. Use /stop first."
                            elif len(msg_parts) < 3:
                                message = f"[B][C][FF0000]Invalid Format! Use: /loop [uid1 uid2] [team_code]"
                            else:
                                try:
                                    # Parse space-separated UIDs (all except last)
                                    target_uids = parse_space_uids(msg_parts)
                                    team_code = get_last_param(msg_parts)
                                    
                                    if not target_uids:
                                        message = f"[B][C][FF0000]No valid UIDs found."
                                    else:
                                        loop_active = True
                                        loop_task = asyncio.create_task(loop_function(uid, chat_id, target_uids, team_code, key, iv))
                                        message = None
                                except (ValueError, IndexError):
                                    message = f"[B][C][FF0000]Invalid UIDs or Team Code."
                            if message:
                                P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command == '/evoloop':
                        if is_private_chat:
                            if loop_active or evoloop_active:
                                message = f"[B][C][FF0000]Another process is already running. Use /stop first."
                            elif len(msg_parts) < 3:
                                message = f"[B][C][FF0000]Invalid Format! Use: /evoloop [uid1 uid2] [team_code]"
                            else:
                                try:
                                    # Parse space-separated UIDs (all except last)
                                    target_uids = parse_space_uids(msg_parts)
                                    team_code = get_last_param(msg_parts)
                                    
                                    if not target_uids:
                                        message = f"[B][C][FF0000]No valid UIDs found."
                                    else:
                                        evoloop_active = True
                                        evoloop_task = asyncio.create_task(evoloop_function(uid, chat_id, target_uids, team_code, key, iv))
                                        message = None
                                except (ValueError, IndexError):
                                    message = f"[B][C][FF0000]Invalid UIDs or Team Code."
                            if message:
                                P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                    
                    elif command == '/stop':
                        stopped_processes = []
                        if loop_active and loop_task:
                            loop_active = False
                            loop_task.cancel()
                            loop_task = None
                            stopped_processes.append("Loop")
                        
                        if evoloop_active and evoloop_task:
                            evoloop_active = False
                            evoloop_task.cancel()
                            evoloop_task = None
                            stopped_processes.append("Evolution Loop")
                        
                        if stopped_processes:
                            message = f"[B][C][00FF00]{', '.join(stopped_processes)} stopped successfully."
                        else:
                            message = f"[B][C][FF0000]No automated process is currently active."
                        
                        P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command == '/solo' or command == 'leave':
                        leave_packet = await ExiT(None, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', leave_packet)
                        message = f"[B][C][{get_random_color()}]Left the squad."
                        P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command == '/come':
                        if len(msg_parts) > 1:
                            team_code = msg_parts[1]
                            join_packet = await GenJoinSquadsPacket(team_code, key, iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
                            message = f"[B][C][{get_random_color()}]Joined squad: {team_code}"
                            P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command == '/fun':
                        if len(msg_parts) < 3:
                            message = f"[B][C][FF0000]Invalid Format! Use: /fun [uid1 uid2] [emote_id]"
                        else:
                            try:
                                # Parse space-separated UIDs (all except last)
                                target_uids = parse_space_uids(msg_parts)
                                emote_id = int(get_last_param(msg_parts))
                                
                                if not target_uids:
                                    message = f"[B][C][FF0000]No valid UIDs found."
                                else:
                                    asyncio.create_task(fun_function(uid, chat_id, target_uids, emote_id, key, iv))
                                    message = None  # Response sent from within function
                            except (ValueError, IndexError):
                                message = f"[B][C][FF0000]Invalid UIDs or Emote ID."
                        
                        if message:
                            P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command.startswith('/e'):
                        if is_private_chat:
                            try:
                                emote_num = int(command[2:])  # Extract number from /e1, /e2, etc.
                                emote_id = get_emote_from_file(emote_num)
                                if not emote_id:
                                    message = f"[B][C][FF0000]Emote number {emote_num} not found in emote.txt"
                                elif len(msg_parts) < 3:
                                    message = f"[B][C][FF0000]Invalid Format! Use: {command} [uid1 uid2] [team_code]"
                                else:
                                    # Parse space-separated UIDs (all except last)
                                    target_uids = parse_space_uids(msg_parts)
                                    team_code = get_last_param(msg_parts)
                                    
                                    if not target_uids:
                                        message = f"[B][C][FF0000]No valid UIDs found."
                                    else:
                                        asyncio.create_task(emote_multiple_function(uid, chat_id, target_uids, team_code, emote_id, key, iv))
                                        message = None  # Response sent from within function
                            except (ValueError, IndexError):
                                message = f"[B][C][FF0000]Invalid format or emote number"
                            except Exception as e:
                                message = f"[B][C][FF0000]Error: {str(e)}"
                            
                            if message:
                                P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command.startswith('/evo'):
                        if is_private_chat:
                            try:
                                evo_num = int(command[4:])  # Extract number from /evo1, /evo2, etc.
                                evo_id = get_evo_from_file(evo_num)
                                if not evo_id:
                                    message = f"[B][C][FF0000]Evo number {evo_num} not found in evo.txt"
                                elif len(msg_parts) < 3:
                                    message = f"[B][C][FF0000]Invalid Format! Use: {command} [uid1 uid2] [team_code]"
                                else:
                                    # Parse space-separated UIDs (all except last)
                                    target_uids = parse_space_uids(msg_parts)
                                    team_code = get_last_param(msg_parts)
                                    
                                    if not target_uids:
                                        message = f"[B][C][FF0000]No valid UIDs found."
                                    else:
                                        asyncio.create_task(evo_multiple_function(uid, chat_id, target_uids, team_code, evo_id, key, iv))
                                        message = None  # Response sent from within function
                            except (ValueError, IndexError):
                                message = f"[B][C][FF0000]Invalid format or evo number"
                            except Exception as e:
                                message = f"[B][C][FF0000]Error: {str(e)}"
                            
                            if message:
                                P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                    elif command == '/proxy':
                        if len(msg_parts) < 3:
                            message = f"[B][C][FF0000]Invalid Format! Use: /proxy [uid1 uid2] [emote_id]"
                        else:
                            try:
                                # Parse space-separated UIDs (all except last)
                                uids = parse_space_uids(msg_parts)
                                emote_id = int(get_last_param(msg_parts))
                                
                                if not uids:
                                    message = f"[B][C][FF0000]No valid UIDs found."
                                else:
                                    if is_private_chat:
                                        # For private chat, we need team code
                                        if len(msg_parts) < 4:
                                            message = f"[B][C][FF0000]In private chat, use: /proxy [uid1 uid2] [emote_id] [team_code]"
                                        else:
                                            team_code = get_last_param(msg_parts)
                                            asyncio.create_task(proxy_private_function(uid, chat_id, team_code, uids, emote_id, key, iv))
                                            message = None
                                    else:
                                        # For squad chat, directly emote without joining/leaving
                                        asyncio.create_task(proxy_squad_function(uid, chat_id, uids, emote_id, key, iv))
                                        message = None
                                    
                            except (ValueError, IndexError):
                                message = f"[B][C][FF0000]Invalid UIDs or emote ID"
                        
                        if message:
                            P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

            whisper_writer.close(); await whisper_writer.wait_closed(); whisper_writer = None
        except Exception as e: print(f"ErroR {ip}:{port} - {e}"); whisper_writer = None
        await asyncio.sleep(reconnect_delay)


async def MaiiiinE():
    Uid , Pw = '4229611937' , '8B41E2E7BA38683D6A3622BF69758BA0FB466C576FDAEB01A34AFC1EAA3D3FA3'
    
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL, REGION)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin DaTa !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event))
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))
    os.system('clear')
    print(render('NILAY', colors=['white', 'red'], align='center'))
    print(f"\n - BoT STarTinG And OnLine on TarGet : {TarGeT}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    await asyncio.gather(task1 , task2)
    
async def StarTinG():
    while True:
        try: 
            await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: 
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e: 
            print(f"ErroR TcP - {e} => ResTarTinG ...")

if __name__ == '__main__':
    get_emote_from_file(1) 
    get_evo_from_file(1)
    get_random_loop_item()
    get_random_evoloop_item()
    asyncio.run(StarTinG())