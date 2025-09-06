import asyncio
import socket
import time
import select
import threading
import json
import os
from datetime import datetime
from protobuf_decoder.protobuf_decoder import Parser
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters
import logging

# إعداد التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

####################################
# إعدادات البوت والمتغيرات العامة
####################################
BOT_TOKEN = "8190967468:AAGsHiI6RyBAyiU4w38P2v2tWUzDNMuMdUo"  # ضع توكن البوت هنا
SOCKS5_VERSION = 5
username = "bot"
password = "bot"

# قاموس لتخزين بيانات كل مستخدم
user_sessions = {}

class UserSession:
    def __init__(self, user_id):
        self.user_id = user_id
        self.captured_packets = []
        self.server_list = []
        self.proxy_thread = None
        self.proxy_socket = None
        self.is_capturing = False
        self.capture_mode = None
        self.max_packets = 0
        
    def reset(self):
        self.captured_packets.clear()
        self.server_list.clear()
        self.is_capturing = False
        self.capture_mode = None
        self.max_packets = 0
        if self.proxy_socket:
            try:
                self.proxy_socket.close()
            except:
                pass
            self.proxy_socket = None

####################################
# وظائف فك تشفير Protobuf
####################################
def parse_results(parsed_results):
    """تحليل النتائج وإرجاعها كـ dictionary بمفاتيح رقمية"""
    result_dict = {}
    for result in parsed_results:
        field_num = int(result.field)
        
        if result.wire_type == "varint":
            result_dict[field_num] = result.data
        elif result.wire_type in ["string", "bytes"]:
            result_dict[field_num] = result.data
        elif result.wire_type == "length_delimited":
            nested_data = parse_results(result.data.results)
            result_dict[field_num] = nested_data
    
    return result_dict

def decode_protobuf(packet_hex):
    """فك تشفير Protobuf وإرجاع dictionary مع مفاتيح رقمية"""
    try:
        if len(packet_hex) > 10:
            packet_hex = packet_hex[10:]
        
        parsed_results = Parser().parse(packet_hex)
        parsed_dict = parse_results(parsed_results)
        return parsed_dict
    except Exception as e:
        return None

def format_dict_output(data, indent=0):
    """تنسيق الإخراج بشكل جميل مع مفاتيح رقمية"""
    if not isinstance(data, dict):
        return repr(data)
    
    if not data:
        return "{}"
    
    lines = ["{"]
    items = list(data.items())
    
    for i, (key, value) in enumerate(items):
        spaces = "    " * (indent + 1)
        if isinstance(value, dict):
            formatted_value = format_dict_output(value, indent + 1)
        else:
            formatted_value = repr(value)
        
        comma = "," if i < len(items) - 1 else ""
        lines.append(f"{spaces}{key}: {formatted_value}{comma}")
    
    closing_spaces = "    " * indent
    lines.append(f"{closing_spaces}}}")
    
    return "\n".join(lines)

####################################
# وظائف SOCKS5 Proxy
####################################
def handle_client(connection, user_session):
    """التعامل مع اتصالات العملاء"""
    try:
        version, nmethods = connection.recv(2)
        methods = get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS5_VERSION, 2]))
        if not verify(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length).decode('utf-8')
            address = socket.gethostbyname(address)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((address, port))
        serverlog(address, port, user_session)
        bind_address = remote.getsockname()
        addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
        port = bind_address[1]
        reply = b"".join([
            SOCKS5_VERSION.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(1).to_bytes(1, 'big'),
            addr.to_bytes(4, 'big'),
            port.to_bytes(2, 'big')
        ])
        connection.sendall(reply)
        exchange_loop(connection, remote, user_session)
    except Exception as e:
        connection.close()

def verify(connection):
    """التحقق من بيانات الاعتماد"""
    try:
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username_received = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password_received = connection.recv(password_len).decode('utf-8')
        if username_received == username and password_received == password:
            connection.sendall(bytes([version, 0]))
            return True
        connection.sendall(bytes([version, 0xFF]))
        connection.close()
        return False
    except:
        return False

def get_available_methods(nmethods, connection):
    """الحصول على الطرق المتاحة"""
    return [connection.recv(1)[0] for _ in range(nmethods)]

def serverlog(address, port, user_session):
    """تسجيل معلومات الخادم"""
    server_info = f"{address}:{port}"
    if server_info not in user_session.server_list:
        user_session.server_list.append(server_info)

def analyze_packet(packet_hex, direction, user_session):
    """تحليل الحزمة وحفظها"""
    if not user_session.is_capturing:
        return
    
    # فحص نوع الحزمة حسب الوضع المختار
    should_capture = False
    mode = user_session.capture_mode
    
    if mode == "1" or mode == "5":  # جميع الحزم
        should_capture = True
    elif mode == "2" and packet_hex.startswith("1215"):  # حزم الجيلد
        should_capture = True
    elif mode == "3" and packet_hex.startswith("0515"):  # حزم السكواد
        should_capture = True
    
    if should_capture:
        packet_data = {
            "hex": packet_hex,
            "direction": direction,
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # فك التشفير إذا كان في الوضع 5
        if mode == "5":
            decoded_data = decode_protobuf(packet_hex)
            if decoded_data:
                packet_data["decoded"] = decoded_data
        
        user_session.captured_packets.append(packet_data)
        
        # إيقاف الالتقاط إذا وصل للحد الأقصى
        if user_session.max_packets > 0 and len(user_session.captured_packets) >= user_session.max_packets:
            user_session.is_capturing = False

def exchange_loop(client, remote, user_session):
    """حلقة تبادل البيانات مع تحليل الحزم"""
    while user_session.is_capturing:
        try:
            r, w, e = select.select([client, remote], [], [], 1)
            
            if client in r:
                dataC = client.recv(4096)
                if not dataC:
                    break
                dataC_hex = dataC.hex()
                analyze_packet(dataC_hex, "SERVER→CLIENT", user_session)
                if remote.send(dataC) <= 0:
                    break
                    
            if remote in r:
                dataS = remote.recv(4096)
                if not dataS:
                    break
                dataS_hex = dataS.hex()
                analyze_packet(dataS_hex, "CLIENT→SERVER", user_session)
                if client.send(dataS) <= 0:
                    break
        except Exception as e:
            break
    
    client.close()
    remote.close()

def run_proxy(user_session):
    """تشغيل خادم الـ proxy"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1",3000))
        s.listen()
        user_session.proxy_socket = s
        
        while user_session.is_capturing:
            try:
                s.settimeout(1)
                conn, addr = s.accept()
                if user_session.is_capturing:
                    t = threading.Thread(target=handle_client, args=(conn, user_session))
                    t.daemon = True
                    t.start()
                else:
                    conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                break
    except Exception as e:
        pass
    finally:
        if s:
            s.close()

####################################
# وظائف بوت التلجرام
####################################
def get_user_session(user_id):
    """الحصول على جلسة المستخدم أو إنشاء واحدة جديدة"""
    if user_id not in user_sessions:
        user_sessions[user_id] = UserSession(user_id)
    return user_sessions[user_id]

async def start(update: Update, context) -> None:
    """وظيفة البداية"""
    user_id = update.effective_user.id
    session = get_user_session(user_id)
    
    welcome_text = """
🔥 **مرحباً بك في FFPacketSniper Advanced Bot** 🔥

🤖 **تطوير:** @fox, @trickzqw
📦 **النسخة:** 2.0 المطورة
🔐 **المصادقة:** bot:bot
🎯 **الهدف:** تسجيل وتحليل حزم FREE FIRE

استخدم /help لعرض جميع الأوامر المتاحة
    """
    
    keyboard = [
        [InlineKeyboardButton("📋 القائمة الرئيسية", callback_data="main_menu")],
        [InlineKeyboardButton("ℹ️ المساعدة", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def help_command(update: Update, context) -> None:
    """عرض قائمة المساعدة"""
    await show_main_menu(update, context)

async def show_main_menu(update: Update, context) -> None:
    """عرض القائمة الرئيسية"""
    menu_text = """
🎯 **أداة FOX المطورة لتسجيل وتحليل حزم FREE FIRE**

🔹 **الأوامر المتاحة:**

1️⃣ تسجيل جميع الحزم + فك التشفير التلقائي
2️⃣ تسجيل حزم الجيلد (GUILD) فقط  
3️⃣ تسجيل حزم السكواد (SQUAD) فقط
4️⃣ عرض معلومات الحزم
5️⃣ تسجيل مع فك التشفير المباشر
6️⃣ فك تشفير يدوي لحزمة
7️⃣ فك تشفير جميع الحزم المحفوظة
8️⃣ إظهار إحصائيات الحزم
🛑 إيقاف التسجيل الحالي

📊 **معلومات الحزم:**
• الجيلد: 1215
• السكواد: 0515  
• الرسائل: 1200
    """
    
    keyboard = [
        [InlineKeyboardButton("1️⃣ تسجيل كل الحزم", callback_data="mode_1"),
         InlineKeyboardButton("2️⃣ حزم الجيلد", callback_data="mode_2")],
        [InlineKeyboardButton("3️⃣ حزم السكواد", callback_data="mode_3"),
         InlineKeyboardButton("4️⃣ معلومات الحزم", callback_data="packet_info")],
        [InlineKeyboardButton("5️⃣ تسجيل + فك تشفير", callback_data="mode_5"),
         InlineKeyboardButton("6️⃣ فك تشفير يدوي", callback_data="manual_decode")],
        [InlineKeyboardButton("7️⃣ فك تشفير المحفوظة", callback_data="decode_all"),
         InlineKeyboardButton("8️⃣ الإحصائيات", callback_data="statistics")],
        [InlineKeyboardButton("🛑 إيقاف التسجيل", callback_data="stop_capture")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.callback_query:
        await update.callback_query.edit_message_text(menu_text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await update.message.reply_text(menu_text, reply_markup=reply_markup, parse_mode='Markdown')

async def button_handler(update: Update, context) -> None:
    """معالج أزرار الكيبورد"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    session = get_user_session(user_id)
    
    if query.data == "main_menu":
        await show_main_menu(update, context)
    elif query.data == "help":
        await show_main_menu(update, context)
    elif query.data.startswith("mode_"):
        mode = query.data.split("_")[1]
        await ask_packet_count(query, session, mode)
    elif query.data == "packet_info":
        await show_packet_info(query)
    elif query.data == "manual_decode":
        await ask_manual_decode(query)
    elif query.data == "decode_all":
        await decode_all_packets(query, session)
    elif query.data == "statistics":
        await show_statistics(query, session)
    elif query.data == "stop_capture":
        await stop_capture(query, session)
    elif query.data.startswith("start_"):
        parts = query.data.split("_")
        mode = parts[1]
        count = int(parts[2]) if parts[2] != "unlimited" else 0
        await start_capture(query, session, mode, count)

async def ask_packet_count(query, session, mode):
    """سؤال عن عدد الحزم المطلوب تسجيلها"""
    mode_names = {
        "1": "تسجيل جميع الحزم + فك التشفير التلقائي",
        "2": "تسجيل حزم الجيلد (GUILD) فقط",
        "3": "تسجيل حزم السكواد (SQUAD) فقط", 
        "5": "تسجيل مع فك التشفير المباشر"
    }
    
    text = f"""
🎯 **تم اختيار:** {mode_names.get(mode, "وضع غير محدد")}

📊 **كم حزمة تريد تسجيلها؟**

اختر العدد المناسب أو تسجيل غير محدود:
    """
    
    keyboard = [
        [InlineKeyboardButton("10 حزم", callback_data=f"start_{mode}_10"),
         InlineKeyboardButton("25 حزمة", callback_data=f"start_{mode}_25")],
        [InlineKeyboardButton("50 حزمة", callback_data=f"start_{mode}_50"),
         InlineKeyboardButton("100 حزمة", callback_data=f"start_{mode}_100")],
        [InlineKeyboardButton("🔄 غير محدود", callback_data=f"start_{mode}_unlimited")],
        [InlineKeyboardButton("🔙 رجوع", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

async def start_capture(query, session, mode, count):
    """بدء تسجيل الحزم"""
    if session.is_capturing:
        await query.edit_message_text("⚠️ التسجيل يعمل بالفعل! استخدم إيقاف التسجيل أولاً.")
        return
    
    session.reset()
    session.capture_mode = mode
    session.max_packets = count
    session.is_capturing = True
    
    # بدء الproxy في thread منفصل
    session.proxy_thread = threading.Thread(target=run_proxy, args=(session,))
    session.proxy_thread.daemon = True
    session.proxy_thread.start()
    
    count_text = f"{count} حزمة" if count > 0 else "غير محدود"
    mode_names = {
        "1": "جميع الحزم + فك تشفير تلقائي",
        "2": "حزم الجيلد فقط",
        "3": "حزم السكواد فقط",
        "5": "تسجيل + فك تشفير مباشر"
    }
    
    text = f"""
✅ **تم بدء التسجيل بنجاح!**

🎯 **الوضع:** {mode_names.get(mode)}
📊 **العدد المطلوب:** {count_text}
🌐 **البروكسي:** 127.0.0.1:1080
🔐 **المصادقة:** bot:bot

📱 **الآن قم بضبط البروكسي في Free Fire وابدأ اللعب**

⏱️ **حالة التسجيل:** جاري التسجيل...
📦 **الحزم المسجلة:** 0
    """
    
    keyboard = [
        [InlineKeyboardButton("🛑 إيقاف التسجيل", callback_data="stop_capture")],
        [InlineKeyboardButton("📊 عرض الإحصائيات", callback_data="statistics")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # مراقبة التسجيل
    await monitor_capture(query, session)

async def monitor_capture(query, session):
    """مراقبة عملية التسجيل"""
    last_count = 0
    
    while session.is_capturing:
        await asyncio.sleep(5)  # فحص كل 5 ثوان
        current_count = len(session.captured_packets)
        
        # تحديث الرسالة إذا تغير العدد
        if current_count != last_count:
            count_text = f"{session.max_packets} حزمة" if session.max_packets > 0 else "غير محدود"
            mode_names = {
                "1": "جميع الحزم + فك تشفير تلقائي",
                "2": "حزم الجيلد فقط",
                "3": "حزم السكواد فقط",
                "5": "تسجيل + فك تشفير مباشر"
            }
            
            status = "جاري التسجيل..." if session.is_capturing else "تم إيقاف التسجيل"
            
            text = f"""
✅ **حالة التسجيل**

🎯 **الوضع:** {mode_names.get(session.capture_mode)}
📊 **العدد المطلوب:** {count_text}
🌐 **البروكسي:** 127.0.0.1:1080

⏱️ **الحالة:** {status}
📦 **الحزم المسجلة:** {current_count}
🖥️ **الخوادم المتصلة:** {len(session.server_list)}
            """
            
            keyboard = [
                [InlineKeyboardButton("🛑 إيقاف التسجيل", callback_data="stop_capture")],
                [InlineKeyboardButton("📊 عرض الإحصائيات", callback_data="statistics")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            try:
                await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
            except:
                pass
            
            last_count = current_count
        
        # إيقاف تلقائي عند الوصول للحد الأقصى
        if session.max_packets > 0 and current_count >= session.max_packets:
            session.is_capturing = False
            await stop_capture_auto(query, session)
            break

async def stop_capture_auto(query, session):
    """إيقاف تلقائي للتسجيل"""
    await send_captured_files(query, session)

async def stop_capture(query, session):
    """إيقاف التسجيل يدوياً"""
    if not session.is_capturing:
        await query.edit_message_text("ℹ️ لا يوجد تسجيل نشط حالياً.")
        return
    
    session.is_capturing = False
    
    if session.proxy_socket:
        try:
            session.proxy_socket.close()
        except:
            pass
    
    await send_captured_files(query, session)

async def send_captured_files(query, session):
    """إرسال ملفات الحزم المسجلة"""
    if not session.captured_packets:
        text = """
⚠️ **لم يتم تسجيل أي حزم**

تأكد من:
• ضبط البروكسي بشكل صحيح (127.0.0.1:1080)
• استخدام المصادقة الصحيحة (bot:bot)  
• اللعب في Free Fire بعد بدء التسجيل
        """
        
        keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
        return
    
    # إنشاء ملفات البيانات
    timestamp = int(time.time())
    
    # ملف HEX
    hex_content = f"# FF Packet Sniper - الحزم المسجلة\n"
    hex_content += f"# التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    hex_content += f"# العدد: {len(session.captured_packets)}\n"
    hex_content += f"# الوضع: {session.capture_mode}\n\n"
    
    for i, packet in enumerate(session.captured_packets):
        hex_content += f"# Packet {i+1} - {packet['direction']} - {packet['datetime']}\n"
        hex_content += f"{packet['hex']}\n\n"
    
    hex_filename = f"packets_hex_{timestamp}.txt"
    with open(hex_filename, "w", encoding="utf-8") as f:
        f.write(hex_content)
    
    # ملف JSON مع فك التشفير
    json_data = {
        "session_info": {
            "timestamp": timestamp,
            "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "mode": session.capture_mode,
            "total_packets": len(session.captured_packets),
            "servers": session.server_list
        },
        "packets": []
    }
    
    decoded_count = 0
    for packet in session.captured_packets:
        packet_data = {
            "hex": packet['hex'],
            "direction": packet['direction'],
            "timestamp": packet['timestamp'],
            "datetime": packet['datetime']
        }
        
        # محاولة فك التشفير
        if "decoded" in packet:
            packet_data["decoded"] = packet["decoded"]
            decoded_count += 1
        else:
            decoded = decode_protobuf(packet['hex'])
            if decoded:
                packet_data["decoded"] = decoded
                decoded_count += 1
        
        json_data["packets"].append(packet_data)
    
    json_filename = f"packets_decoded_{timestamp}.json"
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    # إرسال الملفات
    text = f"""
✅ **تم انتهاء التسجيل بنجاح!**

📊 **الإحصائيات:**
• إجمالي الحزم: {len(session.captured_packets)}
• تم فك تشفيرها: {decoded_count}
• الخوادم المتصلة: {len(session.server_list)}

📁 **الملفات:**
• ملف HEX: يحتوي على جميع الحزم الخام
• ملف JSON: يحتوي على البيانات مع فك التشفير
    """
    
    keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # إرسال الملفات
    try:
        with open(hex_filename, 'rb') as f:
            await query.message.reply_document(f, filename=hex_filename, caption="📄 ملف الحزم بصيغة HEX")
        
        with open(json_filename, 'rb') as f:
            await query.message.reply_document(f, filename=json_filename, caption="🔓 ملف الحزم مع فك التشفير")
        
        # حذف الملفات المؤقتة
        os.remove(hex_filename)
        os.remove(json_filename)
        
    except Exception as e:
        await query.message.reply_text(f"❌ حدث خطأ في إرسال الملفات: {str(e)}")

async def show_packet_info(query):
    """عرض معلومات الحزم"""
    text = """
📋 **معلومات أنواع الحزم**

🔹 **حزم الجيلد (GUILD):** 1215
🔹 **حزم السكواد (SQUAD):** 0515  
🔹 **حزم الرسائل (MESSAGES):** 1200
🔹 **الدعوات المزعجة:** 0515

💡 **نصائح:**
• استخدم وضع "جميع الحزم" للحصول على تسجيل شامل
• وضع فك التشفير المباشر يوفر تحليلاً فورياً
• حفظ الملفات يتم تلقائياً بعد انتهاء التسجيل
    """
    
    keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

async def show_statistics(query, session):
    """عرض إحصائيات الحزم"""
    if not session.captured_packets:
        text = "📊 **الإحصائيات**\n\n⚠️ لا توجد حزم مسجلة حالياً"
        
        keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
        return
    
    total_packets = len(session.captured_packets)
    client_to_server = len([p for p in session.captured_packets if "CLIENT→SERVER" in p['direction']])
    server_to_client = total_packets - client_to_server
    
    guild_packets = len([p for p in session.captured_packets if p['hex'].startswith("1215")])
    squad_packets = len([p for p in session.captured_packets if p['hex'].startswith("0515")])
    
    # حساب البيانات المفكوكة
    decoded_packets = len([p for p in session.captured_packets if "decoded" in p])
    
    text = f"""
📊 **إحصائيات الحزم المسجلة**

📦 **إجمالي الحزم:** {total_packets}
⬆️ **من العميل للخادم:** {client_to_server}
⬇️ **من الخادم للعميل:** {server_to_client}

🏰 **حزم الجيلد:** {guild_packets}
👥 **حزم السكواد:** {squad_packets}
🔓 **تم فك تشفيرها:** {decoded_packets}

🖥️ **الخوادم المتصلة:** {len(session.server_list)}
⏱️ **حالة التسجيل:** {"🟢 نشط" if session.is_capturing else "🔴 متوقف"}
    """
    
    keyboard = [
        [InlineKeyboardButton("🛑 إيقاف التسجيل", callback_data="stop_capture")] if session.is_capturing else [],
        [InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup([btn for btn in keyboard if btn])
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

async def ask_manual_decode(query):
    """طلب حزمة لفك التشفير يدوياً"""
    text = """
🔧 **فك التشفير اليدوي**

📝 **أرسل الحزمة بتنسيق HEX للفك:**

مثال: `1a0a08c8e1d2f30b1003180120002a020800`

⚠️ **ملاحظة:** أرسل الحزمة في رسالة منفصلة
    """
    
    keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')

async def decode_all_packets(query, session):
    """فك تشفير جميع الحزم المحفوظة"""
    if not session.captured_packets:
        text = "⚠️ **لا توجد حزم محفوظة لفك التشفير**"
        
        keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
        return
    
    await query.edit_message_text(f"🔄 **جاري فك تشفير {len(session.captured_packets)} حزمة...**")
    
    decoded_count = 0
    failed_count = 0
    
    for packet in session.captured_packets:
        if "decoded" not in packet:
            decoded_data = decode_protobuf(packet['hex'])
            if decoded_data:
                packet["decoded"] = decoded_data
                decoded_count += 1
            else:
                failed_count += 1
        else:
            decoded_count += 1
    
    # إنشاء ملف النتائج
    timestamp = int(time.time())
    results = {
        "decode_session": {
            "timestamp": timestamp,
            "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "total_packets": len(session.captured_packets),
            "decoded_successfully": decoded_count,
            "failed_to_decode": failed_count
        },
        "decoded_packets": []
    }
    
    for i, packet in enumerate(session.captured_packets):
        if "decoded" in packet:
            packet_result = {
                "packet_index": i + 1,
                "hex": packet['hex'],
                "direction": packet['direction'],
                "datetime": packet['datetime'],
                "decoded_fields": packet['decoded']
            }
            results["decoded_packets"].append(packet_result)
    
    filename = f"all_decoded_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    text = f"""
✅ **تم فك التشفير بنجاح!**

📊 **النتائج:**
• إجمالي الحزم: {len(session.captured_packets)}
• تم فك تشفيرها: {decoded_count}
• فشل فك التشفير: {failed_count}
• معدل النجاح: {(decoded_count/len(session.captured_packets)*100):.1f}%

📁 **تم إنشاء ملف النتائج**
    """
    
    keyboard = [[InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # إرسال ملف النتائج
    try:
        with open(filename, 'rb') as f:
            await query.message.reply_document(f, filename=filename, 
                                             caption=f"🔓 نتائج فك تشفير {decoded_count} حزمة")
        os.remove(filename)
    except Exception as e:
        await query.message.reply_text(f"❌ خطأ في إرسال الملف: {str(e)}")

async def handle_hex_message(update: Update, context) -> None:
    """معالجة رسائل HEX لفك التشفير"""
    text = update.message.text.strip()
    
    # فحص إذا كان النص يحتوي على hex
    if all(c in '0123456789abcdefABCDEF' for c in text.replace(' ', '')):
        hex_data = text.replace(' ', '').lower()
        
        if len(hex_data) >= 4:  # حد أدنى للحزمة
            await update.message.reply_text("🔄 **جاري فك التشفير...**")
            
            decoded_data = decode_protobuf(hex_data)
            
            if decoded_data:
                # إنشاء ملف النتيجة
                timestamp = int(time.time())
                result = {
                    "manual_decode": {
                        "timestamp": timestamp,
                        "datetime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "original_hex": hex_data
                    },
                    "decoded_fields": decoded_data
                }
                
                formatted_output = format_dict_output(decoded_data)
                
                # عرض النتيجة (مختصرة إذا كانت طويلة)
                if len(formatted_output) > 3000:
                    preview = formatted_output[:3000] + "\n... (باقي البيانات في الملف)"
                else:
                    preview = formatted_output
                
                response_text = f"""
✅ **تم فك التشفير بنجاح!**

📦 **الحزمة الأصلية:** `{hex_data[:50]}{'...' if len(hex_data) > 50 else ''}`

🔓 **البيانات المفكوكة:**
```
{preview}
```
                """
                
                # إنشاء وإرسال ملف النتيجة
                filename = f"manual_decode_{timestamp}.json"
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                
                await update.message.reply_text(response_text, parse_mode='Markdown')
                
                try:
                    with open(filename, 'rb') as f:
                        await update.message.reply_document(f, filename=filename, 
                                                          caption="🔓 نتيجة فك التشفير اليدوي")
                    os.remove(filename)
                except Exception as e:
                    await update.message.reply_text(f"❌ خطأ في إرسال الملف: {str(e)}")
            
            else:
                await update.message.reply_text("""
❌ **فشل في فك التشفير**

🔍 **الأسباب المحتملة:**
• الحزمة تالفة أو غير مكتملة
• تنسيق HEX غير صحيح
• ليست حزمة Protobuf صالحة

💡 **تأكد من:**
• نسخ الحزمة كاملة
• إزالة أي مسافات أو رموز إضافية
                """)
        else:
            await update.message.reply_text("⚠️ **الحزمة قصيرة جداً**\n\nيجب أن تكون الحزمة أطول من 4 أحرف hex")

async def error_handler(update: Update, context) -> None:
    """معالج الأخطاء العام"""
    print(f"خطأ: {context.error}")

def main():
    """الوظيفة الرئيسية لتشغيل البوت"""
    if BOT_TOKEN == "8190967468:AAGsHiI6RyBAyiU4w38P2v2tWUzDNMuMdUo":
        print("⚠️ يرجى إدخال توكن البوت في المتغير BOT_TOKEN")
        return
    
    # إنشاء التطبيق
    application = Application.builder().token(BOT_TOKEN).build()
    
    # إضافة معالجات الأوامر
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    
    # معالج الأزرار
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # معالج رسائل HEX
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_hex_message))
    
    # معالج الأخطاء
    application.add_error_handler(error_handler)
    
    print("🤖 تم تشغيل FFPacketSniper Telegram Bot...")
    print("📱 أرسل /start للبدء")
    
    # تشغيل البوت
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
