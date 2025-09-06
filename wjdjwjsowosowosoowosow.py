import socket
import time
import select
import re
import threading
import json
import telebot
from protobuf_decoder.protobuf_decoder import Parser
from telebot.types import ReplyKeyboardMarkup, KeyboardButton

####################################
# إعدادات عامة
####################################
START_GAME = False
SOCKS5_VERSION = 5
username = "bot"
password = "bot"
server_list = []
captured_packets = []

# ألوان الطرفية
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_UNDERLINE = "\033[4m"

# إعدادات بوت تلجرام
TELEGRAM_BOT_TOKEN = "8190967468:AAGsHiI6RyBAyiU4w38P2v2tWUzDNMuMdUo"
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# حالة البروكسي
proxy_running = False
proxy_thread = None
current_choice = None

####################################
# وظائف فك تشفير Protobuf
####################################
def parse_results(parsed_results):
    """
    تحليل النتائج وإرجاعها كـ dictionary بمفاتيح رقمية
    """
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
    """
    فك تشفير Protobuf وإرجاع dictionary مع مفاتيح رقمية
    """
    try:
        # إزالة البادئة إذا كانت موجودة
        if len(packet_hex) > 10:
            packet_hex = packet_hex[10:]
        
        parsed_results = Parser().parse(packet_hex)
        parsed_dict = parse_results(parsed_results)
        return parsed_dict
    except Exception as e:
        print(f"{COLOR_RED}خطأ في فك تشفير Protobuf: {e}{COLOR_RESET}")
        return None

def format_dict_output(data, indent=0):
    """
    تنسيق الإخراج بشكل جميل مع مفاتيح رقمية
    """
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

def save_decoded_packet(decoded_data, packet_hex):
    """
    حفظ البيانات المفكوكة في ملفات
    """
    if decoded_data:
        timestamp = int(time.time())
        
        # حفظ في تنسيق Python
        with open(f"decoded_packet_{timestamp}.py", "w", encoding="utf-8") as f:
            f.write("# نتائج فك تشفير Protobuf\n")
            f.write(f"# الحزمة الأصلية: {packet_hex}\n")
            f.write("fields = ")
            f.write(format_dict_output(decoded_data))
            f.write("\n")
        
        # حفظ في تنسيق JSON
        with open(f"decoded_packet_{timestamp}.json", "w", encoding="utf-8") as f:
            json.dump({
                "original_packet": packet_hex,
                "decoded_fields": decoded_data,
                "timestamp": timestamp
            }, f, indent=4, ensure_ascii=False)
        
        return f"تم حفظ البيانات المفكوكة في:\n- decoded_packet_{timestamp}.py\n- decoded_packet_{timestamp}.json"
    return "فشل في حفظ البيانات"

####################################
# وظائف SOCKS5 Proxy
####################################
def handle_client(connection, choice):
    """
    التعامل مع اتصالات العملاء
    """
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
        serverlog(address, port)
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
        exchange_loop(connection, remote, choice)
    except Exception as e:
        print(f"{COLOR_RED}خطأ في التعامل مع العميل: {e}{COLOR_RESET}")
        connection.close()

def verify(connection):
    """
    التحقق من بيانات الاعتماد
    """
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
    """
    الحصول على الطرق المتاحة
    """
    return [connection.recv(1)[0] for _ in range(nmethods)]

def serverlog(address, port):
    """
    تسجيل معلومات الخادم
    """
    server_info = f"{address}:{port}"
    if server_info not in server_list:
        server_list.append(server_info)
        print(f"{COLOR_CYAN}خادم جديد متصل: {COLOR_BOLD}{server_info}{COLOR_RESET}")

def analyze_packet(packet_hex, direction, choice):
    """
    تحليل الحزمة وفك تشفيرها إذا لزم الأمر
    """
    # حفظ الحزمة
    captured_packets.append({
        "hex": packet_hex,
        "direction": direction,
        "timestamp": time.time()
    })
    
    # فك التشفير التلقائي للحزم المهمة
    if choice in ["1", "5"] or (choice == "2" and packet_hex.startswith("1215")) or (choice == "3" and packet_hex.startswith("0515")):
        decoded_data = decode_protobuf(packet_hex)
        if decoded_data:
            print(f"{COLOR_YELLOW}[DECODED] {direction}: {COLOR_RESET}")
            print(format_dict_output(decoded_data))
            print(f"{COLOR_CYAN}{'='*50}{COLOR_RESET}")

def exchange_loop(client, remote, choice):
    """
    حلقة تبادل البيانات مع تحليل الحزم
    """
    while True:
        try:
            r, w, e = select.select([client, remote], [], [])
            
            if client in r:
                dataC = client.recv(4096)
                if not dataC:
                    break
                dataC_hex = dataC.hex()
                
                # عرض الحزم حسب الاختيار
                if choice == "1":
                    print(f"{COLOR_RED}{COLOR_BOLD}SERVER==⟩ CLIENT: {dataC_hex}{COLOR_RESET}")
                    analyze_packet(dataC_hex, "SERVER→CLIENT", choice)
                elif choice == "2" and dataC_hex.startswith("1215"):
                    print(f"{COLOR_RED}{COLOR_BOLD}SERVER TO CLIENT [GUILD] --⟩⟩ : {dataC_hex}{COLOR_RESET}")
                    analyze_packet(dataC_hex, "SERVER→CLIENT[GUILD]", choice)
                elif choice == "3" and dataC_hex.startswith("0515"):
                    print(f"{COLOR_RED}{COLOR_BOLD}SERVER==⟩ CLIENT [SQUAD]: {dataC_hex}{COLOR_RESET}")
                    analyze_packet(dataC_hex, "SERVER→CLIENT[SQUAD]", choice)
                elif choice == "5":
                    print(f"{COLOR_RED}{COLOR_BOLD}SERVER==⟩ CLIENT: {dataC_hex}{COLOR_RESET}")
                    analyze_packet(dataC_hex, "SERVER→CLIENT", choice)
                
                if remote.send(dataC) <= 0:
                    break
                    
            if remote in r:
                dataS = remote.recv(4096)
                if not dataS:
                    break
                dataS_hex = dataS.hex()
                
                # عرض الحزم حسب الاختيار
                if choice == "1":
                    print(f"CLIENT==⟩ {COLOR_BLUE}{COLOR_BOLD}SERVER: {dataS_hex}{COLOR_RESET}")
                    analyze_packet(dataS_hex, "CLIENT→SERVER", choice)
                elif choice == "2" and dataS_hex.startswith("1215"):
                    print(f"{COLOR_BLUE}{COLOR_BOLD}CLIENT TO SERVER [GUILD] --⟩⟩ : {dataS_hex}{COLOR_RESET}")
                    analyze_packet(dataS_hex, "CLIENT→SERVER[GUILD]", choice)
                elif choice == "3" and dataS_hex.startswith("0515"):
                    print(f"{COLOR_BLUE}{COLOR_BOLD}CLIENT==⟩ SERVER [SQUAD]: {dataS_hex}{COLOR_RESET}")
                    analyze_packet(dataS_hex, "CLIENT→SERVER[SQUAD]", choice)
                elif choice == "5":
                    print(f"CLIENT==⟩ {COLOR_BLUE}{COLOR_BOLD}SERVER: {dataS_hex}{COLOR_RESET}")
                    analyze_packet(dataS_hex, "CLIENT→SERVER", choice)
                
                if client.send(dataS) <= 0:
                    break
        except Exception as e:
            print(f"{COLOR_RED}خطأ في تبادل البيانات: {e}{COLOR_RESET}")
            break
    
    client.close()
    remote.close()

def decode_saved_packets():
    """
    فك تشفير جميع الحزم المحفوظة
    """
    if not captured_packets:
        return "لا توجد حزم محفوظة لفك التشفير"
    
    result = f"فك تشفير {len(captured_packets)} حزمة محفوظة...\n"
    
    decoded_count = 0
    for i, packet in enumerate(captured_packets):
        result += f"[{i+1}/{len(captured_packets)}] {packet['direction']}\n"
        decoded_data = decode_protobuf(packet['hex'])
        if decoded_data:
            decoded_count += 1
            result += "تم فك التشفير بنجاح:\n"
            result += format_dict_output(decoded_data) + "\n"
            
            # حفظ البيانات المفكوكة
            save_result = save_decoded_packet(decoded_data, packet['hex'])
            result += save_result + "\n"
        else:
            result += "فشل فك التشفير\n"
        result += "="*60 + "\n"
    
    result += f"تم فك تشفير {decoded_count} من {len(captured_packets)} حزمة بنجاح"
    return result

def manual_decode(packet_hex):
    """
    فك تشفير يدوي لحزمة hex
    """
    if not packet_hex.strip():
        return "لم تدخل أي حزمة"
    
    decoded_data = decode_protobuf(packet_hex.strip())
    if decoded_data:
        result = "تم فك التشفير بنجاح:\n"
        result += format_dict_output(decoded_data) + "\n"
        save_result = save_decoded_packet(decoded_data, packet_hex.strip())
        result += save_result
        return result
    else:
        return "فشل فك التشفير"

####################################
# وظائف الـ Proxy
####################################
def run_proxy(host, port, choice):
    """
    تشغيل خادم الـ proxy
    """
    global proxy_running
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"{COLOR_YELLOW}Proxy يعمل على ⟩⟩ : {COLOR_MAGENTA}{COLOR_BOLD}{host}:{port}{COLOR_RESET}")
        print(f"{COLOR_GREEN}بانتظار الاتصالات...{COLOR_RESET}")
        
        while proxy_running:
            conn, addr = s.accept()
            print(f"{COLOR_CYAN}اتصال جديد من: {addr}{COLOR_RESET}")
            t = threading.Thread(target=handle_client, args=(conn, choice))
            t.daemon = True
            t.start()
    except Exception as e:
        print(f"{COLOR_RED}خطأ في تشغيل الـ proxy: {e}{COLOR_RESET}")
    finally:
        proxy_running = False

def start_proxy(choice):
    """
    بدء تشغيل البروكسي في thread منفصل
    """
    global proxy_running, proxy_thread, current_choice
    
    if proxy_running:
        return "البروكسي يعمل بالفعل!"
    
    proxy_running = True
    current_choice = choice
    proxy_thread = threading.Thread(target=run_proxy, args=("127.0.0.1", 3000, choice))
    proxy_thread.daemon = True
    proxy_thread.start()
    
    return "تم بدء تشغيل البروكسي بنجاح!"

def stop_proxy():
    """
    إيقاف تشغيل البروكسي
    """
    global proxy_running, proxy_thread
    
    if not proxy_running:
        return "البروكسي غير يعمل!"
    
    proxy_running = False
    proxy_thread = None
    
    return "تم إيقاف البروكسي بنجاح!"

####################################
# وظائف بوت تلجرام
####################################
def create_keyboard():
    """
    إنشاء لوحة مفاتيح للبوت
    """
    keyboard = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    keyboard.add(
        KeyboardButton("تشغيل البروكسي"),
        KeyboardButton("إيقاف البروكسي"),
        KeyboardButton("عرض الحزم المحفوظة"),
        KeyboardButton("فك تشفير الحزم"),
        KeyboardButton("إحصائيات الحزم"),
        KeyboardButton("المساعدة")
    )
    return keyboard

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """
    معالجة أمر البدء والمساعدة
    """
    help_text = """
مرحبًا بك في بوت FFPacketSniper Advanced!

الأوامر المتاحة:
/start - بدء البوت
/help - عرض هذه الرسالة

خيارات البروكسي:
- تشغيل البروكسي: بدء تسجيل الحزم
- إيقاف البروكسي: إيقاف تسجيل الحزم
- عرض الحزم المحفوظة: عرض جميع الحزم المسجلة
- فك تشفير الحزم: فك تشفير حزمة محددة
- إحصائيات الحزم: عرض إحصائيات الحزم
- المساعدة: عرض رسالة المساعدة

لبدء التسجيل، اضغط على "تشغيل البروكسي" ثم اختر نوع التسجيل.
"""
    bot.reply_to(message, help_text, reply_markup=create_keyboard())

@bot.message_handler(func=lambda message: message.text == "المساعدة")
def show_help(message):
    """
    عرض رسالة المساعدة
    """
    help_text = """
أهلاً بك في أداة FOX المطورة لتسجيل وتحليل حزم FREE FIRE!:
[1] تسجيل جميع الحزم + فك التشفير التلقائي
[2] تسجيل حزم الجيلد (GUILD) فقط
[3] تسجيل حزم السكواد (SQUAD) فقط
[4] عرض معلومات الحزم
[5] تسجيل مع فك التشفير المباشر
[6] فك تشفير يدوي لحزمة
[7] فك تشفير جميع الحزم المحفوظة
[8] إظهار إحصائيات الحزم
[0] خروج

للبدء، اضغط على "تشغيل البروكسي" ثم اختر الرقم المناسب.
"""
    bot.reply_to(message, help_text)

@bot.message_handler(func=lambda message: message.text == "تشغيل البروكسي")
def start_proxy_handler(message):
    """
    معالجة طلب تشغيل البروكسي
    """
    keyboard = ReplyKeyboardMarkup(row_width=3, resize_keyboard=True)
    keyboard.add(
        KeyboardButton("1 - جميع الحزم"),
        KeyboardButton("2 - حزم الجيلد فقط"),
        KeyboardButton("3 - حزم السكواد فقط"),
        KeyboardButton("5 - فك تشفير مباشر"),
        KeyboardButton("الغاء")
    )
    
    bot.send_message(message.chat.id, "اختر نوع التسجيل:", reply_markup=keyboard)

@bot.message_handler(func=lambda message: message.text in ["1 - جميع الحزم", "2 - حزم الجيلد فقط", "3 - حزم السكواد فقط", "5 - فك تشفير مباشر"])
def handle_proxy_choice(message):
    """
    معالجة اختيار نوع البروكسي
    """
    choice_map = {
        "1 - جميع الحزم": "1",
        "2 - حزم الجيلد فقط": "2",
        "3 - حزم السكواد فقط": "3",
        "5 - فك تشفير مباشر": "5"
    }
    
    choice = choice_map[message.text]
    result = start_proxy(choice)
    bot.send_message(message.chat.id, result, reply_markup=create_keyboard())

@bot.message_handler(func=lambda message: message.text == "إيقاف البروكسي")
def stop_proxy_handler(message):
    """
    معالجة طلب إيقاف البروكسي
    """
    result = stop_proxy()
    bot.send_message(message.chat.id, result)

@bot.message_handler(func=lambda message: message.text == "عرض الحزم المحفوظة")
def show_captured_packets(message):
    """
    عرض الحزم المحفوظة
    """
    if not captured_packets:
        bot.send_message(message.chat.id, "لا توجد حزم محفوظة بعد")
        return
    
    response = f"عدد الحزم المحفوظة: {len(captured_packets)}\n\n"
    for i, packet in enumerate(captured_packets[-10:]):  # عرض آخر 10 حزم فقط
        response += f"{i+1}. {packet['direction']} - {packet['hex'][:50]}...\n"
    
    bot.send_message(message.chat.id, response)

@bot.message_handler(func=lambda message: message.text == "فك تشفير الحزم")
def decode_packets_handler(message):
    """
    معالجة طلب فك تشفير الحزم
    """
    if not captured_packets:
        bot.send_message(message.chat.id, "لا توجد حزم محفوظة لفك التشفير")
        return
    
    # فك تشفير آخر 5 حزم فقط لتجنب الرسائل الطويلة
    recent_packets = captured_packets[-5:]
    
    response = "نتائج فك التشفير:\n\n"
    for i, packet in enumerate(recent_packets):
        response += f"الحزمة {i+1} ({packet['direction']}):\n"
        decoded_data = decode_protobuf(packet['hex'])
        if decoded_data:
            response += format_dict_output(decoded_data) + "\n\n"
        else:
            response += "فشل فك التشفير\n\n"
    
    # إذا كانت النتيجة طويلة جدًا، نقسمها إلى أجزاء
    if len(response) > 4000:
        parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
        for part in parts:
            bot.send_message(message.chat.id, part)
    else:
        bot.send_message(message.chat.id, response)

@bot.message_handler(func=lambda message: message.text == "إحصائيات الحزم")
def packet_stats_handler(message):
    """
    معالجة طلب إحصائيات الحزم
    """
    if not captured_packets:
        bot.send_message(message.chat.id, "لا توجد حزم محفوظة بعد")
        return
    
    total_packets = len(captured_packets)
    client_to_server = len([p for p in captured_packets if "CLIENT→SERVER" in p['direction']])
    server_to_client = total_packets - client_to_server
    
    guild_packets = len([p for p in captured_packets if p['hex'].startswith("1215")])
    squad_packets = len([p for p in captured_packets if p['hex'].startswith("0515")])
    
    response = f"""
إحصائيات الحزم:
إجمالي الحزم: {total_packets}
من العميل إلى الخادم: {client_to_server}
من الخادم إلى العميل: {server_to_client}
حزم الجيلد: {guild_packets}
حزم السكواد: {squad_packets}
الخوادم المتصلة: {len(server_list)}
"""
    bot.send_message(message.chat.id, response)

@bot.message_handler(func=lambda message: True)
def handle_message(message):
    """
    معالجة جميع الرسائل الأخرى
    """
    if message.text == "الغاء":
        bot.send_message(message.chat.id, "تم الإلغاء", reply_markup=create_keyboard())
    else:
        bot.send_message(message.chat.id, "لم أفهم طلبك. استخدم /help للاطلاع على الأوامر المتاحة.")

####################################
# الوظيفة الرئيسية
####################################
def main():
    """
    الوظيفة الرئيسية لتشغيل البوت
    """
    print("Starting Telegram Bot...")
    bot.polling(none_stop=True)

if __name__ == "__main__":
    main()
