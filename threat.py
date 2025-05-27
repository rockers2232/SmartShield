import serial
import json
import re
import msvcrt
import matplotlib.pyplot as plt
import numpy as np
import asyncio
from bleak import BleakScanner

PORT = "COM4"
BAUDRATE = 9600

block_id = ["scam@fraud.com", "hacker@unknown.com", "fakebank@phishmail.org", "offers@scamdeal.net", "admin@untrustedmail.io", "lottery@cheatmail.com"]
block_domain = ["spam.net", "phishmail.org", "scamdeal.net", "untrustedmail.io", "malicious.info", "fakenews.online", "tricklink.biz"]

sender_id = ["abc@gmail.com", "support@yahoo.com", "alerts@bankofindia.com", "info@securemail.com", "notifications@yourservice.in", "help@officialsite.org"]
domain = ["gmail.com", "yahoo.com", "bankofindia.com", "officialsite.org", "yourservice.in", "securemail.com"]
suspecious = ["urgent", "click here", "free", "password", "reset", "login", "verify", "confirm", "urgently", "offer", "win", "limited time", "claim now", "exclusive", "act fast", "access blocked", "security alert"]
impo = ["bank", "otp", "transaction", "account", "balance", "invoice", "payment", "debit", "credit", "security code", "billing", "transfer"]

spam_list = []
sms_log = []
mac_lookup = {}
blocked_messages = []

#=======================member-2=============================
async def scan_ble_devices():
    print("🔍 Scanning nearby Bluetooth devices...")
    devices = await BleakScanner.discover(timeout=5)
    named_devices = [d for d in devices if d.name]

    if not named_devices:
        print("❌ No BLE devices found with names.")
        return None, None

    print("✅ BLE devices found:")
    for i, device in enumerate(named_devices, 1):
        print(f"{i}. {device.name} ({device.address})")

    while True:
        try:
            choice = int(input("Enter device number to connect: "))
            if 1 <= choice <= len(named_devices):
                selected_device = named_devices[choice - 1]
                print(f"🔗 Connected to {selected_device.name} ({selected_device.address})")
                return selected_device.name.lower(), selected_device.address
            else:
                print("⚠️ Invalid choice. Try again.")
        except ValueError:
            print("⚠️ Please enter a valid number.")

def extract_fields(message):
    try:
        data = json.loads(message)
        return data.get("sender", ""), data.get("subject", ""), data.get("content", "")
    except:
        pass
    if message.count(",") >= 2:
        parts = [p.strip() for p in message.split(",", 2)]
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
    return "", "", message.strip()


#==============================member-1=================================
def get_domain(sender):
    match = re.search(r"@([\w.-]+)", sender)
    return match.group(1) if match else ""

def detect(sender, subject, content):
    reasons = []
    if sender not in sender_id:
        reasons.append("❌ Untrusted sender")
    matches = re.findall(r"@([\w.-]+)", sender)
    if not matches or matches[0] not in domain:
        reasons.append("⚠️ Suspicious domain")
    for word in suspecious:
        if word in subject or word in content:
            reasons.append(f"⚠️ Keyword detected: '{word}'")
            break
    return reasons

def priority(content):
    for word in impo:
        if word in content.lower():
            return True
    return False


#===========================member-3====================================
async def main():
    selected_name, connected_mac = await scan_ble_devices()
    if not connected_mac:
        print("No device selected. Exiting...")
        return

    try:
        with serial.Serial(PORT, BAUDRATE, timeout=1) as bt:
            print(f"\n✅ Listening on {PORT}...")
            messagebox = None
            message_log = None

            while True:
                if bt.in_waiting:
                    raw = bt.readline().decode("utf-8").strip()
                    if raw:
                        sender, subject, content = extract_fields(raw)
                        subject = subject.lower()
                        content = content.lower()

                        domain_check = get_domain(sender)
                        mac = connected_mac if connected_mac else "Unknown MAC"

                        if sender in block_id or domain_check in block_domain:
                            print(f"\n⛔ Message from {sender} BLOCKED!")
                            print(f"   MAC: {mac}")
                            blocked_messages.append((sender, subject, content, mac))
                            continue

                        if not sender or not subject:
                            if content and priority(content):
                                messagebox = ("<unknown>", "<important>", content)
                                message_log = "<unknown>"
                                sms_log.append(content)
                                print("\n📩 [SMS] Important Message Received")
                                continue
                            else:
                                print(f"\n⚠️ Incomplete message received → {raw}")
                            continue

                        reasons = detect(sender, subject, content)

                        if reasons:
                            spam_list.append(reasons)
                            print(f"\n❌ Spam Alert ↓")
                            print(f"From: {sender}")
                            print(f"Subject: {subject}")
                            print(f"Content: {content}")
                            for r in reasons:
                                print("  *", r)
                            print(f"🔒 MAC: {mac}")

                            is_suspicious_only = (
                                sender in sender_id and
                                get_domain(sender) in domain and
                                any("Keyword detected" in r for r in reasons)
                            )
                            if is_suspicious_only:
                                block_decision = input("\n⚠️ Suspicious content. Block sender? ").strip().lower()
                                if block_decision == "yes":
                                    domain_extracted = get_domain(sender)
                                    if sender not in block_id:
                                        block_id.append(sender)
                                        print(f"✅ Sender '{sender}' blocked.")
                                        print(f"   MAC: {mac}")
                                    if domain_extracted and domain_extracted not in block_domain:
                                        block_domain.append(domain_extracted)
                                        print(f"✅ Domain '{domain_extracted}' blocked.")

                            messagebox = (sender, subject, content)
                            message_log = sender
                        else:
                            messagebox = (sender, subject, content)
                            message_log = None
                            print("\n📥 Inbox: New message received")

                if messagebox and bt.in_waiting == 0:
                    if msvcrt.kbhit():
                        user_input = input().strip().lower()
                        if user_input == "ok":
                            s, subj, cont = messagebox
                            mac = connected_mac if connected_mac else "Unknown MAC"
                            print(f"\n🗂️ Inbox Message")
                            print(f"From: {s}")
                            print(f"Subject: {subj}")
                            print(f"Content: {cont}")
                            #print(f"MAC: {mac}")

                            if message_log and message_log not in sender_id:
                                block_decision = input("\n⚠️ Block this sender? ").strip().lower()
                                if block_decision == "yes":
                                    domain_extracted = get_domain(message_log)
                                    if message_log not in block_id:
                                        block_id.append(message_log)
                                        print(f"✅ Sender '{message_log}' blocked. MAC: {mac}")
                                    if domain_extracted and domain_extracted not in block_domain:
                                        block_domain.append(domain_extracted)
                                        print(f"✅ Domain '{domain_extracted}' blocked.")
                            messagebox = None
                            message_log = None

                        elif user_input == "view blocked":
                            if not blocked_messages:
                                print("📭 No blocked messages.")
                            else:
                                print(f"\n🔐 Blocked Messages:")
                                for b_sender, b_subject, b_content, b_mac in blocked_messages:
                                    print(f"\nFrom: {b_sender}")
                                    print(f"Subject: {b_subject}")
                                    print(f"Content: {b_content}")
                                    print(f"MAC: {b_mac}")

    except serial.SerialException:
        print("❌ Connection failed!")
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")


#===========================member-4===================================
    if spam_list:
        threat_counter = {
            "Untrusted Sender": 0,
            "Suspicious Domain": 0,
            "Keyword Detected": 0
        }
        for reasons in spam_list:
            for r in reasons:
                if "Untrusted sender" in r:
                    threat_counter["Untrusted Sender"] += 1
                if "Suspicious domain" in r:
                    threat_counter["Suspicious Domain"] += 1
                if "Keyword detected" in r.lower():
                    threat_counter["Keyword Detected"] += 1

        labels = list(threat_counter.keys())
        values = list(threat_counter.values())
        y = np.arange(len(labels))

        plt.figure(figsize=(8, 5))
        bars = plt.barh(y, values, color=["red", "blue", "orange"])

        plt.xlabel("Number of Times Detected")
        plt.ylabel("Threat Type")
        plt.title("Threat Detection Summary")
        plt.yticks(y, labels)
        plt.grid(axis='x')

        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.3, bar.get_y() + bar.get_height() / 2, str(int(width)), va='center')

        plt.tight_layout()
        plt.show()
    else:
        print("📭 No spam threats to show.")

asyncio.run(main())
