from mitmproxy import ctx, websocket
import hmac
import hashlib

def load(l):
    ctx.options.ssl_insecure = True
    ctx.log.info("WebSocket tampering script loaded.")

def calculate_hmac(message, key):
    """计算给定消息的 HMAC"""
    hmac_obj = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
    return hmac_obj.hexdigest()

def websocket_message(flow):
    if flow.websocket.messages:
        message = flow.websocket.messages[-1]

        # 检查消息是否来自客户端并且是文本消息
        if message.from_client and message.is_text:
            original_message = message.content
            ctx.log.info(f"Original message from client: {original_message}")

            # 每次收到消息时询问是否篡改
            user_input = input("Do you want to tamper this message? (y/n): ").strip().lower()
            if user_input == 'y':
                # 让用户输入想要更改的内容
                tampered_message = input("Enter the new message content: ").strip()

                # 询问是否计算 HMAC
                hmac_input = input("Do you want to calculate HMAC for this message? (y/n): ").strip().lower()
                if hmac_input == 'y':
                    # 让用户输入自定义的私钥内容
                    secret_key = input("Enter your custom secret key for HMAC: ").strip()
                    # 计算 HMAC 并附加到消息内容中，用 ":" 分隔
                    message_hmac = calculate_hmac(tampered_message, secret_key)
                    tampered_message_with_hmac = f"{tampered_message}:{message_hmac}"
                    message.content = tampered_message_with_hmac.encode("utf-8")
                    ctx.log.info(f"Tampered message with HMAC sent to server: {tampered_message_with_hmac}")
                else:
                    message.content = tampered_message.encode("utf-8")
                    ctx.log.info(f"Tampered message sent to server: {tampered_message}")
            else:
                ctx.log.info("Message not tampered.")
