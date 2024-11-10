import asyncio
import ssl
import websockets
import hmac
import hashlib

# Creating an HMAC Key
HMAC_KEY = b'secret_key_for_hmac'

# # 定义常量
# K = [
#     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
#     0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
#     0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
#     0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
#     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
#     0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
#     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
#     0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
#     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
#     0xc67178f2
# ]

# def right_rotate(value, count):
#     """ 右旋转一个 32 位整数 """
#     return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF

# def sha256(message):
#     """ 手动实现 SHA-256 哈希算法 """
#     # 初始化哈希值
#     h = [
#         0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
#         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
#     ]

#     # 预处理：填充消息
#     message = bytearray(message, 'utf-8')
#     orig_len_in_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
#     message.append(0x80)
#     while (len(message) * 8) % 512 != 448:
#         message.append(0)

#     message += orig_len_in_bits.to_bytes(8, byteorder='big')

#     # 处理消息的每一个 512 位块
#     for i in range(0, len(message), 64):
#         w = [0] * 64
#         for j in range(16):
#             w[j] = int.from_bytes(message[i + j * 4:i + j * 4 + 4], byteorder='big')
#         for j in range(16, 64):
#             s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
#             s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
#             w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

#         a, b, c, d, e, f, g, h_ = h

#         # 主循环
#         for j in range(64):
#             s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
#             ch = (e & f) ^ (~e & g)
#             temp1 = (h_ + s1 + ch + K[j] + w[j]) & 0xFFFFFFFF
#             s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
#             maj = (a & b) ^ (a & c) ^ (b & c)
#             temp2 = (s0 + maj) & 0xFFFFFFFF

#             h_, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

#         # 更新哈希值
#         h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h_])]

#     # 生成最终的哈希值
#     return ''.join(f'{i:08x}' for i in h)

# def hmac_sha256(key, message):
#     """ 手动实现 HMAC-SHA256 """
#     block_size = 64

#     # 如果密钥长度超过块大小，使用 SHA-256 散列密钥
#     if len(key) > block_size:
#         key = bytes.fromhex(sha256(key))

#     # 用 0 补齐密钥到块大小
#     key = key.ljust(block_size, b'\x00')

#     o_key_pad = bytes((x ^ 0x5c) for x in key)
#     i_key_pad = bytes((x ^ 0x36) for x in key)

#     # 计算 HMAC
#     inner_hash = sha256((i_key_pad + message).decode('latin1'))
#     return sha256((o_key_pad + bytes.fromhex(inner_hash)).decode('latin1'))

# # 重新实现的 create_hmac 函数，不依赖 hashlib
# def create_hmac(message, key):
#     """ 手动实现 HMAC """
#     return hmac_sha256(key, message.encode('utf-8'))


def create_hmac(message):
    return hmac.new(HMAC_KEY, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, client_hmac):
    calculated_hmac = create_hmac(message)
    print(calculated_hmac)
    print(client_hmac)
    return hmac.compare_digest(calculated_hmac, client_hmac)

async def handle_message(websocket, path):
    async for message in websocket:
        print(f"Received data: {message}")
        try:
            msg, client_hmac = message.split(':')
            if verify_hmac(msg, client_hmac):
                print(f"Verified message: {msg}")
                await websocket.send("Message verified")
            else:
                print("Verification failed")
                await websocket.send("Message verification failed")
        except ValueError:
            print("Invalid data format received")
            await websocket.send("Invalid format")

# Starting a server with WebSockets and SSL
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
start_server = websockets.serve(handle_message, "127.0.0.1", 4455, ssl=ssl_context)

asyncio.get_event_loop().run_until_complete(start_server)
print("WebSocket server started on wss://localhost:4455")
asyncio.get_event_loop().run_forever()
