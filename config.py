# =====================================================================
# MODULE: config.py
# CHỨC NĂNG: LƯU TRỮ CÁC HẰNG SỐ MẬT MÃ VÀ CẤU HÌNH HỆ THỐNG
# =====================================================================

"""
Lưu ý cho Báo cáo:
Việc tách riêng cấu hình giúp dễ dàng bảo trì và nâng cấp. 
Ví dụ: 5 năm sau, khi máy tính mạnh lên, ta chỉ cần vào đây đổi 
PBKDF2_ITERATIONS thành 5.000.000 mà không cần đụng vào lõi mật mã.
"""

# --- 1. THÔNG SỐ THUẬT TOÁN AES & HMAC (NIST STANDARDS) ---
AES_BLOCK_SIZE = 16         # Kích thước khối AES chuẩn (16 bytes = 128 bits)
KEY_SIZE = 32               # Kích thước khóa cho AES-256 (32 bytes = 256 bits)
MAC_SIZE = 32               # Kích thước chữ ký HMAC-SHA256 (32 bytes = 256 bits)
SALT_SIZE = 16              # Kích thước Muối (Salt) ngẫu nhiên (16 bytes)
IV_SIZE = 16                # Kích thước Vector khởi tạo (IV) ngẫu nhiên (16 bytes)

# --- 2. CẤU HÌNH SINH KHÓA (KEY DERIVATION FUNCTION) ---
PBKDF2_ITERATIONS = 1_000_000 # 1 triệu vòng lặp. Tiêu chuẩn hiện đại chống tấn công bằng GPU.
DERIVED_KEY_LENGTH = 64       # Tổng chiều dài khóa cần đúc (32 bytes AES + 32 bytes HMAC)

# --- 3. TỐI ƯU HÓA BỘ NHỚ (MEMORY OPTIMIZATION) ---
# Cơ chế Streaming: Đọc/ghi luồng dữ liệu theo từng khối 64KB (chia hết cho 16 bytes).
# Đảm bảo phần mềm có thể khóa file video 50GB trên máy tính chỉ có 2GB RAM.
CHUNK_SIZE = 64 * 1024      

# --- 4. CHÍNH SÁCH BẢO MẬT & UX (SECURITY POLICIES & UX) ---
MAX_ATTEMPTS = 5            # Giới hạn số lần thử giải mã để chống Brute-force tự động
MIN_PASSWORD_LENGTH = 8     # Yêu cầu độ mạnh mật khẩu (Entropy) tối thiểu
TMP_EXTENSION = ".tmp"      # Đuôi file tạm sử dụng cho cơ chế Ghi nguyên tử (Atomic Write)
LOG_FILE = "crypto_tracking.log" # File lưu vết hệ thống