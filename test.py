import os
import core_crypto
import utils

TEST_FILE = "dulieu_test.txt"
ENC_FILE = TEST_FILE + ".enc"
DEC_FILE = "dulieu_test_khoiphuc.txt"
TEST_PASSWORD = "MatKhauSieuManh@2026"
TEST_CONTENT = b"Day la du lieu mat cua nhom Cryptography. Khong duoc de lo!"

def run_tests():
    print("="*50)
    print("   KHỞI CHẠY KỊCH BẢN KIỂM THỬ TỰ ĐỘNG (AUTO-TEST)   ")
    print("="*50)

    print("\n[TEST 1] Tạo file dữ liệu gốc...")
    with open(TEST_FILE, 'wb') as f:
        f.write(TEST_CONTENT)
    if os.path.exists(TEST_FILE):
        print("  -> [PASS] Tạo file thành công.")
    else:
        print("  -> [FAIL] Không tạo được file.")
        return

    print("\n[TEST 2] Chạy module Mã hóa (Encrypting)...")
    try:
        core_crypto.encrypt_file(TEST_FILE, ENC_FILE, TEST_PASSWORD)
        if os.path.exists(ENC_FILE):
            print("  -> [PASS] Mã hóa thành công, đã sinh ra file .enc")
        else:
            print("  -> [FAIL] Không tìm thấy file .enc sau khi mã hóa")
    except Exception as e:
        print(f"  -> [FAIL] Lỗi khi mã hóa: {e}")

    print("\n[TEST 3] Chạy module Giải mã (Decrypting)...")
    try:
        core_crypto.decrypt_file(ENC_FILE, DEC_FILE, TEST_PASSWORD)
        
        with open(DEC_FILE, 'rb') as f:
            decrypted_content = f.read()
            
        if decrypted_content == TEST_CONTENT:
            print("  -> [PASS] Giải mã thành công. Dữ liệu khớp 100% bản gốc!")
        else:
            print("  -> [FAIL] Dữ liệu sau giải mã bị sai lệch!")
    except Exception as e:
        print(f"  -> [FAIL] Lỗi khi giải mã: {e}")

    print("\n[TEST 4] Giả lập Hacker can thiệp sửa đổi file .enc...")
    try:
        with open(ENC_FILE, 'r+b') as f:
            f.seek(-1, os.SEEK_END)
            byte_cu = f.read(1)
            f.seek(-1, os.SEEK_END)
            f.write(b'\x00' if byte_cu != b'\x00' else b'\x01')
            
        print("  -> Hacker đã sửa trộm 1 byte dữ liệu!")
        
        print("  -> Hệ thống đang cố gắng giải mã file bị lỗi...")
        is_success = core_crypto.decrypt_file(ENC_FILE, "ketqua_loi.txt", TEST_PASSWORD)
        
        if not is_success:
            print("  -> [PASS] BẢO VỆ THÀNH CÔNG: Chữ ký HMAC đã phát hiện giả mạo và chặn giải mã!")
        else:
            print("  -> [FAIL] LỖI NGHIÊM TRỌNG: Hệ thống vẫn cho phép giải mã file bị hack!")
            
    except Exception as e:
        print(f"  -> [FAIL] Lỗi test: {e}")

    print("\n[*] Đang dọn dẹp các file rác sinh ra trong quá trình test...")
    for file in [TEST_FILE, ENC_FILE, DEC_FILE, "ketqua_loi.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print("[*] Hoàn tất kiểm thử!")

if __name__ == "__main__":
    run_tests()