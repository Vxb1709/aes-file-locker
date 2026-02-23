import os
import getpass
import config
import logging
import core_crypto
import utils

def main():
    utils.setup_logging()
    logging.info("--- HỆ THỐNG AES FILE LOCKER KHỞI ĐỘNG ---")

    while True:
        print("\n" + "=" * 55)
        print("   HỆ THỐNG AES FILE LOCKER (NHÓM CRYPTO)   ")
        print("=" * 55)
        print("1. Khóa tập tin (Encrypt)")
        print("2. Mở khóa tập tin (Decrypt)")
        print("3. Thoát chương trình (Exit)")
        
        choice = input("\nChọn chức năng (1/2/3): ").strip()
        
        if choice == "3":
            print("[*] Đang đóng hệ thống an toàn. Tạm biệt!")
            logging.info("--- HỆ THỐNG ĐÓNG AN TOÀN ---")
            break
            
        elif choice == "1":
            print("\n--- CHẾ ĐỘ KHÓA TẬP TIN ---")
            raw_path = input("Nhập đường dẫn file cần khóa: ")
            in_file = utils.clean_path(raw_path)
            out_file = in_file + ".enc"
            
            if not utils.validate_io_paths(in_file, out_file):
                continue
                
            if os.path.exists(out_file):
                print(f"[!] Cảnh báo: File '{out_file}' đã tồn tại.")
                if input("Bạn có muốn ghi đè không? (y/n): ").strip().lower() != 'y':
                    print("[-] Đã hủy tác vụ.")
                    continue
            
            while True:
                pwd = getpass.getpass(f"Thiết lập mật khẩu (Ít nhất {config.MIN_PASSWORD_LENGTH} ký tự, sẽ bị ẩn): ")
                if not utils.validate_password_strength(pwd):
                    continue
                    
                pwd_confirm = getpass.getpass("Xác nhận lại mật khẩu: ")
                if pwd != pwd_confirm:
                    print("[-] LỖI: Mật khẩu không khớp! Vui lòng nhập lại.\n")
                else:
                    break
            
            print("[*] Đang khởi tạo bộ máy AES-256-CBC và HMAC-SHA256...")
            try:
                if core_crypto.encrypt_file(in_file, out_file, pwd, progress_callback=utils.draw_progress_bar):
                    print(f"\n[+] THÀNH CÔNG TỐI ĐA: Dữ liệu đã được khóa an toàn tại '{out_file}'")
                    print("[*] Đang hủy tiêu hủy file gốc để bảo vệ an toàn tuyệt đối...")
                    utils.secure_delete(in_file)
                    print(f"[+] Đã xóa vĩnh viễn: '{in_file}'")
                    logging.info(f"Đã tiêu hủy an toàn file gốc: {in_file}")
            except Exception as e:
                print(f"\n[-] LỖI HỆ THỐNG TRONG QUÁ TRÌNH MÃ HÓA: {e}")

        elif choice == "2":
            print("\n--- CHẾ ĐỘ MỞ KHÓA TẬP TIN ---")
            raw_path = input("Nhập đường dẫn file cần mở khóa (.enc): ")
            in_file = utils.clean_path(raw_path)
            out_file = in_file[:-4] if in_file.endswith(".enc") else in_file + ".dec"
            
            if not utils.validate_io_paths(in_file, out_file): continue
                
            if os.path.exists(out_file):
                print(f"[!] Cảnh báo: File '{out_file}' đã tồn tại.")
                if input("Bạn có muốn ghi đè không? (y/n): ").strip().lower() != 'y': continue
            
            attempts = 0
            while attempts < config.MAX_ATTEMPTS:
                lan_thu = config.MAX_ATTEMPTS - attempts
                pwd = getpass.getpass(f"Nhập mật khẩu để mở khóa (Còn {lan_thu} lần thử, sẽ bị ẩn): ")
                
                print("[*] Đang quét toàn vẹn dữ liệu (HMAC Verification)...")
                try:
                    if core_crypto.decrypt_file(in_file, out_file, pwd, progress_callback=utils.draw_progress_bar):
                        print(f"\n[+] THÀNH CÔNG TỐI ĐA: Đã khôi phục dữ liệu gốc ra file '{out_file}'")
                        break 
                    else:
                        attempts += 1
                        print("[-] TỪ CHỐI: Mật khẩu SAI hoặc File đã bị can thiệp!\n")
                except ValueError as ve:
                    print(f"\n[-] LỖI CẤU TRÚC: {ve}")
                    break
                except Exception as e:
                    print(f"\n[-] LỖI HỆ THỐNG BẤT NGỜ: {e}")
                    break
                    
            if attempts == config.MAX_ATTEMPTS:
                print(f"[!] KHÓA TỰ ĐỘNG: Nhập sai quá {config.MAX_ATTEMPTS} lần. Hệ thống từ chối phục vụ!")
                logging.critical(f"🚨 [CẢNH BÁO BẢO MẬT] Phát hiện nhập sai mật khẩu {config.MAX_ATTEMPTS} lần liên tiếp đối với file: {in_file}")

        else:
            print("[-] Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Đã ép buộc dừng hệ thống (Ctrl+C). Tạm biệt!")
        logging.warning("Hệ thống bị ép buộc dừng bởi người dùng (Ctrl+C).")