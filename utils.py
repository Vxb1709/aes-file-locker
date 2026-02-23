import os
import sys
import logging
import config

def setup_logging():
    logging.basicConfig(
        filename=config.LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        encoding='utf-8'
    )
    
def clean_path(path: str) -> str:
    return path.strip(" '\"")

def validate_io_paths(input_path: str, output_path: str) -> bool:
    if not os.path.exists(input_path):
        print(f"[-] LỖI: Không tìm thấy '{input_path}'.")
        return False
        
    if not os.path.isfile(input_path):
        print(f"[-] LỖI: '{input_path}' là một Thư mục. Hệ thống chỉ khóa Tập tin (File)!")
        return False

    if os.path.getsize(input_path) == 0:
        print(f"[-] LỖI: Tập tin rỗng (0 byte). Không có dữ liệu để xử lý.")
        return False

    if not os.access(input_path, os.R_OK):
        print(f"[-] LỖI TỪ CHỐI TRUY CẬP: Không có quyền đọc file gốc '{input_path}'.")
        return False

    out_dir = os.path.dirname(output_path) or '.' 
    if not os.access(out_dir, os.W_OK):
        print(f"[-] LỖI TỪ CHỐI TRUY CẬP: Hệ điều hành không cho phép ghi file vào thư mục '{out_dir}'.")
        return False

    return True

def validate_password_strength(password: str) -> bool:
    if len(password) < config.MIN_PASSWORD_LENGTH:
        print(f"[-] LỖI BẢO MẬT: Mật khẩu quá yếu! Vui lòng nhập ít nhất {config.MIN_PASSWORD_LENGTH} ký tự.")
        return False
    return True

def draw_progress_bar(current: int, total: int, prefix: str = 'Đang xử lý'):
    if total == 0:
        return
        
    percent = 100 * (current / float(total))
    filled_length = int(40 * current // total)
    bar = '█' * filled_length + '-' * (40 - filled_length)
    
    sys.stdout.write(f'\r[*] {prefix} |{bar}| {percent:.1f}%')
    sys.stdout.flush()
    
    if current == total:
        sys.stdout.write('\n')

def secure_delete(file_path: str):
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'wb') as f:
            f.write(b'\x00' * file_size)
        os.remove(file_path)
    except Exception as e:
        print(f"[-] Không thể xóa an toàn file gốc. Chi tiết lỗi: {e}")