import os
import shutil
import logging
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import config

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode('utf-8'), 
        salt, 
        dkLen=config.DERIVED_KEY_LENGTH, 
        count=config.PBKDF2_ITERATIONS, 
        hmac_hash_module=SHA256
    )

def encrypt_file(input_path: str, output_path: str, password: str, progress_callback=None) -> bool:
    tmp_path = output_path + config.TMP_EXTENSION
    file_size = os.path.getsize(input_path)
    logging.info(f"=== BẮT ĐẦU MÃ HÓA: {input_path} ===")

    salt = get_random_bytes(config.SALT_SIZE)
    iv = get_random_bytes(config.IV_SIZE)
    logging.info(f"[BƯỚC 1] Khởi tạo tham số ngẫu nhiên -> Salt: {salt.hex()} | IV: {iv.hex()}")

    key_material = derive_key(password, salt)
    aes_key, hmac_key = key_material[:32], key_material[32:]
    logging.info(f"[BƯỚC 2] Đúc khóa PBKDF2 ({config.PBKDF2_ITERATIONS} vòng) -> AES Key: {aes_key.hex()} | HMAC Key: {hmac_key.hex()}")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)
    
    bytes_processed = 0
    try:
        logging.info(f"[BƯỚC 3] Đang mã hóa luồng dữ liệu (Chunk: {config.CHUNK_SIZE//1024}KB)...")
        with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(iv)
            
            while True:
                chunk = f_in.read(config.CHUNK_SIZE)
                if len(chunk) < config.CHUNK_SIZE:
                    padded_chunk = pad(chunk, config.AES_BLOCK_SIZE)
                    encrypted_chunk = cipher.encrypt(padded_chunk)
                    hmac_obj.update(encrypted_chunk)
                    f_out.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    if progress_callback: progress_callback(bytes_processed, file_size)
                    break
                else:
                    encrypted_chunk = cipher.encrypt(chunk)
                    hmac_obj.update(encrypted_chunk)
                    f_out.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    if progress_callback: progress_callback(bytes_processed, file_size)
            final_hmac = hmac_obj.digest()        
            f_out.write(hmac_obj.digest())
            logging.info(f"[BƯỚC 4] Chữ ký toàn vẹn (HMAC-SHA256) sinh ra: {final_hmac.hex()}")
            
        try:
            shutil.copystat(input_path, tmp_path)
        except Exception:
            pass
        
        os.replace(tmp_path, output_path)
        logging.info(f"=== HOÀN TẤT MÃ HÓA THÀNH CÔNG: {output_path} ===")
        return True
        
    except Exception as e:
        logging.error(f"[LỖI] Mã hóa thất bại: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise e

def decrypt_file(encrypted_path: str, output_path: str, password: str, progress_callback=None) -> bool:
    file_size = os.path.getsize(encrypted_path)
    tmp_path = output_path + config.TMP_EXTENSION
    logging.info(f"=== BẮT ĐẦU GIẢI MÃ: {encrypted_path} ===")
    
    if file_size < (config.SALT_SIZE + config.IV_SIZE + config.MAC_SIZE + config.AES_BLOCK_SIZE):
        logging.error("[LỖI] Cấu trúc file quá nhỏ, bị hỏng.")
        raise ValueError("File quá nhỏ, cấu trúc dữ liệu bị hỏng.")

    with open(encrypted_path, 'rb') as f_in:
        salt = f_in.read(config.SALT_SIZE)
        iv = f_in.read(config.IV_SIZE)
        
        f_in.seek(-config.MAC_SIZE, os.SEEK_END)
        hmac_goc = f_in.read(config.MAC_SIZE)
        logging.info(f"[BƯỚC 1] Trích xuất siêu dữ liệu -> Salt: {salt.hex()} | IV: {iv.hex()} | HMAC Gốc: {hmac_goc.hex()}")

        key_material = derive_key(password, salt)
        aes_key, hmac_key = key_material[:32], key_material[32:]
        logging.info(f"[BƯỚC 2] Tái tạo khóa thành công từ Mật khẩu người dùng.")
        
        hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)
        ciphertext_size = file_size - config.SALT_SIZE - config.IV_SIZE - config.MAC_SIZE
        f_in.seek(config.SALT_SIZE + config.IV_SIZE)
        
        bytes_to_verify = ciphertext_size
        while bytes_to_verify > 0:
            chunk = f_in.read(min(config.CHUNK_SIZE, bytes_to_verify))
            hmac_obj.update(chunk)
            bytes_to_verify -= len(chunk)

        hmac_moi = hmac_obj.digest()
        logging.info(f"[BƯỚC 3] HMAC tự tính toán để đối chiếu: {hmac_moi.hex()}")
            
        try:
            hmac_obj.verify(hmac_goc)
            logging.info("[BƯỚC 4] KẾT QUẢ: Xác thực HMAC THÀNH CÔNG. File an toàn, cho phép giải mã.")
        except ValueError:
            logging.warning("[CẢNH BÁO] Xác thực HMAC THẤT BẠI. File bị sửa đổi hoặc sai mật khẩu!")
            return False
            
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        f_in.seek(config.SALT_SIZE + config.IV_SIZE)
        bytes_to_decrypt = ciphertext_size
        bytes_processed = 0
        
        try:
            with open(tmp_path, 'wb') as f_out:
                while bytes_to_decrypt > 0:
                    read_size = min(config.CHUNK_SIZE, bytes_to_decrypt)
                    chunk = f_in.read(read_size)
                    bytes_to_decrypt -= len(chunk)
                    
                    decrypted_chunk = cipher.decrypt(chunk)
                    if bytes_to_decrypt == 0:
                        f_out.write(unpad(decrypted_chunk, config.AES_BLOCK_SIZE))
                    else:
                        f_out.write(decrypted_chunk)
                        
                    bytes_processed += read_size
                    if progress_callback: progress_callback(bytes_processed, ciphertext_size)
                    
            try:
                shutil.copystat(encrypted_path, tmp_path)
            except Exception:
                pass
            
            os.replace(tmp_path, output_path)
            logging.info(f"=== HOÀN TẤT GIẢI MÃ THÀNH CÔNG: {output_path} ===")
            return True
            
        except Exception as e:
            logging.error(f"[LỖI] Quá trình giải mã thất bại: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise e