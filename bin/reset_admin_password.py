import sqlite3
import os
from dotenv import load_dotenv
import argparse

# 获取 openvpn-webui 根目录
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 加载 .env 文件
load_dotenv(os.path.join(ROOT_DIR, 'config', '.env'))

# 默认配置（从 .env 文件加载，必要时提供内部路径的回退值）
DATABASE_PATH = os.getenv('DATABASE_PATH', os.path.join(ROOT_DIR, 'openvpn.db'))
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')

def reset_admin_password(new_password):
    try:
        # 连接数据库
        with sqlite3.connect(DATABASE_PATH) as conn:
            c = conn.cursor()
            # 检查管理员账户是否存在
            c.execute('SELECT id FROM users WHERE username = ? AND role = ?', (ADMIN_USERNAME, 'admin'))
            user = c.fetchone()
            
            if not user:
                print(f"错误: 未找到管理员账户 '{ADMIN_USERNAME}'")
                return False
            
            # 更新密码
            c.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, user[0]))
            conn.commit()
            print(f"成功: 管理员 '{ADMIN_USERNAME}' 的密码已重置为 '{new_password}'")
            return True
            
    except sqlite3.Error as e:
        print(f"数据库错误: {str(e)}")
        return False
    except Exception as e:
        print(f"错误: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="重置 OpenVPN WebUI 管理员密码")
    parser.add_argument('--new-password', required=True, help="新管理员密码")
    args = parser.parse_args()
    
    if reset_admin_password(args.new_password):
        print("密码重置完成，请使用新密码登录 WebUI")
    else:
        print("密码重置失败，请检查错误信息")

if __name__ == '__main__':
    main()