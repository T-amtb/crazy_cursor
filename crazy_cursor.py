import json
import logging
import os
import platform
import sqlite3
import subprocess
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import psutil
import requests
import base64
import winreg
import uuid
import hashlib
import sys
from dotenv import load_dotenv

# 设置控制台输出编码
if platform.system() == 'Windows':
    # Windows系统下设置控制台编码为UTF-8
    os.system('chcp 65001')
    # 清除 chcp 命令输出
    os.system('cls')

# 确保输出流使用UTF-8编码
sys.stdout.reconfigure(encoding='utf-8')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# 加载 .env 文件
def load_env_config():
    """加载环境变量配置"""
    env_path = Path('.env')
    try:
        if env_path.exists():
            load_dotenv(env_path)
            logger.debug("已加载 .env 配置文件")
    except Exception as e:
        logger.debug(f"加载 .env 配置文件失败: {e}")

# 常量配置
class Config:
    """配置常量类"""
    # 从环境变量获取配置，如果不存在则使用默认值
    API_URL = os.getenv('CURSOR_API_URL', "https://cursor.ccopilot.org/api/get_next_token.php")
    ACCESS_CODE = os.getenv('CURSOR_ACCESS_CODE', "")
    PROCESS_TIMEOUT = 5
    CURSOR_PROCESS_NAMES = ['cursor.exe', 'cursor']
    DB_KEYS = {
        'email': 'cursorAuth/cachedEmail',
        'access_token': 'cursorAuth/accessToken',
        'refresh_token': 'cursorAuth/refreshToken'
    }
    MIN_PATCH_VERSION = "0.45.0"  # 需要 patch 的版本
    VERSION_PATTERN = r"^\d+\.\d+\.\d+$"  # 版本号格式
    SCRIPT_VERSION = "2025020801"  # 脚本版本号
    
    # 新增使用量查询相关配置
    NAME_LOWER = "cursor"
    NAME_CAPITALIZE = "Cursor"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36"
    BASE_HEADERS = {
        "User-Agent": USER_AGENT
    }


@dataclass
class TokenData:
    """Token数据类"""
    mac_machine_id: str
    machine_id: str
    dev_device_id: str
    email: str
    token: str

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'TokenData':
        """从字典创建TokenData实例"""
        return cls(
            mac_machine_id=data['mac_machine_id'],
            machine_id=data['machine_id'],
            dev_device_id=data['dev_device_id'],
            email=data['email'],
            token=data['token']
        )


class FilePathManager:
    """文件路径管理器"""

    @staticmethod
    def get_storage_path() -> Path:
        """获取storage.json文件路径"""
        system = platform.system()
        if system == "Windows":
            return Path(os.getenv('APPDATA')) / 'Cursor' / 'User' / 'globalStorage' / 'storage.json'
        elif system == "Darwin":
            return Path.home() / 'Library' / 'Application Support' / 'Cursor' / 'User' / 'globalStorage' / 'storage.json'
        elif system == "Linux":
            return Path.home() / '.config' / 'Cursor' / 'User' / 'globalStorage' / 'storage.json'
        raise OSError(f"不支持的操作系统: {system}")

    @staticmethod
    def get_db_path() -> Path:
        """获取数据库文件路径"""
        system = platform.system()
        if system == "Windows":
            return Path(os.getenv('APPDATA')) / 'Cursor' / 'User' / 'globalStorage' / 'state.vscdb'
        elif system == "Darwin":
            return Path.home() / 'Library' / 'Application Support' / 'Cursor' / 'User' / 'globalStorage' / 'state.vscdb'
        elif system == "Linux":
            return Path.home() / '.config' / 'Cursor' / 'User' / 'globalStorage' / 'state.vscdb'
        raise OSError(f"不支持的操作系统: {system}")

    @staticmethod
    def get_cursor_app_paths() -> Tuple[Path, Path]:
        """获取Cursor应用相关路径"""
        system = platform.system()

        if system == "Windows":
            base_path = Path(os.getenv("LOCALAPPDATA", "")) / "Programs" / "Cursor" / "resources" / "app"
        elif system == "Darwin":
            base_path = Path("/Applications/Cursor.app/Contents/Resources/app")
        elif system == "Linux":
            # 检查可能的Linux安装路径
            possible_paths = [
                Path("/opt/Cursor/resources/app"),
                Path("/usr/share/cursor/resources/app")
            ]
            base_path = next((p for p in possible_paths if p.exists()), None)
            if not base_path:
                raise OSError("在Linux系统上未找到Cursor安装路径")
        else:
            raise OSError(f"不支持的操作系统: {system}")

        return base_path / "package.json", base_path / "out" / "main.js"

    @staticmethod
    def get_update_config_path() -> Optional[Path]:
        """获取更新配置文件路径"""
        system = platform.system()
        if system == "Windows":
            return Path(os.getenv('LOCALAPPDATA')) / 'Programs' / 'Cursor' / 'resources' / 'app-update.yml'
        elif system == "Darwin":
            return Path('/Applications/Cursor.app/Contents/Resources/app-update.yml')
        return None


class FilePermissionManager:
    """文件权限管理器"""

    @staticmethod
    def make_file_writable(file_path: Union[str, Path]) -> None:
        """修改文件权限为可写"""
        file_path = Path(file_path)
        if platform.system() == "Windows":
            subprocess.run(['attrib', '-R', str(file_path)], check=True)
        else:
            os.chmod(file_path, 0o666)

    @staticmethod
    def make_file_readonly(file_path: Union[str, Path]) -> None:
        """修改文件权限为只读"""
        file_path = Path(file_path)
        if platform.system() == "Windows":
            subprocess.run(['attrib', '+R', str(file_path)], check=True)
        else:
            os.chmod(file_path, 0o444)


class CursorAuthManager:
    """Cursor认证信息管理器"""

    def __init__(self):
        self.db_path = FilePathManager.get_db_path()

    def update_auth(self, email: Optional[str] = None,
                    access_token: Optional[str] = None,
                    refresh_token: Optional[str] = None) -> bool:
        """更新或插入Cursor的认证信息"""
        updates: List[Tuple[str, str]] = []
        if email is not None:
            updates.append((Config.DB_KEYS['email'], email))
        if access_token is not None:
            updates.append((Config.DB_KEYS['access_token'], access_token))
        if refresh_token is not None:
            updates.append((Config.DB_KEYS['refresh_token'], refresh_token))

        if not updates:
            logger.info("没有提供任何要更新的值")
            return False

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for key, value in updates:
                    cursor.execute("SELECT 1 FROM itemTable WHERE key = ?", (key,))
                    exists = cursor.fetchone() is not None

                    if exists:
                        cursor.execute("UPDATE itemTable SET value = ? WHERE key = ?", (value, key))
                    else:
                        cursor.execute("INSERT INTO itemTable (key, value) VALUES (?, ?)", (key, value))
                    logger.info(f"成功{'更新' if exists else '插入'} {key.split('/')[-1]}")
                return True
        except sqlite3.Error as e:
            logger.error(f"数据库错误: {e}")
            return False
        except Exception as e:
            logger.error(f"发生错误: {e}")
            return False

    def get_auth_token(self) -> Optional[str]:
        """获取数据库中存储的access token"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM itemTable WHERE key = ?", 
                             (Config.DB_KEYS['access_token'],))
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
            logger.error(f"获取token时发生数据库错误: {e}")
            return None
        except Exception as e:
            logger.error(f"获取token时发生错误: {e}")
            return None

class CursorManager:
    """Cursor管理器"""

    @staticmethod
    def reset_cursor_id(token_data: TokenData) -> bool:
        """重置Cursor ID"""
        storage_path = FilePathManager.get_storage_path()
        if not storage_path.exists():
            logger.warning(f"未找到文件: {storage_path}")
            return False

        try:
            FilePermissionManager.make_file_writable(storage_path)
            data = json.loads(storage_path.read_text(encoding='utf-8'))

            data.update({
                "telemetry.macMachineId": token_data.mac_machine_id,
                "telemetry.machineId": token_data.machine_id,
                "telemetry.devDeviceId": token_data.dev_device_id
            })

            storage_path.write_text(json.dumps(data, indent=4))
            FilePermissionManager.make_file_readonly(storage_path)
            logger.info("Cursor 机器码已成功修改")
            return True
        except Exception as e:
            logger.error(f"重置 Cursor 机器码时发生错误: {e}")
            return False

    @staticmethod
    def exit_cursor() -> bool:
        """安全退出Cursor进程"""
        try:
            logger.info("开始退出 Cursor...")
            cursor_processes = [
                proc for proc in psutil.process_iter(['pid', 'name'])
                if proc.info['name'].lower() in Config.CURSOR_PROCESS_NAMES
            ]

            if not cursor_processes:
                logger.info("未发现运行中的 Cursor 进程")
                return True

            # 温和地请求进程终止
            for proc in cursor_processes:
                try:
                    if proc.is_running():
                        proc.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # 等待进程终止
            start_time = time.time()
            while time.time() - start_time < Config.PROCESS_TIMEOUT:
                still_running = [p for p in cursor_processes if p.is_running()]
                if not still_running:
                    logger.info("所有 Cursor 进程已正常关闭")
                    return True
                time.sleep(0.5)

            still_running = [p for p in cursor_processes if p.is_running()]
            if still_running:
                process_list = ", ".join(str(p.pid) for p in still_running)
                logger.warning(f"以下进程未能在规定时间内关闭: {process_list}")
                return False

            return True
        except Exception as e:
            logger.error(f"关闭 Cursor 进程时发生错误: {e}")
            return False


class TokenManager:
    """Token管理器"""

    @staticmethod
    def fetch_token_data(access_code: str, cursor_version: str) -> Optional[TokenData]:
        """获取Token数据"""
        logger.info("正在获取 Token 数据...")
        try:
            params = {
                "accessCode": access_code,
                "cursorVersion": cursor_version,
                "scriptVersion": Config.SCRIPT_VERSION
            }
            proxies = UsageManager.get_proxy()
            # logger.info(f"当前使用的代理设置: {proxies}")
                        
            # response = requests.get(Config.API_URL, params=params, proxies=proxies)
            response = requests.get(Config.API_URL, params=params)
            data = response.json()

            # 检查响应数据
            if data.get("code") == 0:
                token_data = data.get("data")
                print(token_data)
                if token_data:
                    logger.info("成功获取 Token 数据")
                    return TokenData.from_dict(token_data)

            logger.warning(f"获取 Token 失败: {data.get('message', '未知错误')}")
            return None
        except requests.RequestException:
            logger.error("获取 Token 数据失败,请检查网络连接是否正常,如果使用代理请确认代理是否配置正确")
            return None
        except Exception as e:
            logger.error(f"获取 Token 数据时发生错误: {e}")
            return None

    @staticmethod
    def update_token(token_data: TokenData) -> bool:
        """更新Cursor的token信息"""
        try:
            # 更新机器ID
            if not CursorManager.reset_cursor_id(token_data):
                return False

            # 更新认证信息
            auth_manager = CursorAuthManager()
            if not auth_manager.update_auth(email=token_data.email, access_token=token_data.token,
                                            refresh_token=token_data.token):
                logger.error("更新 Token 时发生错误")
                return False

            logger.info(f"成功更新 Cursor 认证信息! 邮箱: {token_data.email}")
            return True
        except Exception as e:
            logger.error(f"更新 Token 时发生错误: {e}")
            return False


class Utils:
    """工具类"""

    @staticmethod
    def version_check(version: str, min_version: str = "", max_version: str = "") -> bool:
        """
        版本号检查

        Args:
            version: 当前版本号
            min_version: 最小版本号要求
            max_version: 最大版本号要求

        Returns:
            bool: 版本号是否符合要求
        """
        try:
            if not re.match(Config.VERSION_PATTERN, version):
                logger.error(f"无效的版本号格式: {version}")
                return False

            def parse_version(ver: str) -> Tuple[int, ...]:
                return tuple(map(int, ver.split(".")))

            current = parse_version(version)

            if min_version and current < parse_version(min_version):
                return False

            if max_version and current > parse_version(max_version):
                return False

            return True

        except Exception as e:
            logger.error(f"版本检查失败: {str(e)}")
            return False

    @staticmethod
    def check_files_exist(pkg_path: Path, main_path: Path) -> bool:
        """
        检查文件是否存在

        Args:
            pkg_path: package.json 文件路径
            main_path: main.js 文件路径

        Returns:
            bool: 检查是否通过
        """
        for file_path in [pkg_path, main_path]:
            if not file_path.exists():
                logger.error(f"文件不存在: {file_path}")
                return False
        return True


class CursorPatcher:
    """Cursor补丁管理器"""

    @staticmethod
    def check_version(version: str) -> bool:
        return Utils.version_check(version, min_version=Config.MIN_PATCH_VERSION)

    @staticmethod
    def patch_main_js(main_path: Path) -> bool:
        """
        修改main.js文件以移除机器码检查

        Args:
            main_path: main.js文件路径

        Returns:
            bool: 修改是否成功
        """
        try:
            # 读取文件内容
            content = main_path.read_text(encoding="utf-8")

            # 定义需要替换的模式
            patterns = {
                r"async getMachineId\(\)\{return [^??]+\?\?([^}]+)\}": r"async getMachineId(){return \1}",
                r"async getMacMachineId\(\)\{return [^??]+\?\?([^}]+)\}": r"async getMacMachineId(){return \1}"
            }

            # 检查是否存在需要修复的代码
            found_patterns = False
            for pattern in patterns.keys():
                if re.search(pattern, content):
                    found_patterns = True
                    break

            if not found_patterns:
                logger.info("未发现需要修复的代码，可能已经修复或不支持当前版本")
                return True

            # 执行替换
            for pattern, replacement in patterns.items():
                content = re.sub(pattern, replacement, content)

            # 写入修改后的内容
            FilePermissionManager.make_file_writable(main_path)
            main_path.write_text(content, encoding="utf-8")
            FilePermissionManager.make_file_readonly(main_path)
            logger.info("成功 Patch Cursor 机器码")
            return True

        except Exception as e:
            logger.error(f"Patch Cursor 机器码时发生错误: {e}")
            return False


class UpdateManager:
    """更新管理器"""

    @staticmethod
    def disable_auto_update_main():
        """禁用自动更新"""
        if not UpdateManager.check_auto_upload_file_exist():
            logger.info("暂不支持自动禁用更新，请手动操作，参考：https://linux.do/t/topic/297886")
            return

        if UpdateManager.check_auto_upload_file_empty():
            return

        logger.info("（建议禁用自动更新）是否要禁用 Cursor 自动更新？(y/n)")
        if input().strip().lower() == 'y':
            UpdateManager.disable_auto_update()

    @staticmethod
    def check_auto_upload_file_exist() -> bool:
        """检查更新配置文件是否存在"""
        update_path = FilePathManager.get_update_config_path()
        return update_path and update_path.exists()

    @staticmethod
    def check_auto_upload_file_empty() -> bool:
        """检查更新配置文件是否为空"""
        update_path = FilePathManager.get_update_config_path()
        return update_path and update_path.stat().st_size == 0

    @staticmethod
    def disable_auto_update() -> bool:
        """禁用自动更新"""
        update_path = FilePathManager.get_update_config_path()
        if not update_path:
            logger.error("无法获取更新配置文件路径")
            return False

        if UpdateManager.check_auto_upload_file_empty():
            logger.info("更新配置文件已经为空，无需重复操作")
            return True

        try:
            # 创建备份
            backup_path = update_path.with_suffix('.bak')
            if not backup_path.exists():
                import shutil
                shutil.copy2(update_path, backup_path)
                logger.info(f"已创建配置文件备份: {backup_path}")

            # 清空文件内容
            FilePermissionManager.make_file_writable(update_path)
            update_path.write_text("")
            FilePermissionManager.make_file_readonly(update_path)

            logger.info("已成功禁用自动更新")
            return True

        except Exception as e:
            logger.error(f"禁用自动更新时发生错误: {e}")
            return False


class UsageManager:
    """使用量管理器"""
    
    @staticmethod
    def get_proxy():
        """获取系统代理设置"""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                
                if proxy_enable and proxy_server:
                    proxy_parts = proxy_server.split(":")
                    if len(proxy_parts) == 2:
                        return {"http": f"http://{proxy_server}", "https": f"http://{proxy_server}"}
        except WindowsError:
            pass
        return {"http": None, "https": None}

    @staticmethod
    def extract_user_id_from_jwt(token: str) -> str:
        """从JWT中提取用户ID"""
        try:
            payload = json.loads(base64.b64decode(token.split('.')[1] + '==').decode('utf-8'))
            match = re.search(r'auth0\|(.+)', payload.get('sub', ''))
            return match.group(1) if match else ''
        except:
            return ''

    @staticmethod
    def get_usage(token: str) -> Optional[Dict]:
        """获取使用量信息"""
        url = f"https://www.{Config.NAME_LOWER}.com/api/usage"
        
        user_id = UsageManager.extract_user_id_from_jwt(token)
        cookie_id = user_id if user_id else "user_01OOOOOOOOOOOOOOOOOOOOOOOO"
        
        headers = Config.BASE_HEADERS.copy()
        headers.update({
            "Cookie": f"Workos{Config.NAME_CAPITALIZE}SessionToken={cookie_id}%3A%3A{token}"
        })

        try:
            proxies = UsageManager.get_proxy()
            # logger.info(f"当前使用的代理设置: {proxies}")
            
            response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
            response.raise_for_status()
            data = response.json()
            
            return {
                "premium_usage": data.get("gpt-4", {}).get("numRequestsTotal", 0),
                "max_premium_usage": data.get("gpt-4", {}).get("maxRequestUsage", 999),
                "basic_usage": data.get("gpt-3.5-turbo", {}).get("numRequestsTotal", 0),
                "max_basic_usage": data.get("gpt-3.5-turbo", {}).get("maxRequestUsage", 999)
            }
        except requests.RequestException as e:
            logger.error("获取使用量失败,请检查网络连接是否正常,如果使用代理请确认代理是否配置正确")
            return None

    @staticmethod
    def get_stripe_profile(token: str) -> Optional[Dict]:
        """获取用户订阅信息"""
        url = f"https://api2.{Config.NAME_LOWER}.sh/auth/full_stripe_profile"
        
        headers = Config.BASE_HEADERS.copy()
        headers.update({
            "Authorization": f"Bearer {token}"
        })
        
        try:
            proxies = UsageManager.get_proxy()
            # logger.info(f"当前使用的代理设置: {proxies}")
            
            response = requests.get(url, headers=headers, timeout=10, proxies=proxies)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error("获取订阅信息失败,请检查网络连接是否正常,如果使用代理请确认代理是否配置正确")
            return None


def generate_device_uuid(base_id: str) -> str:
    """生成设备UUID"""
    namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8') 
    return str(uuid.uuid5(namespace, base_id))

def generate_ids(user_id: str = None) -> dict:
    """生成各种ID"""
    base_id = user_id if user_id else str(uuid.uuid4())
    
    dev_device_id = generate_device_uuid(base_id)
    
    machine_id = hashlib.sha256(base_id.encode()).hexdigest()
    
    mac_machine_id = hashlib.sha256((base_id + base_id).encode()).hexdigest()
    
    return {
        'dev_device_id': dev_device_id,
        'machine_id': machine_id,
        'mac_machine_id': mac_machine_id
    }

def save_access_code(access_code: str) -> bool:
    """保存access_code到.env文件"""
    try:
        env_path = Path('.env')
        env_content = ""
        
        # 读取现有的.env内容
        if env_path.exists():
            env_content = env_path.read_text(encoding='utf-8')
            
        # 解析现有内容
        lines = env_content.splitlines() if env_content else []
        access_code_updated = False
        
        # 更新或添加 access_code
        new_lines = []
        for line in lines:
            if line.startswith('CURSOR_ACCESS_CODE='):
                new_lines.append(f'CURSOR_ACCESS_CODE={access_code}')
                access_code_updated = True
            else:
                new_lines.append(line)
        
        # 如果没有找到 access_code 配置，添加它
        if not access_code_updated:
            if new_lines and new_lines[-1] != '':
                new_lines.append('')
            new_lines.append(f'CURSOR_ACCESS_CODE={access_code}')
        
        # 写入文件
        env_path.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
        logger.debug("已保存 access_code 到 .env 文件")
        return True
    except Exception as e:
        logger.debug(f"保存 access_code 失败: {e}")
        return False

def get_token_data(cursor_version: str) -> Optional[TokenData]:
    """获取Token数据，支持手动输入或API获取"""
    # 先检查环境变量中是否有有效的 access_code
    access_code = os.getenv('CURSOR_ACCESS_CODE', '')
    if access_code and access_code != 'your_access_code_here':
        # 如果有有效的 access_code，直接使用它
        return TokenManager.fetch_token_data(access_code, cursor_version)
    
    # 如果没有有效的 access_code，显示选择菜单
    print("\n请选择Token获取方式:")
    print("1. 从API自动获取")
    print("2. 手动输入email和token")
    print("3. 退出程序")
    
    choice = input("请输入选择(1/2/3): ").strip()
    
    if choice == "3":
        logger.info("程序已退出")
        exit(0)
    elif choice == "2":
        email = input("请输入email: ").strip()
        token = input("请输入token: ").strip()
        
        ids = generate_ids()
        token_data = TokenData(
            mac_machine_id=ids['mac_machine_id'],
            machine_id=ids['machine_id'],
            dev_device_id=ids['dev_device_id'],
            email=email,
            token=token
        )
        print(token_data)
        return token_data
    else:
        access_code = input("请输入授权码（获取地址：https://cursor.ccopilot.org）: ").strip()
        if access_code:
            # 保存用户输入的 access_code
            save_access_code(access_code)
        return TokenManager.fetch_token_data(access_code, cursor_version)


def show_usage_info():
    """显示使用量信息"""
    # 获取订阅信息
    auth_manager = CursorAuthManager()
    
    # 获取token
    token = auth_manager.get_auth_token()
    print("当前token：")
    print(token)
    if not token:
        logger.error("未找到有效的token")
        return
    profile = UsageManager.get_stripe_profile(token)
    if profile:
        print("\n=== 订阅信息 ===")
        print(f"用户ID: {UsageManager.extract_user_id_from_jwt(token)}")
        print(f"账户类型: {profile['membershipType']}")
        print(f"剩余天数: {profile['daysRemainingOnTrial']}")

    # 获取使用量
    usage = UsageManager.get_usage(token)
    if usage:
        print("\n=== 使用量信息 ===")
        print(f'Premium 使用情况: {usage["premium_usage"]}/{usage["max_premium_usage"]}')
        print(f'Basic   使用情况: {usage["basic_usage"]}/{usage["max_basic_usage"]}')


def main() -> None:
    """主函数"""
    try:
        # 加载环境变量配置
        load_env_config()
        
        # 添加启动界面 - 保持原有的 CRAZY CURSOR logo
        print("""
 ██████╗██████╗  █████╗ ███████╗██╗   ██╗     ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
██╔════╝██╔══██╗██╔══██╗╚══███╔╝╚██╗ ██╔╝    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
██║     ██████╔╝███████║  ███╔╝  ╚████╔╝     ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
██║     ██╔══██╗██╔══██║ ███╔╝    ╚██╔╝      ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
╚██████╗██║  ██║██║  ██║███████╗   ██║       ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                                                Version: 2025020801
        """)
        
        # 修改介绍部分的框体，确保右侧对齐
        print("+------------------------------------------------------------------------------+")
        print("|                                CRAZY CURSOR                                  |")
        print("+------------------------------------------------------------------------------+")
        print("| 本工具基于 @crazy 大佬的体验脚本由 @user705 & @阿弥陀佛 & @文殊师利 共同开发    |")
        print("|                                                                              |")
        print("| 更多详情请访问：                                                              |")
        print("| • https://linux.do/t/topic/359608                                            |")
        print("| • https://cursor.ccopilot.org                                                |")
        print("+------------------------------------------------------------------------------+\n")
        
        while True:
            print("\n=== Cursor 工具 ===")
            print("1. 更新 Token")
            print("2. 查询使用量")
            print("3. 退出程序")
            
            choice = input("\n请选择功能(1/2/3): ").strip()
            
            if choice == "3":
                logger.info("程序已退出")
                break
            elif choice == "2":
                show_usage_info() 
            elif choice == "1":
                logger.info("提示：本脚本请不要再 Cursor 中执行")
                # 获取Cursor路径
                pkg_path, main_path = FilePathManager.get_cursor_app_paths()

                if not Utils.check_files_exist(pkg_path, main_path):
                    logger.warning("请检查是否正确安装 Cursor")
                    continue

                cursor_version = ""
                # 检查版本
                try:
                    cursor_version = json.loads(pkg_path.read_text(encoding="utf-8"))["version"]
                    logger.info(f"当前 Cursor 版本: {cursor_version}")
                    need_patch = CursorPatcher.check_version(cursor_version)
                    if not need_patch:
                        logger.info("当前版本无需 Patch，继续执行 Token 更新...")
                except Exception as e:
                    logger.error(f"读取版本信息失败: {e}")
                    continue
                time.sleep(0.1)

                # 获取token数据
                token_data = get_token_data(cursor_version)
                if not token_data:
                    continue

                logger.info("即将退出 Cursor 并修改配置，请确保所有工作已保存。")
                input("按回车键继续...")

                # 退出Cursor
                if not CursorManager.exit_cursor():
                    continue

                if need_patch and not CursorPatcher.patch_main_js(main_path):
                    logger.error("Patch 失败，程序退出")
                    continue

                if not TokenManager.update_token(token_data):
                    continue

                logger.info("所有操作已完成，现在可以重新打开Cursor体验了\n")
                logger.info("请注意：建议禁用 Cursor 自动更新!!! ")
                logger.info("从 0.45.xx 开始每次更新都需要重新执行此脚本\n\n")

                UpdateManager.disable_auto_update_main()
            else:
                print("无效的选择，请重试")

    except Exception as e:
        logger.error(f"程序执行过程中发生错误: {e}")


if __name__ == "__main__":
    main()