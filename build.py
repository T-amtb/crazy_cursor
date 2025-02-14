import os
import shutil
import subprocess
import sys
from pathlib import Path

def print_banner():
    """打印启动横幅"""
    print("""
╔══════════════════════════════════════════════╗
║             Crazy Cursor 打包工具             ║
║                                              ║
║  版本: 2025.2.14.1                          ║
║  作者: 阿弥陀佛                              ║
╚══════════════════════════════════════════════╝
    """)

def clean_build_dirs():
    """清理构建目录"""
    print("【1/4】清理构建目录...")
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            try:
                shutil.rmtree(dir_name)
                print(f"  ✓ 已删除 {dir_name}/")
            except Exception as e:
                print(f"  ✗ 删除 {dir_name}/ 失败: {e}")
                return False
    return True

def check_python_version():
    """检查Python版本"""
    print("\n【2/4】检查Python环境...")
    version = sys.version_info
    min_version = (3, 7)
    
    if version < min_version:
        print(f"  ✗ Python版本过低: {version[0]}.{version[1]}")
        print(f"  ✗ 需要Python {min_version[0]}.{min_version[1]}或更高版本")
        return False
    
    print(f"  ✓ Python版本: {version[0]}.{version[1]}.{version[2]}")
    return True

def install_requirements():
    """安装必要的依赖"""
    print("\n【3/4】安装依赖包...")
    
    # 先卸载已有的 PyInstaller 及其依赖
    try:
        print("  正在清理旧版本...", end='', flush=True)
        subprocess.run(
            [sys.executable, '-m', 'pip', 'uninstall', '-y', 'pyinstaller', 'pyinstaller-hooks-contrib'],
            capture_output=True,
            text=True
        )
        print(" ✓")
    except:
        print(" (跳过)")
    
    # 基础依赖包
    required_packages = [
        'setuptools>=65.5.1',
        'wheel>=0.38.4',
        'psutil>=5.9.0',
        'requests>=2.31.0',
        'python-dotenv>=1.0.0'
    ]
    
    # 安装基础依赖包
    for package in required_packages:
        package_name = package.split('>=')[0].split('==')[0]
        try:
            print(f"  正在安装 {package}...", end='', flush=True)
            result = subprocess.run(
                [
                    sys.executable, 
                    '-m', 
                    'pip', 
                    'install', 
                    '--no-cache-dir',
                    package
                ],
                check=True,
                capture_output=True,
                text=True
            )
            print(" ✓")
        except Exception as e:
            print(f"\n  ✗ 安装 {package_name} 时发生错误: {e}")
            return False
    
    # 单独安装 PyInstaller
    print("  正在安装 PyInstaller...", end='', flush=True)
    try:
        # 先安装 pyinstaller-hooks-contrib
        subprocess.run(
            [
                sys.executable,
                '-m',
                'pip',
                'install',
                '--no-cache-dir',
                'pyinstaller-hooks-contrib'
            ],
            check=True,
            capture_output=True,
            text=True
        )
        
        # 安装 pyinstaller
        subprocess.run(
            [
                sys.executable,
                '-m',
                'pip',
                'install',
                '--no-cache-dir',
                'pyinstaller'
            ],
            check=True,
            capture_output=True,
            text=True
        )
        print(" ✓")
        
        # 验证安装
        print("  验证 PyInstaller 安装...", end='', flush=True)
        try:
            import PyInstaller
            print(f" ✓ (版本 {PyInstaller.__version__})")
            return True
        except ImportError:
            print("\n  ✗ PyInstaller 导入失败")
            # 尝试使用 pip 安装的可执行文件
            try:
                result = subprocess.run(
                    ['pyinstaller', '--version'],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    print(f"  ✓ PyInstaller CLI 可用 (版本 {result.stdout.strip()})")
                    return True
            except:
                pass
            return False
            
    except Exception as e:
        print(f"\n  ✗ PyInstaller 安装失败: {e}")
        return False

def build_exe():
    """构建exe文件"""
    print("\n【4/4】构建可执行文件...")
    try:
        # 尝试不同的构建命令
        commands = [
            # 方式1：使用 python -m PyInstaller
            [sys.executable, '-m', 'PyInstaller', '--clean', '--noconfirm', 'crazy_cursor.spec'],
            # 方式2：直接使用 pyinstaller 命令
            ['pyinstaller', '--clean', '--noconfirm', 'crazy_cursor.spec'],
            # 方式3：使用 python -m pyinstaller (小写)
            [sys.executable, '-m', 'pyinstaller', '--clean', '--noconfirm', 'crazy_cursor.spec']
        ]
        
        success = False
        for cmd in commands:
            try:
                print(f"  尝试构建方式: {' '.join(cmd)}")
                process = subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True
                )
                success = True
                break
            except subprocess.CalledProcessError as e:
                print(f"  - 失败: {e.stderr.strip() if e.stderr else str(e)}")
                continue
            except Exception as e:
                print(f"  - 错误: {str(e)}")
                continue
        
        if not success:
            print("  ✗ 所有构建方式都失败了")
            return False
        
        # 检查构建结果
        exe_path = Path('dist/crazy_cursor.exe')
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"  ✓ 构建成功!")
            print(f"  ✓ 输出文件: {exe_path.absolute()}")
            print(f"  ✓ 文件大小: {size_mb:.1f}MB")
            return True
        else:
            print("  ✗ 构建失败: 未找到输出文件")
            return False
            
    except Exception as e:
        print(f"  ✗ 构建过程中发生错误: {e}")
        return False

def main():
    print_banner()
    
    # 检查必要文件
    required_files = ['crazy_cursor.py', 'crazy_cursor.spec']
    for file in required_files:
        if not os.path.exists(file):
            print(f"错误: 未找到必要文件 {file}")
            return
    
    # 执行构建步骤
    steps = [
        clean_build_dirs,
        check_python_version,
        install_requirements,
        build_exe
    ]
    
    for step in steps:
        if not step():
            print("\n构建失败! 按任意键退出...")
            input()
            return
    
    print("\n✨ 构建完成! 按任意键退出...")
    input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n构建已取消!")
    except Exception as e:
        print(f"\n构建过程中发生未知错误: {e}")
        print("请将以上错误信息反馈给开发者")
        input("按任意键退出...") 