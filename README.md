# OpenVPN Web 管理平台后端服务

这是一个基于 Flask 框架开发的 OpenVPN 后端管理服务，配合前端页面可实现 VPN 用户的管理，包括查看配置、添加、删除用户等功能。

## 🌟 功能简介

- 查询当前 OpenVPN 用户配置
- 添加新的 OpenVPN 用户配置
- 删除已有用户配置
- 显示服务器状态信息

## 📁 项目结构

.
├── bin/
│   └── webui.py            # 主后端程序（Flask Web 服务）
├── config/
│   └── .env                # 配置文件，包含路径及 OpenVPN 设置
├── static/
│   ├── index.html          # 首页（用户配置管理）
│   └── login.html          # 登录页面（如有身份验证功能）


## 🚀 快速开始

### 1️⃣ 安装依赖

确保系统已安装 Python 3.6+，然后执行：

```bash
pip install -r requirements.txt
2️⃣ 配置环境变量
在 config/ 目录下创建 .env 文件，示例如下：

# 数据库路径
DATABASE_URL=sqlite:///../openvpn.db

# 管理员登录信息
ADMIN_USERNAME=admin
ADMIN_PASSWORD=yourpassword

# 日志路径
LOG_FILE_PATH=../log/platform.log
3️⃣ 启动平台
python bin/webui.py
默认运行在：http://127.0.0.1:5000。

🧰 功能介绍

✅ 图形化管理 OpenVPN 用户（添加/删除）
✅ 管理员登录认证
✅ 管理员密码重置脚本
✅ 系统运行日志记录
✅ 简洁易用的前端页面（HTML）
🛠️ OpenVPN 安装参考

在使用本系统前，您需要先完成 OpenVPN 的安装。

推荐使用以下脚本安装：

📌 hwdsl2/openvpn-install（中文说明）

一键安装示例：

wget -O openvpn.sh https://get.vpnsetup.net/ovpn
sudo bash openvpn.sh --auto
安装完成后，即可使用本平台进行用户管理。

🔐 重置管理员密码

如果管理员密码遗忘，可以通过脚本重置：

python bin/reset_admin_password.py
按照提示输入新用户名和密码，.env 文件将自动更新。

🖥️ 使用说明

启动平台并访问：http://127.0.0.1:5000
使用 .env 文件中配置的管理员账号登录
进入控制台后可进行以下操作：
👤 添加用户
❌ 删除用户
🔍 查看当前所有用户
📦 主要依赖

Flask
Flask-Login
Flask-SQLAlchemy
python-dotenv
SQLite
安装依赖：

pip install -r requirements.txt
❓ 常见问题

Q: 登录失败怎么办？
检查 .env 文件中账号密码是否正确
检查 webui.py 是否正常运行
查看 log/ 目录下的日志文件获取报错信息
Q: 如何查看平台日志？
tail -f log/platform.log
Q: 支持 HTTPS 吗？
目前暂不支持，建议通过反向代理（如 Nginx）配置 SSL 证书。

🤝 参与贡献

欢迎提交 Issues 和 Pull Requests，一起改进这个项目！

📄 License

本项目基于 MIT License 开源发布。
