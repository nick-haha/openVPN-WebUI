# OpenVPN Web 管理平台后端服务

这是一个基于 Flask 框架开发的 OpenVPN 后端管理服务，配合前端页面可实现 VPN 用户的管理，包括查看配置、添加、删除用户等功能。

##🧰 功能介绍

✅ 图形化管理 OpenVPN 用户（添加/删除）
✅ 管理员登录认证
✅ 管理员密码重置脚本
✅ 系统运行日志记录
✅ 简洁易用的前端页面（HTML） 

##🚀 快速开始

###1️⃣ 安装依赖

确保系统已安装 Python 3.6+，然后执行：


pip install -r requirements.txt


###2️⃣ 配置环境变量

在 config/ 目录下编辑 .env 文件

###3️⃣ 启动平台

python bin/webui.py
默认运行在：http://127.0.0.1:5000

##🛠️ OpenVPN 安装参考
在使用本系统前，您需要先完成 OpenVPN 的安装。
推荐使用以下脚本安装：

wget -O openvpn.sh https://get.vpnsetup.net/ovpn
sudo bash openvpn.sh --auto
安装完成后，即可使用本平台进行用户管理。

##🔐 重置管理员密码
如果管理员密码遗忘，可以通过脚本重置：

python bin/reset_admin_password.py
# 🖥️ 使用说明
启动平台并访问：http://127.0.0.1:5000
使用 .env 文件中配置的管理员账号登录
进入控制台后可进行以下操作：
👤 添加用户
❌ 删除用户
🔍 查看当前所有用户

