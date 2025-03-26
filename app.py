from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session
import os
import argparse
import hashlib
import json
import shutil  # 引入 shutil 模組

app = Flask(__name__)
app.secret_key = "your_secret_key"  # 用於 Session 管理

SHARED_FOLDER = "./shared"
ACCOUNTS_FILE = "accounts.json"

# 初始化資料夾
if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

# 加密密碼
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 載入帳號資料
def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return {}
    with open(ACCOUNTS_FILE, "r") as file:
        return json.load(file)

# 儲存帳號資料
def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "w") as file:
        json.dump(accounts, file)

# 新增帳號
def add_user(username, password):
    accounts = load_accounts()
    if username in accounts:
        print(f"帳號 {username} 已存在！")
        return

    user_folder = os.path.join(SHARED_FOLDER, username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    accounts[username] = hash_password(password)
    save_accounts(accounts)
    print(f"成功新增帳號 {username}！")

# 刪除帳號
def delete_user(username):
    accounts = load_accounts()
    if username not in accounts:
        print(f"帳號 {username} 不存在！")
        return

    user_folder = os.path.join(SHARED_FOLDER, username)
    if os.path.exists(user_folder):
        shutil.rmtree(user_folder)  # 使用 shutil.rmtree 刪除資料夾及內容

    del accounts[username]
    save_accounts(accounts)
    print(f"成功刪除帳號 {username}！")
    
# 命令列解析器
def cli():
    parser = argparse.ArgumentParser(description="用戶管理工具")
    parser.add_argument("action", choices=["add", "del"], help="操作類型：add 或 del")
    parser.add_argument("-u", "--username", required=True, help="使用者名稱")
    parser.add_argument("-p", "--password", help="密碼（僅新增帳號時需要）")

    args = parser.parse_args()

    if args.action == "add":
        if not args.password:
            print("新增帳號時必須提供密碼！")
            return
        add_user(args.username, args.password)
    elif args.action == "del":
        delete_user(args.username)

# 路由：首頁（登入頁面）
@app.route("/")
def home():
    return render_template("login.html")

# 登入功能
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    accounts = load_accounts()
    if username in accounts and accounts[username] == hash_password(password):
        session["username"] = username
        return redirect(url_for("dashboard"))
    else:
        return "登入失敗：帳號或密碼錯誤！"

# 登出功能
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))

# 使用者主頁（顯示檔案）
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("home"))

    username = session["username"]
    user_folder = os.path.join(SHARED_FOLDER, username)

    if not os.path.exists(user_folder):
        return "用戶資料夾不存在！", 404

    # 列出用戶的檔案
    files = os.listdir(user_folder)
    return render_template("dashboard.html", username=username, files=files)

@app.route("/download/<filename>")
def download_file(filename):
    if "username" not in session:
        return redirect(url_for("home"))

    username = session["username"]
    user_folder = os.path.join(SHARED_FOLDER, username)

    # 調試日誌
    print(f"檢查用戶資料夾：{user_folder}")
    print(f"資料夾內容：{os.listdir(user_folder)}")
    print(f"嘗試下載檔案名稱：{filename}")

    # 確認檔案是否存在
    filepath = os.path.join(user_folder, filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        return send_from_directory(user_folder, filename)
    else:
        print(f"檔案不存在或名稱錯誤：{filepath}")
        return "檔案不存在！", 404




# 啟動伺服器或命令列
if __name__ == "__main__":
    if len(os.sys.argv) > 1:
        cli()
    else:
        app.run(debug=True)
