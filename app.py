from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session
import os
import argparse
import hashlib
import json
import shutil
import base64  # 用於加鹽密碼
from flask import send_file

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")  # 從環境變數讀取密鑰

SHARED_FOLDER = "./shared"
ACCOUNTS_FILE = "accounts.json"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt', 'json', 'xml'}

# 初始化資料夾
if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

# 加鹽加密密碼
def hash_password(password):
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    salted_password = salt + password
    return f"{salt}:{hashlib.sha256(salted_password.encode()).hexdigest()}"

def verify_password(stored_password, provided_password):
    salt, hashed = stored_password.split(':')
    salted_password = salt + provided_password
    return hashed == hashlib.sha256(salted_password.encode()).hexdigest()

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

# 檢查檔案類型是否合法
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    if username in accounts and verify_password(accounts[username], password):
        session["username"] = username
        return redirect(url_for("dashboard"))
    else:
        return "登入失敗：帳號或密碼錯誤！", 401

# 登出功能
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))

# 使用者主頁：檔案管理（上傳與下載）
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("home"))

    username = session["username"]
    user_folder = os.path.join(SHARED_FOLDER, username)

    if not os.path.exists(user_folder):
        return "用戶資料夾不存在！", 404

    # 處理檔案上傳請求
    if request.method == "POST":
        if 'file' not in request.files:
            return "未選擇檔案！", 400
        file = request.files['file']
        if file.filename == '':
            return "檔案名稱空白！", 400
        if not allowed_file(file.filename):
            return "不支持的檔案類型！", 400

        filepath = os.path.join(user_folder, file.filename)
        file.save(filepath)
        return "檔案上傳成功！"

    # 列出用戶的檔案
    files = os.listdir(user_folder)
    return render_template("dashboard.html", username=username, files=files)

# 檔案下載功能
@app.route("/download/<filename>")
def download_file(filename):
    if "username" not in session:
        return redirect(url_for("home"))

    username = session["username"]
    user_folder = os.path.join(SHARED_FOLDER, username)

    # 防止目錄遍歷攻擊
    if '..' in filename or filename.startswith('/'):
        return "非法檔案名稱！", 400

    filepath = os.path.join(user_folder, filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        # 使用 send_file 強制下載
        return send_file(filepath, as_attachment=True)
    else:
        return "檔案不存在！", 404

# 啟動伺服器或命令列
if __name__ == "__main__":
    if len(os.sys.argv) > 1:
        cli()
    else:
        app.run(debug=True)
