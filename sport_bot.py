import os
import requests
import logging
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import json
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os

class Config:
    # 用户信息
    USER = os.getenv("USER")  
    PASSWORD = os.getenv("PASSWORD")  

    # 位置坐标
    LONGITUDE = float(os.getenv("LONGITUDE", 108.654387))
    LATITUDE = float(os.getenv("LATITUDE", 34.257229))

    # 邮件通知
    SEND_EMAIL = True  
    SMTP_AUTH_CODE = os.getenv("SMTP_AUTH_CODE")  
    EMAIL_SENDER = os.getenv("EMAIL_SENDER")  
    EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")  

    # 加密公钥
    AES_PUBLIC_KEY = "0725@pwdorgopenp"


# 初始化日志
logging.basicConfig(
    filename=Config.LOG_FILE,
    level=Config.LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8",
)

# 前端界面的加密函数
def aes_ecb_encrypt(pwd_val: str, public_key=Config.AES_PUBLIC_KEY) -> str:
    key = public_key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(pwd_val.encode("utf-8"), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode("utf-8")


def get_token(user, password):
    try:
        # Step 1: 获取初始Cookie
        response = requests.get(
            "https://org.xjtu.edu.cn/openplatform/oauth/authorize",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
            params={
                "appId": "1740",
                "redirectUri": "https://ipahw.xjtu.edu.cn/sso/callback",
                "responseType": "code",
                "scope": "user_info",
                "state": "1234",
            },
            allow_redirects=False,
        )
        cookies = response.cookies.get_dict()

        # Step 2: 获取验证码Cookie
        response = requests.post(
            "https://org.xjtu.edu.cn/openplatform/g/admin/getJcaptchaCode",
            headers={
                "Cookie": f"route={cookies['route']}; rdstate={cookies['rdstate']}; cur_appId_={cookies['cur_appId_']}; state={cookies['state']}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
        )
        cookies.update(response.cookies.get_dict())

        # Step 3: 执行登录
        response = requests.post(
            "https://org.xjtu.edu.cn/openplatform/g/admin/login",
            headers={
                "Cookie": f"route={cookies['route']}; rdstate={cookies['rdstate']}; cur_appId_={cookies['cur_appId_']}; state={cookies['state']}; JSESSIONID={cookies['JSESSIONID']}; sid_code={cookies['sid_code']}",
                "Content-Type": "application/json;charset=UTF-8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            },
            data=json.dumps(
                {
                    "loginType": 1,
                    "username": user,
                    "pwd": password,
                    "jcaptchaCode": "",
                }
            ),
        )
        response_json = response.json()
        if not response_json["message"] == "成功":
            raise Exception("统一身份认证登录失败")

        # Step 4-5: 获取最终token
        cookies["open_Platform_User"] = response_json["data"]["tokenKey"]
        response = requests.get(
            "https://org.xjtu.edu.cn/openplatform/oauth/auth/getRedirectUrl",
            params={
                "userType": "1",
                "personNo": user,
                "_": str(int(time.time() * 1000)),
            },
            headers={"Cookie": "; ".join([f"{k}={v}" for k, v in cookies.items()])},
        )
        oauth_code = parse_qs(urlparse(response.json()["data"]).query)["code"][0]

        response = requests.get(
            "https://ipahw.xjtu.edu.cn/szjy-boot/sso/codeLogin",
            params={"userType": "1", "code": oauth_code, "employeeNo": user},
            headers={"Referer": response.json()["data"]},
        )
        return response.json()["data"]["token"]

    except Exception as e:
        logging.error(f"Token获取失败: {str(e)}")
        return None


def sign_operation(url, payload, token, operation_name):
    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/537.36",
                "token": token,
            },
            data=json.dumps(payload),
        )
        logging.info(f"{operation_name}请求: {response.status_code}")

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get("success"):
                logging.info(f"{operation_name}成功")
                return True
            logging.warning(f"{operation_name}失败: {response_data.get('msg')}")
        return False
    except Exception as e:
        logging.error(f"{operation_name}异常: {str(e)}")
        return False


def send_email(content):
    try:
        msg = MIMEText(content, "plain", "utf-8")
        msg["From"] = Header(Config.EMAIL_SENDER)
        msg["To"] = Header(Config.EMAIL_RECEIVER)
        msg["Subject"] = Header("运动打卡通知", "utf-8")

        with smtplib.SMTP_SSL("smtp.qq.com", 465) as smtp:
            smtp.login(Config.EMAIL_SENDER, Config.SMTP_AUTH_CODE)
            smtp.sendmail(Config.EMAIL_SENDER, [Config.EMAIL_RECEIVER], msg.as_string())
            smtp.quit()
        logging.info("邮件发送成功")
    except Exception as e:
        logging.error(f"邮件发送失败: {str(e)}")


def main():
    # 获取加密后的密码
    crypto_pwd = aes_ecb_encrypt(Config.PASSWORD)

    # 获取访问令牌
    token = get_token(Config.USER, crypto_pwd)
    if not token:
        logging.error("获取token失败，终止流程")
        if Config.SEND_EMAIL:
            send_email("获取token失败，请检查账号密码")
        return

    # 执行签到
    sign_in_success = sign_operation(
        "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signRun",
        {
            "sportType": 2,
            "longitude": Config.LONGITUDE,
            "latitude": Config.LATITUDE,
            "courseInfoId": "null",
        },
        token,
        "签到",
    )

    if sign_in_success:
        logging.info("等待31分钟后签退...")
        print("签到成功！请勿关闭程序，31分钟后自动签退...")
        time.sleep(31*60)  # 31分钟

        sign_out_success = sign_operation(
            "https://ipahw.xjtu.edu.cn/szjy-boot/api/v1/sportActa/signOutTrain",
            {"longitude": Config.LONGITUDE, "latitude": Config.LATITUDE},
            token,
            "签退",
        )
        if sign_out_success:
            notice_msg = "打卡成功"
            print("已签退，本次打卡有效！")
        else:
            notice_msg = "签到成功但签退失败"
            print("签退失败，请手动签退")
    else:
        notice_msg = "签到失败"
        print("签到失败！请检查sport_bot.log文件排查错误")

    if Config.SEND_EMAIL:
        send_email(notice_msg)


if __name__ == "__main__":
    main()
