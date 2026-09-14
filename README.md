# CAPTCHA-tencent
https://cloud.tencent.com/document/sdk 腾讯云验证码搭配nginx使用
    
启动，也可以直接启动，注意带入变量
    
cat  /etc/systemd/system/captcha-gateway.service
[Unit]
Description=Tencent Captcha Gateway
After=network.target

[Service]
WorkingDirectory=/epailive/app/captcha-gateway
Environment=CAPTCHA_APP_ID=*****
Environment=APP_SECRET_KEY=***** #'你的AppSecretKey'
Environment=TENCENT_SECRET_ID=****   #'你的SecretId'
Environment=TENCENT_SECRET_KEY=****  #'你的SecretKey'
Environment=COOKIE_SECRET=*****   #openssl rand -hex 32
Environment=COOKIE_SECURE=1
ExecStart=/usr/bin/python3 gateway.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target


systemctl daemon-reload
systemctl enable --now captcha-gateway
systemctl status captcha-gateway
