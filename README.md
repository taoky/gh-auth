# gh-auth

A flask website to validate the relationship between student ID and GitHub account.

## Installation

### Docker

```shell
$ docker pull ghcr.io/taoky/gh-auth:main
$ wget https://raw.githubusercontent.com/taoky/gh-auth/main/app/config.example.py -O config.py
$ docker run --rm ghcr.io/taoky/gh-auth:main python /app/utils/nacl_gen.py  # generate NACL public key and private key
$ vim config.py  # modify the config.py to your settings
$ docker run -p 15000:80 -v ${PWD}/config.py:/app/config.py --rm ghcr.io/taoky/gh-auth:main
```

The app will listen on port 15000.

### Manual

```shell
$ git clone https://github.com/taoky/gh-auth.git
$ cd gh-auth
$ python -m venv venv
$ . venv/bin/activate
(venv) $ pip install -r requirements.txt
(venv) $ cp app/config.example.py app/config.py
(venv) $ python utils/nacl_gen.py
NACL_PRIVKEY="PRIVATEKEY"
NACL_PUBKEY="PUBKEY"
(venv) $ vim app/config.py  # modify the config.py to your settings and use generated NACL_PRIVKEY and NACL_PUBKEY
(venv) $ cd app
(venv) $ FLASK_RUN_PORT=15000 FLASK_APP=main.py flask run
```

You should use uwsgi/gunicorn if used in production environment.

## Notes

Create a new GitHub oauth app at <https://github.com/settings/applications/new>.

`config.py`:

```python
CLIENT_ID="Register your client on GitHub!"
CLIENT_SECRET="Register your client on GitHub!"
NACL_PUBKEY="generate by utils/nacl_gen.py"
NACL_PRIVKEY="generate by utils/nacl_gen.py"
CAS_URL="https://passport.ustc.edu.cn/login"  # replace to your CAS server if not applicable.
CAS_VALIDATE="https://passport.ustc.edu.cn/serviceValidate"
CAS_REDIRECT="http://home.ustc.edu.cn/~zzh1996/cas_redirect.html"  # replace to your own redirect page.
CAS_LOGOUT="https://passport.ustc.edu.cn/logout"
SECRET="Secret for flask session"
HOST="https://ghauth.taoky.moe"  # GitHub auth relies on this value.
```

This app uses no database and its security relies on the secrecy of `config.py`. If `config.py` leaks out then your GitHub oauth app will be compromised and user can generate forged tokens.
