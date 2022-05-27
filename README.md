# Authentication-Module
Simple web application in Flask-Python and SQL Alchemy, which consists in an authentication module that is able to prevent bot attacks without using reCAPTCHA.

With the purpose of mitigating this brute force attack, three particular preventive measures are taken:
- A text-based captcha, more specifically: a numerical captcha.
- A randomly selected wait time ( between 1 and 3 seconds) before validating the user and password combination.
- After three failed attempts to log in the website the account gets blocked and will not allow the user to authenticate for ten minutes.
