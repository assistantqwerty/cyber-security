WEEK 4 – Advanced Threat Detection & Web Security Enhancements
Task 1: Rate Limiting
Kiya kya: express-rate-limit package lagaya.

Kyun kiya: Brute force attack rokne ke liye.

Kaise kaam karta hai:
Login par 5 galat attempts ke baad 15 minute block.
             
"Dekho, main 5 baar galat password daal raha hoon. 6th attempt par block ho gaya – Too many attempts. Rate limiting working hai."

Task 2: CORS Configuration
Kiya kya: cors package configure kiya.

Kyun kiya: Sirf allowed domains ko access de.

Kaise kaam karta hai:
Sirf localhost:3000 aur 127.0.0.1:3000 allowed hain.

Video mein bolna:
"CORS lagaya hai – koi aur website meri API use nahi kar sakti."

Task 3: CSP & HSTS Headers
Kiya kya: helmet package se CSP aur HSTS enable kiye.

Kyun kiya: CSP script injection (XSS) rokta hai, HSTS HTTPS enforce karta hai.

"CSP aur HSTS headers active hain – script injection aur HTTP attacks se bachav."

Task 4: API Key Authentication
Kiya kya: /api/users endpoint par API key requirement lagayi.

API Key: secure-api-key-2026-cybersecurity-intern

Kaise test kiya: Curl command se.

bash
curl -H "X-API-Key: secure-api-key-2026-cybersecurity-intern" http://localhost:3000/api/users
Result: Users ki list aa gayi {"users":[{"username":"ashan"}],"total":1}

"API key authentication se sirf valid key wale users list dekh sakte hain."

🟢 WEEK 5 – Ethical Hacking & Exploiting Vulnerabilities
Task 1: SQL Injection Fix
Vulnerability: admin' OR '1'='1 se login ho raha tha.

Fix: bcrypt password hashing + bcrypt.compare().

Result: Ab SQL injection kaam nahi karta.

"Pehle vulnerable app mein SQL injection se login ho jata tha. Ab bcrypt lagane se fail ho raha hai."

Task 2: XSS Fix
Vulnerability: <script>alert('XSS')</script> se popup aa raha tha.

Fix: validator.escape() se input sanitization.

Result: Script tags escape ho gaye, execute nahi h
"Ab XSS attack kaam nahi karta – script text ke roop mein show hota hai."

Task 3: CSRF Protection
Fix: csurf middleware lagaya.

Kaise kaam karta hai: Har form mein hidden _csrf token generate hota hai.

Result: Bina token ke POST request fail (403 Forbidden).


"Har form mein CSRF token hai – bina token ke koi form submit nahi ho sakta."

Task 4: JWT Authentication
Fix: jsonwebtoken se token-based authentication.

Kaise kaam karta hai: Login par token milega, profile access ke liye token chahiye.

"Login ke baad token milta hai – woh token profile par daalne se access milta hai."

🟢 WEEK 6 – Security Audits & Secure Deployment
Task 1: Security Audit Endpoint
Kiya kya: /security-audit endpoint banaya.

Kya deta hai: JSON mein saari security features ki list.

"Security audit endpoint se JSON report milti hai – rate limiting, CORS, CSP, sab enabled hain."

Task 2: Winston Logging
Kiya kya: winston logger lagaya.

Kaha store hota hai: security.log file mein.

Kya log hota hai: Login attempts, signups, XSS prevention, invalid API keys.

"Saare events security.log file mein log ho rahe hain – IP, timestamp, sab kuch."

Task 3: Helmet Security Headers
Kiya kya: helmet() middleware lagaya.

Kya headers set kiye: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection.

"Helmet ne saare security headers automatically set kar diye.
