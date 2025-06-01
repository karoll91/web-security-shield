# 🛡️ Web Security Shield

**"Web saytlarga bo'ladigan hujumlarda axborot xavfsizligini ta'minlovchi himoya mexanizmlarini ishlab chiqish"**

*Bitiruv malakaviy ishi - 2025*

---

## 📋 Loyiha Haqida

Web Security Shield - bu web aplikatsiyalarni eng keng tarqalgan xavfsizlik tahdidlaridan himoya qiluvchi to'liq xavfsizlik tizimi. Loyiha Java Spring Boot framework asosida ishlab chiqilgan bo'lib, real vaqt rejimida hujumlarni aniqlash va bloklash imkoniyatini beradi.

## 🎯 Asosiy Maqsad

- XSS (Cross-Site Scripting) hujumlarini aniqlash va bloklash
- SQL Injection hujumlarini oldini olish
- Rate Limiting orqali DDoS hujumlardan himoya
- IP-based bloklash tizimi
- Real-time monitoring va logging
- Xavfsizlik hodisalari statistikasi

## 🔧 Texnologiyalar

### Backend
- **Java 17** - Asosiy dasturlash tili
- **Spring Boot 3.2.0** - Web framework
- **Spring Security** - Xavfsizlik va autentifikatsiya
- **Spring Data JPA** - Database integration
- **H2 Database** - In-memory database (development)
- **Gradle** - Build tool

### Frontend
- **Thymeleaf** - Template engine
- **Bootstrap 5** - UI framework
- **Chart.js** - Data visualization
- **Bootstrap Icons** - Icon library

## 🚀 Ishga Tushirish

### Talablar
- Java 17 yoki undan yuqori
- Gradle 7.0+

### 1. Loyihani klonlash
```bash
git clone [repository-url]
cd web-security-shield
```

### 2. Loyihani build qilish
```bash
./gradlew build
```

### 3. Ishga tushirish
```bash
./gradlew bootRun
```

Yoki JAR faylni ishga tushirish:
```bash
java -jar build/libs/web-security-shield.jar
```

### 4. Web brauzerda ochish
```
http://localhost:8080
```

## 📊 Dashboard va Sahifalar

### Asosiy Sahifalar
- **Login/Register** - Foydalanuvchi autentifikatsiyasi
- **Dashboard** - Asosiy monitoring panel
- **Security Logs** - Xavfsizlik hodisalari loglari
- **Blocked IPs** - Bloklangan IP manzillar
- **Critical Attacks** - Kritik hujumlar ro'yxati

### Test Foydalanuvchisi
Tizim ishga tushgandan keyin avtomatik test foydalanuvchisi yaratiladi:
- **Username:** `admin`
- **Password:** `admin123`

## 🛡️ Xavfsizlik Xususiyatlari

### 1. XSS (Cross-Site Scripting) Himoyasi
- Real-time XSS pattern detection
- Dangerous script tag filtering
- Event handler detection
- JavaScript injection prevention

### 2. SQL Injection Himoyasi
- SQL keyword detection
- Comment injection prevention
- Union attack blocking
- Prepared statement enforcement

### 3. Rate Limiting
- IP-based request limiting
- Configurable thresholds
- Automatic temporary blocking
- Burst traffic protection

### 4. IP Bloklash Tizimi
- Manual IP blocking
- Automatic threat-based blocking
- Temporary va permanent blocks
- Block expiration management

### 5. Real-time Monitoring
- Live attack detection
- Security event logging
- Dashboard statistics
- Threat type analysis

## ⚙️ Sozlamalar

`application.yml` faylida asosiy sozlamalar:

```yaml
security:
  rate-limit:
    requests-per-minute: 10
    block-duration-minutes: 5
    
  ip-blocking:
    max-failed-attempts: 5
    block-duration-hours: 1
    
  xss-protection:
    enabled: true
    block-mode: true
    
  sql-injection:
    enabled: true
    strict-mode: false
```

## 📈 Test Qilish

### XSS Test
```
http://localhost:8080/test?param=<script>alert('xss')</script>
```

### SQL Injection Test
```
http://localhost:8080/test?id=1' OR '1'='1
```

### Rate Limit Test
Bir IP dan 10 tadan ko'p so'rov yuborish

## 📊 Monitoring

### H2 Database Console
Development rejimida database ni ko'rish uchun:
```
http://localhost:8080/h2-console
```
- **JDBC URL:** `jdbc:h2:mem:security_db`
- **Username:** `sa`
- **Password:** (bo'sh)

### Security Logs
Barcha xavfsizlik hodisalari `logs/security.log` faylida saqlanadi.

## 🏗️ Loyiha Strukturasi

```
src/main/java/uz/edu/security/
├── entity/           # Database modellari
├── repository/       # Data access layer
├── service/          # Business logic
├── controller/       # Web controllers
├── security/         # Security filters
└── config/          # Configuration

src/main/resources/
├── templates/        # HTML sahifalar
├── static/          # CSS, JS, images
└── application.yml  # Sozlamalar
```

## 📝 Xususiyatlar

### ✅ Amalga oshirilgan
- [x] XSS hujumlarini aniqlash va bloklash
- [x] SQL Injection himoyasi
- [x] Rate limiting va IP bloklash
- [x] Real-time monitoring dashboard
- [x] Security logging va statistika
- [x] User authentication
- [x] Responsive web UI

### 🔄 Kelajakda qo'shilishi mumkin
- [ ] CSRF protection enhancement
- [ ] Advanced bot detection
- [ ] Email notifications
- [ ] API endpoints
- [ ] Database export/import
- [ ] Advanced reporting

## 🎓 Bitiruv Ishi Ma'lumotlari

**Mavzu:** "Web saytlarga bo'ladigan hujumlarda axborot xavfsizligini ta'minlovchi himoya mexanizmlarini ishlab chiqish"

**Texnologiyalar:** Java, Spring Boot, Spring Security, Gradle

**Mualliflar:** [Sizning ismingiz]

**Universitet:** [Universitet nomi]

**Yil:** 2025

## 📞 Yordam

Loyiha bilan bog'liq savollar yoki muammolar uchun:
- GitHub Issues
- Email: [sizning-emailingiz]

---

**© 2025 Web Security Shield - Bitiruv malakaviy ishi**