# Secure API

Лабораторная по безопасности: Java 21, Spring Boot и H2. Авторизация через JWT, пароли — BCrypt, запросы к БД параметризованы, ответы экранируются от XSS.

## Запуск

В PowerShell задайте переменные и запустите проект:

```powershell
$env:JWT_SECRET = Read-Host 'JWT-секрет (минимум 32 байта)'
$env:DB_PASSWORD = Read-Host 'Пароль базы данных'
$env:APP_ADMIN_PASSWORD = Read-Host 'Начальный пароль admin (12–72 ASCII-символа)'
.\mvnw.cmd spring-boot:run
```

Адрес: `http://localhost:18081`. База хранится в `data/`: при повторном запуске используйте тот же пароль БД. Пользователь `admin` создаётся один раз.

## API

- `POST /auth/login` — вход: `username`, `password`; возвращает `accessToken`.
- `GET /api/data` — получить свои записи.
- `POST /api/data` — создать запись: `content`.

Для `/api/data` нужен заголовок `Authorization: Bearer <токен>`. Токен действует 15 минут.

## Проверки

```powershell
.\mvnw.cmd verify spotbugs:check
$env:NVD_API_KEY = Read-Host 'Ключ NVD'
.\scripts\sca.ps1
```

GitHub Actions запускает тесты, SpotBugs и OWASP Dependency-Check на push и pull request. Ключ NVD задаётся в Actions secret `NVD_API_KEY`; отчёты доступны в artifacts. Уязвимости с CVSS ≥ 7 останавливают сборку.
