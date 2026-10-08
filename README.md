# Біздің отбасы

Сайт: HTML + CSS + JavaScript (дайын, ешқандай build керек емес) + `server.mjs` (қосымша пакеттерсіз).

## Компьютерде іске қосу
1. Node.js орнатыңыз (nodejs.org, LTS).
2. Осы папкада терминал ашып:
   - Windows PowerShell: `$env:ADMIN_PASSWORD="era123"; node server.mjs`
   - Mac / Linux: `ADMIN_PASSWORD=era123 node server.mjs`
3. Браузерде http://localhost:8080 ашыңыз.

## Интернетке шығару (Render.com)
Web Service жасағанда: Runtime — **Node**, Build Command — бос қалдырыңыз (немесе `echo ok`), Start Command — `node server.mjs`.
Environment: `ADMIN_PASSWORD` = құпия сөз; `DATA_DIR` = `/data`.
Disks бөлімінде диск қосып, Mount Path = `/data` қойыңыз (жүктелген фото мен баптаулар осында сақталады).

## Админ
Жоғарғы мәзірде «Кіру» → құпия сөз. Кіргеннен кейін «Админ» беті пайда болады: беттердің суреттерін, «Бізбен танысыңыз» карточкаларын, барлық фотоларды және музыканы басқару.
