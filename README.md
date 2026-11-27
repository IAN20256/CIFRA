# Cifra 🔐 — chats cifrados sin número de teléfono

**Español** · [English below](#english)

Cifra es una app de chats cifrados de extremo a extremo. No pide teléfono ni correo:

- **Tu identidad es un código de 5 dígitos** (ej. `13826`). Ese mismo código sirve para que otros te agreguen.
- **Los grupos usan un código de 8 dígitos** (ej. `15928394`) **+ una contraseña corta** (ej. `Pg0q`).
- **Entras con tu código + tu contraseña.**
- En español e inglés (se cambia en la pantalla de inicio o en Ajustes).

## Qué incluye

- Chats privados 1 a 1 y grupos, en tiempo real.
- Cifrado de extremo a extremo: el servidor solo guarda texto cifrado. Ni siquiera conoce los códigos ni los nombres de los grupos.
- Anti-filtraciones:
  - Marca de agua con el código de quien mira + la hora: si alguien hace captura, se sabe quién fue.
  - No se puede seleccionar ni copiar el texto de los mensajes, e imprimir está bloqueado.
  - La app se cubre en cuanto sales de ella o pierde el foco.
  - Mensajes temporales (5 min, 1 h, 24 h, 7 días) que aplican a todos en el chat.
  - Modo sigilo: los mensajes se ven borrosos hasta mantenerlos presionados.
  - Mensajes de "ver una vez": se abren una sola vez y luego el servidor borra el cifrado.
  - "Borrar para todos".
  - Aviso en el chat cuando alguien toma captura en PC (tecla Impr Pant).
  - Bloqueo automático: pide la contraseña al volver a la app.
  - Botón de pánico: borra todo del dispositivo y sale a Google.
- Código de seguridad para comparar en persona (detecta si alguien intercepta un chat privado).
- Bloquear códigos, salir de grupos, vaciar chats, cambiar contraseña, cerrar sesión en otros dispositivos y borrar la cuenta.
- Tiempo real con WebSocket (Durable Object). Si no lo configuras, la app consulta cada 4 s sola.
- Sonidos con Web Audio (se pueden apagar).

## Archivos

| Archivo | Qué es |
|---|---|
| `public/index.html` | La app completa: HTML + CSS + JS en un solo archivo, sin frameworks |
| `worker.js` | El servidor (Cloudflare Worker + D1 + Durable Object) |
| `schema.sql` | Tablas de la base de datos D1 |
| `wrangler.toml` | Configuración de Cloudflare |

## Publicarla (unos 10 minutos, plan gratis de Cloudflare)

Necesitas Node.js. Dentro de la carpeta `cifra`:

```bash
npx wrangler login
npx wrangler d1 create cifra-db
```

Copia el `database_id` que aparece y pégalo en `wrangler.toml`, donde dice `PEGA-AQUI-EL-ID-DE-TU-D1`.

```bash
npx wrangler d1 execute cifra-db --remote --file=schema.sql
npx wrangler secret put PEPPER
```

Para `PEPPER` pega un texto largo y aleatorio (mínimo 16 caracteres, mejor 40 o más). Guárdalo en un lugar seguro y **no lo cambies después**: si cambia, nadie podrá entrar a su cuenta.

```bash
npx wrangler deploy
```

Listo: la app queda en `https://cifra.<tu-subdominio>.workers.dev`. El mismo Worker sirve la app y la API.

### ¿Prefieres GitHub Pages para el HTML?

Sube `public/index.html` a tu repo (por ejemplo `ian20256.github.io/cifra/`) y, dentro del archivo, cambia:

```js
const SERVER_URL = 'https://cifra.<tu-subdominio>.workers.dev';
```

El Worker ya responde con CORS.

### Probar en tu compu

```bash
echo 'PEPPER="cualquier-texto-largo-para-pruebas"' > .dev.vars
npx wrangler d1 execute cifra-db --local --file=schema.sql
npx wrangler dev
```

Abre `http://localhost:8787` en dos navegadores (o una ventana normal y otra de incógnito) y chatea contigo mismo.

## Cómo funciona la seguridad

- Tu contraseña nunca sale del teléfono. Con PBKDF2-SHA256 (600 000 rondas) se convierte en una "prueba" que se envía para entrar y en una llave que nunca sale.
- El servidor guarda `HMAC(PEPPER, prueba)`, no la prueba. Tu llave privada y las llaves de tus grupos se guardan cifradas con tu contraseña y además con la llave del servidor, así que una copia robada de la base de datos no sirve para adivinar contraseñas.
- Chats privados: ECDH P-256 entre los dos teléfonos → AES-256-GCM.
- Grupos: PBKDF2(código + contraseña) → de ahí salen el id del grupo (lo único que ve el servidor) y la llave AES-256-GCM. Sin las dos cosas no se puede entrar ni leer.
- 5 intentos fallidos bloquean ese código 15 minutos, y también hay límite por IP.

## Límites honestos

- **Contraseñas de 4 caracteres**: son cómodas y el servidor las protege limitando intentos, pero si alguien robara el servidor completo (base de datos **y** PEPPER) podría adivinarlas en minutos. Para chats muy sensibles usa 8 caracteres o más; la app acepta hasta 64.
- **Capturas en el celular**: un navegador no puede bloquearlas ni detectarlas. Para eso están la marca de agua, el modo sigilo y "ver una vez". En PC sí se avisa con la tecla Impr Pant. Nada impide una foto con otra cámara.
- **Grupos sin administrador**: cualquiera con el código y la contraseña puede entrar. Si se filtran, crea un grupo nuevo.
- **Códigos de 5 dígitos**: hay 90 000 posibles. Si algún día se acaban, cambia `CODE_MIN`/`CODE_SPAN` e `isCode` en `worker.js` a 6 dígitos (y `rotorInput(5)` en la app).
- **Sin recuperación**: sin teléfono ni correo, si olvidas el código o la contraseña no hay forma de recuperar la cuenta.
- No hay notificaciones push (para no filtrar metadatos); los mensajes llegan con la app abierta.
- Los miembros nuevos de un grupo solo ven los mensajes enviados después de unirse.

## Ideas para la v2

Administradores de grupo (expulsar, cambiar la contraseña), fotos cifradas, notificaciones push opcionales y una versión Android con Capacitor, donde sí se puede bloquear la captura de pantalla de verdad (FLAG_SECURE).

---

<a id="english"></a>

# English

Cifra is an end-to-end encrypted chat app with no phone number or email:

- **Your identity is a 5-digit code** (e.g. `13826`), which is also how people add you.
- **Groups use an 8-digit code** (e.g. `15928394`) **+ a short password** (e.g. `Pg0q`).
- **You sign in with your code + your password.**
- Spanish and English UI (switch on the welcome screen or in Settings).

## Features

- Private 1-to-1 chats and groups, in real time.
- End-to-end encryption: the server only stores ciphertext. It doesn't even know group codes or group names.
- Anti-leak: watermark with the viewer's code and the time, no text selection or copying, printing blocked, the screen is covered when you leave the app, disappearing messages for the whole chat (5 min to 7 days), stealth mode (blurred until you press and hold), view-once messages, delete for everyone, screenshot alerts on PC (Print Screen key), auto-lock, and a panic button that wipes the device and exits to Google.
- Safety code to compare in person, blocking, leave group, clear chat, change password, sign out other devices, delete account.
- WebSocket real time via a Durable Object, with automatic 4-second polling if it isn't configured.

## Deploy (about 10 minutes, Cloudflare free plan)

Inside the `cifra` folder:

```bash
npx wrangler login
npx wrangler d1 create cifra-db        # paste the database_id into wrangler.toml
npx wrangler d1 execute cifra-db --remote --file=schema.sql
npx wrangler secret put PEPPER         # a long random string; never change it later
npx wrangler deploy
```

The app is then live at `https://cifra.<your-subdomain>.workers.dev`, served by the same Worker as the API. To host the HTML on GitHub Pages instead, set `SERVER_URL` at the top of the script in `public/index.html` to your Worker URL.

Local test: create `.dev.vars` with `PEPPER="any-long-test-string"`, run `npx wrangler d1 execute cifra-db --local --file=schema.sql`, then `npx wrangler dev` and open `http://localhost:8787` in two browsers.

## Security in short

- The password never leaves the device: PBKDF2-SHA256 (600,000 rounds) turns it into a login proof and a local key. The server keeps only `HMAC(PEPPER, proof)`.
- Private chats: ECDH P-256 → AES-256-GCM. Groups: PBKDF2(code + password) → group id (all the server sees) + AES-256-GCM key.
- Wrapped keys are sealed again with a server key derived from PEPPER, so a leaked database alone can't be used to guess passwords.
- 5 failed attempts lock that code for 15 minutes; there is also a per-IP limit.

## Honest limits

- 4-character passwords are protected by the attempt limit, but someone who stole the whole server (database **and** PEPPER) could guess them in minutes. Use 8+ characters for sensitive chats (up to 64 are allowed).
- Browsers can't block or detect phone screenshots; that's why the watermark, stealth mode and view-once exist. Nothing stops a photo taken with another camera.
- Groups have no admin: anyone with the code and password can join. If they leak, make a new group.
- 90,000 possible 5-digit codes; switch to 6 digits in `worker.js` if you ever run out.
- No account recovery and no push notifications by design.
