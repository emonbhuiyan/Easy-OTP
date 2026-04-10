# Easy OTP

Easy OTP is a lightweight browser-only TOTP generator built for quick access to one-time passwords directly from your browser.

Nothing is uploaded, synced, or stored anywhere except your own browser.

It is designed for temporary or low-risk use. For important accounts, use a dedicated authenticator app such as Google Authenticator, Microsoft Authenticator, Authy, or similar apps.

---

## Features

- Generate live TOTP codes in the browser
- Supports full `otpauth://totp/...` links
- Supports plain Base32 secret keys
- Automatically detects:
  - Issuer
  - Label
  - Algorithm
  - Digits
  - Period
- Rename labels and issuer names after adding
- Save OTP entries in browser local storage
- Temporary mode without saving
- Copy codes with one click
- Delete individual OTPs
- Clear all saved OTPs
- Live refresh countdown and progress bar
- Mobile-friendly clean UI inspired by Google products

---

## Supported Input Formats

### Full otpauth URL

`otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub`

### Base32 Secret

`JBSWY3DPEHPK3PXP`

---

## Browser Storage Notice

Saved OTPs are stored only in your browser using Local Storage.

They may be deleted automatically if you:

- Clear browser data
- Clear cache or cookies
- Use a browser cleaner
- Change browser profile
- Use private/incognito mode

Because of that, Easy OTP should not be used as the only place to store important authentication secrets.

---

## Recommended Use

Good for:

- Quickly checking a TOTP code
- Temporary OTP access
- Testing TOTP setups
- Development and debugging

Not recommended for:

- Banking accounts
- Main email accounts
- Important social media accounts
- Anything you cannot afford to lose access to

---

## Project Structure

`index.html`  
Main page and layout

`style.css`  
Styles and UI

`script.js`  
TOTP logic, local storage, rendering, copy, edit, and delete features

---

## How To Use

1. Open the website
2. Paste either:
   - An `otpauth://totp/...` link
   - A Base32 secret key
3. Optionally enter a custom label
4. Choose whether to save it locally
5. Click **Add TOTP**
6. Your code will appear instantly

---

## Local Development

Clone the repository:

`git clone https://github.com/yourusername/easy-otp.git`

Open the project folder:

`cd easy-otp`

Then simply open `index.html` in your browser.

You can also use a simple local server if you want:

`python -m http.server`

Then visit:

`http://localhost:8000`

---

## Technologies Used

- HTML5
- CSS3
- JavaScript
- Web Crypto API
- Local Storage
- Bootstrap 5
- Font Awesome

---

## Disclaimer

Easy OTP is only for quick browser use.

For important accounts, use a proper authenticator app instead.