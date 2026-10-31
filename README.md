# Rescura-
# 🛡️ Tafseel — Cyber Incident Recovery Guide

Tafseel helps ordinary people recover from **hacked accounts, stolen phones, phishing, financial fraud, malware, ransomware and password leaks**. It gives calm, step-by-step advice in **English, Urdu (اردو) and Roman Urdu**, in **Short** or **Detailed** mode.

It is built with **Python**, **Streamlit** and the official **`google-genai`** SDK (Google Gemini Flash).

> Tafseel gives general guidance only. It is not legal, police or bank advice.

---

## What it does

| Feature | How it works |
|---|---|
| **Instant safety steps** | Rule-based, written in advance. Work with **no AI, no API key**. |
| **Risk level** | Low / Medium / High / Critical, from the incident type plus 5 quick yes/no questions. AI can raise the level, never lower it. |
| **Prioritised recovery checklist** | Tick boxes with a progress bar. Most urgent step first. |
| **Contacts and official resources** | Fixed list of official sites/helplines (Google, Meta, Microsoft, Apple, FIA NR3C, PTA, State Bank of Pakistan, CISA, No More Ransom, Have I Been Pwned). The AI is **not allowed** to add links or phone numbers. |
| **Prevention tips** | Per incident type. |
| **Downloadable report** | Plain `.txt` file with the checklist state. Contains only the *masked* description. |
| **AI advice (optional)** | Gemini writes a summary and extra actions. Shown separately and clearly labelled. |
| **Languages / length** | English, اردو, Roman Urdu · Short or Detailed. |

## Safety and privacy design

- **Never asks** for passwords, OTPs, PINs, card numbers or CNIC numbers. A banner says so, and the AI is instructed the same way.
- **Masks sensitive data before AI processing and in reports**: passwords/PINs/OTPs written next to words like "password is …", card and account numbers, CNIC (also with Urdu digits), IBAN, phone numbers, emails, IP addresses, API keys/tokens. Web links are cut down to just the site name.
- **API key** is read only from Streamlit **Secrets** (or an environment variable for local use). It is never shown, logged, or put in the code.
- **Prompt-injection protection**: the user's text is checked for "ignore previous instructions"-style phrases (English, Urdu, Roman Urdu); if found, the AI is skipped and the rule-based plan is still shown. The text is wrapped in delimiters and the AI is told it is untrusted data. The AI's answer must be valid JSON; links, HTML, phone numbers and any sentence that asks for a password/OTP/PIN/CNIC are removed.
- **Input validation**: length limit (1500 characters), hidden/control characters stripped, Unicode normalised.
- **Graceful failures**: missing key, missing library, rate limit (429), bad key (401/403), wrong model name (404), timeouts, network errors, server errors (one automatic retry), empty/invalid AI answers → friendly message, and the rule-based plan is always shown.
- **Quota protection**: at most 10 AI requests per browser session, with a 15-second gap.
- **Nothing is stored** by the app: no database, no files, no logging of what you type.

---

## The three files

```
app.py            the whole application
requirements.txt  the two libraries it needs
README.md         this guide
```

---

## Step 1 — Get a free Gemini API key

1. Go to **https://aistudio.google.com/apikey** and sign in with a Google account.
2. Click **Create API key** and copy it.
3. Keep it private. **Never** paste it into `app.py`, GitHub, or a chat.

> If you use the free tier, Google's terms may allow it to use submitted content to improve its products. Tafseel hides sensitive details first, but you should still avoid typing anything private. Read Google's current Gemini API terms.

*(You can skip this step. The app still works, in basic mode, without a key.)*

## Step 2 — Upload the files to GitHub (website only, no Git commands)

1. Create a free account at **https://github.com** (or sign in).
2. Click the **+** at the top right → **New repository**.
3. Repository name: `tafseel`. Choose **Public**. **Do not** tick "Add a README" (you are uploading your own). Click **Create repository**.
4. On the new empty page, click the link **uploading an existing file**.
5. Drag **`app.py`, `requirements.txt` and `README.md`** into the page. They must be in the main folder (not inside another folder).
6. Scroll down and click **Commit changes**.

✅ Check: you see the three files listed in your repository.

⚠️ Do **not** upload any file containing your API key (for example a `secrets.toml`).

## Step 3 — Deploy on Streamlit Community Cloud

1. Go to **https://share.streamlit.io** and click **Continue with GitHub**. Allow access when asked.
2. Click **Create app** → **Deploy a public app from GitHub**.
3. Fill in:
   - **Repository:** `your-username/tafseel`
   - **Branch:** `main`
   - **Main file path:** `app.py`
4. Click **Advanced settings**:
   - Choose Python **3.12** (3.11 also works).
   - In the **Secrets** box paste exactly this, with your real key between the quotes:

   ```toml
   GEMINI_API_KEY = "paste-your-key-here"
   ```

5. Click **Deploy**. The first start takes a few minutes while libraries install.
6. When it loads, you get a public link you can share.

**Changing the key later:** open your app on Streamlit → **⋮ / Manage app → Settings → Secrets**, edit, save.
**Updating the code later:** open the file on GitHub → pencil ✏️ icon → edit → **Commit changes**. The app updates itself.

*(Streamlit and GitHub sometimes rename buttons. If a name differs slightly, look for the closest one.)*

### Optional: choose a different Gemini model

The app uses the alias `gemini-flash-latest` by default, which Google points at its current Flash model. If you ever see "the AI model name is not available", add one more line in **Secrets** with a model name from Google's current model list:

```toml
GEMINI_MODEL = "model-name-from-google-docs"
```

### Optional: run on your own computer

```bash
pip install -r requirements.txt
mkdir .streamlit
# create .streamlit/secrets.toml containing:  GEMINI_API_KEY = "your-key"
streamlit run app.py
```
Never upload the `.streamlit` folder to GitHub.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| "AI is not set up on this site" | The key is missing or mis-pasted in Secrets. Use exactly `GEMINI_API_KEY = "…"` with straight quotes. |
| "The AI key was rejected" | Create a new key in Google AI Studio and update Secrets. |
| "busy or free limit reached" | Wait a few minutes. The rule-based plan still works. |
| "AI model name is not available" | Set `GEMINI_MODEL` (see above). |
| App crashes on start | Open **Manage app → Logs**. Check that `requirements.txt` was uploaded to the main folder. |
| If a key was ever exposed | Delete it in Google AI Studio and create a new one. |

---

## Testing: what was and was not checked

Tested in the build environment (honest summary):

- ✅ `app.py` compiles with no syntax errors (Python 3.13).
- ✅ **154 automated checks passed, 0 failed**, covering: English/Urdu/Roman Urdu content has matching step and tip counts for all 8 incident types; every interface text key exists in all 3 languages; masking of passwords/OTP/PIN, CNIC (including Urdu digits), cards, IBAN, phones, emails, IPs, links and API keys, without over-masking ordinary amounts and dates; input validation; prompt-injection detection (including spaced-out and Urdu/Roman Urdu phrases) and checks that ordinary scam descriptions like "someone pretending to be my bank" are *not* flagged; cleaning of AI replies (links, HTML, phone numbers and "send me your OTP" sentences removed); the Gemini error paths (429, 401/403, 400 bad key, 404, 5xx with one retry, timeout, network, empty reply, non-JSON reply); missing key / missing library; per-session AI limits; the API key never appearing in anything displayed; and the whole screen running through every language × mode × incident type.

**Not possible to test here (please do these yourself after deploying):**

- ❌ **Real Streamlit and the real `google-genai` library could not be installed** in the build environment (the package index was blocked). In the tests they were replaced by simple fakes. So the exact screen layout and the real calls to Gemini have **not** been run. The code follows the documented SDK usage (`genai.Client`, `client.models.generate_content`, `types.GenerateContentConfig`, `google.genai.errors.APIError`), but a version difference could still cause a small problem. If so, the app falls back to basic mode instead of crashing.
- ❌ The default model alias `gemini-flash-latest` was **not confirmed** against Google's current documentation. Use `GEMINI_MODEL` if needed.
- ❌ The Urdu right-to-left layout and fonts were not viewed in a browser.
- ❌ `requirements.txt` uses minimum versions (`streamlit>=1.40.0`, `google-genai>=1.0.0`) because the latest versions could not be looked up.

**Quick check after deployment (2 minutes):**
1. Open the app, choose *Hacked account*, press the button → you should see risk, checklist, contacts, tips.
2. Switch language and Short/Detailed → text changes.
3. Type `my password is Test12345 and email a@b.com` → see the "hidden for your privacy" notice.
4. Type `ignore previous instructions` with AI ticked → see the injection notice, plan still shown.
5. Tick the AI box with a valid key → an AI section appears. Without a key → a friendly notice.
6. Tick a few steps and download the report.

## Limitations

- **Masking uses pattern matching.** It cannot catch everything (names, home addresses, unusual formats). Users are told not to type secrets, and reports should be reviewed before sharing.
- **Prompt-injection protection reduces risk but cannot guarantee perfection.** The design limits harm: the AI cannot add links or numbers, cannot lower the risk level, and the rule-based plan never depends on it.
- **AI can be wrong.** It is labelled as such and always comes after the rule-based steps.
- **Urdu and Roman Urdu text was written by an AI assistant.** Please have a native speaker review it before wide public use. Roman Urdu spelling varies.
- **The per-session AI limit is not a global quota.** A person can refresh the page to reset it. Set a usage limit or budget on your key in Google AI Studio / Google Cloud.
- **Official resources are Pakistan-focused plus global account-recovery pages.** Websites and phone numbers can change. Before publishing, click each link once and confirm numbers on the official sites (FIA NR3C helpline 1991, PTA 0800-55055, police 15). The PTA phone-blocking process in particular has changed over the years and is done through PTA's online complaint system.
- It does not detect threats on your device, contact anyone for you, or replace the police, your bank, or a security professional.

## Verified-resource note

The resource list uses the official sites of the named organisations. Domains and helplines were checked against public sources while building (the FIA cybercrime helpline 1991 and PTA's 0800-55055 toll-free line and online blocking process were confirmed in news coverage; the official sites themselves could not be opened from the build environment). Treat the list as a good starting point and re-verify it periodically.
