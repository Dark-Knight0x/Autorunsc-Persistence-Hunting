# Lab  — Hunting Persistence with Autorunsc.exe

> **Goal:** Filter the output of the persistence-auditing tool **Autorunsc.exe**, use digital signatures and a clean baseline to cut down noise, and identify suspicious **Auto-Start Extensibility Points (ASEPs)**.

---

## Learning Objectives

1. Filter and examine output from the persistence-auditing tool **Autorunsc.exe**.
2. Use **digital signature** information to filter a large dataset.
3. Categorize and identify **anomalous ASEPs** (Auto-Start Extensibility Points).
4. Use a **system baseline** and **file hashes** to reduce false positives.

---

## Core Idea

Malware needs a way to survive a reboot. It does this by hooking into an **auto-start location** (a "persistence point"). Autorunsc lists _every_ auto-start entry on a system — usually thousands. The hunting strategy is to **strip away everything we trust**, so only the suspicious leftovers remain.

```
ALL auto-start entries
        │  remove trusted-signed code
        ▼
   Unsigned / untrusted / blank signers
        │  keep only Enabled entries
        ▼
   Small list of candidates to investigate
```

---

## Data-Reduction Workflow

Open `rd01.shieldbase.com-Autorunsc.csv` in **Timeline Explorer**, then apply filters in this order:

<img width="622" height="261" alt="image" src="https://github.com/user-attachments/assets/318f3e67-8a78-49a4-9773-9c6d9ed6e7f5" />

<br>
<br>

<br>


<img width="1792" height="1151" alt="image" src="https://github.com/user-attachments/assets/3dcaad14-db61-4696-b91b-f6b10ead6f30" />
<br>
<br>
<br>

### 1. Filter the **Signer** column

Keep only the entries we do **not** automatically trust:
<img width="346" height="607" alt="image" src="https://github.com/user-attachments/assets/028976a9-e351-4af2-926c-b7967c8a6477" />

- **`(Not verified)` publishers** — e.g. _(Not verified) Microsoft Corporation_, _(Not verified) prometheus-community_.
- **Publishers that are not major software vendors** — in this lab: _F-Response, FOXIT, Sysinternals, VELOCIDEX_.
- **Blanks** — entries with no publisher and no digital signature at all.

> ⚠️ **Trade-off:** Trusting big vendors (Microsoft, Apple, Google, McAfee) can cause **false negatives** if a certificate was stolen — but stolen certs from major vendors are extremely rare and would be national news. It's a reasonable first cut.

### 2. Filter the **Enabled** column

Select **Enabled** only. This drops disabled/unused entries and leaves active persistence points.
<img width="373" height="372" alt="image" src="https://github.com/user-attachments/assets/df5e216a-8f84-4ac1-9fe0-b351a43cb638" />

✅ You're now ready to analyze.

---

## Question 1 — Auto-Start Categories Present

**Q:** Review the _Category_ column. What types of auto-start locations are present?

**A:** Six categories:

<br>
<img width="208" height="266" alt="image" src="https://github.com/user-attachments/assets/3b77f1d3-22eb-4e09-8438-06af58171db6" />


|Category|What it covers|
|---|---|
|**Services**|Background services that start at boot|
|**Drivers**|Kernel-level drivers (should be signed on 64-bit Windows)|
|**Known DLLs**|DLLs loaded by core Windows processes|
|**Logon**|Programs that run when a user logs on|
|**Tasks**|Scheduled tasks|
|**Explorer**|Shell extensions / Explorer hooks|

---

## Question 2 — Services: Why scrutinize **PsShutdownSvc**?

The Services output contains several legitimate SRL tools (F-Response, Velociraptor, Prometheus `windows_exporter`, Foxit). The interesting one is **PsShutdownSvc**.

**Why it deserves a closer look:**

- **Sysinternals** admin tools are frequently **abused by attackers**.
- The executable sits in **`c:\windows`** — a directory malware often uses to look credible.
- The filename **`pssdnsvc.exe` does not match** the expected tool name _PsShutdown_ (name mismatch is a classic red flag).
- It can **shut down or reboot machines**, which could disrupt users and **impede incident response / recovery**.

**Verdict:** Online research + checking the **file hash** shows it's a **legitimate** SysInternals PsShutdown component. Still worth flagging — confirm with an SRL admin that it was installed for genuine admin use.

> 💡 **Lesson:** A name mismatch + suspicious location justifies investigation, but the **hash** is what confirms innocence or guilt.

---

## Question 3 — Drivers: What's missing from the baseline?

On 64-bit Windows, drivers should be signed by trusted entities, so we expect very few entries. Compare each driver's _Image Path_ against a **known-clean baseline** image.
<img width="988" height="355" alt="image" src="https://github.com/user-attachments/assets/a94487a9-7f38-4540-b738-229333fc2d44" />

- **Baseline used:** `W11_21H2_Pro_20221220_22000.1335.csv`
- **Source:** the _VanillaWindowsReference_ GitHub project (`AndrewRathbun/VanillaWindowsReference`).

**Q:** Which driver is missing from the baseline?

**A: `atmfd.dll`**

- It appears to be an **Adobe font file**; the baseline only contains files from a clean Microsoft install, so its absence is explainable.
- Autorunsc reported **"File not found"** → the file wasn't on disk when the audit ran → it was **not active/in use** at that time.
- Because there was no file to validate, there is **no digital signature and no hash** for it.

**What to do:** With so little data, document `atmfd.dll` as a **"file of interest"** and see if later artifacts (or a copy from another system) give more context.

> ✅ **All other drivers** were present in the baseline at the **expected paths**.

---

## Question 4 — Tasks: Hunting Scheduled-Task Persistence

Modern Windows systems often have **200+ scheduled tasks**, making them an easy hiding spot. You see a smaller subset here because trusted-signed tasks were already filtered out (keep filtering for **Enabled** + untrusted **Signer**).

### 4.1 — Which two tasks should you prioritize?

**A:** `c:\windows\installoffice2019.bat` and `c:\windows\system32\stun.exe`
<img width="519" height="383" alt="image" src="https://github.com/user-attachments/assets/fda282aa-350f-4a4e-beae-7bbac3496271" />

**Why:** They are the **only two not marked "File not found."**

|State|Meaning|
|---|---|
|**File exists**|Task can actually run → persistence is **live and ready to fire**|
|**File not found**|Dead task → can't execute anything|

### 4.2 — What's anomalous about the **Install Office 2019** task?

- It's a **`.bat` (batch) file** — increasingly uncommon and often abused to script malicious actions.
- Located in **`c:\windows`** — a known malware-target folder.
- The filename is **not** in the vanilla Windows baseline.
- **No matching hashes in VirusTotal** at the time of the SRL intrusion. _(If you get a hit today, check the vendor detection count before deciding.)_
- Legitimate scheduled tasks usually live in **`C:\Windows\Tasks`** or **`System32\Tasks`**, not loose in `c:\windows`.

### 4.3 — What's anomalous about the **SRL Update Service** task?

- The `.exe` lives in **`c:\windows\system32`** — heavily targeted, though also full of legit files.
- The filename is **not** in the vanilla baseline.
- **No VirusTotal hashes** at intrusion time. A novel `.bat` having no VT match is somewhat normal, but a **System32 executable** never uploaded to VirusTotal is a **huge red flag**. _(It may be submitted by now — check vendor detections if so.)_
- Again, scheduled tasks normally reside in **`C:\Windows\Tasks`** / **`System32\Tasks`**.

### 4.4 — What's interesting about the two **packer-windows-update** tasks?

1. The **Launch String** shows **`cmd.exe`** launching a **PowerShell** script.
2. The PowerShell script is **Base64-encoded** — a common obfuscation/evasion technique.

**Decode the Base64** to reveal the actual script. Inside the 508 Windows VM you can use WSL (Ubuntu):

<img width="960" height="483" alt="image" src="https://github.com/user-attachments/assets/80be804f-9b3d-44a1-86d4-a5a13a498c4c" />


```bash
echo "base64data" | base64 -d
```

> 🚩 `cmd → powershell → Base64-encoded payload` is a textbook malicious-persistence pattern.

---

## Key Takeaways

- **Trust-based filtering** (signatures) is the fastest first cut, but accept the small false-negative risk from stolen certs.
- **Baselines** (VanillaWindowsReference) tell you what _should_ be on a clean system; anything missing is worth a note.
- **File hashes + VirusTotal** turn "suspicious" into "confirmed" — a System32 `.exe` with **no VT history** is far more alarming than an unknown `.bat`.
- **"File not found"** = dead/inactive entry; **file present** = live persistence to prioritize.
- Watch for the classics: **name mismatches**, **wrong locations** (`c:\windows` instead of `System32\Tasks`), and **Base64-encoded PowerShell**.
