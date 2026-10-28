# Y2JB

Userland code execution using the PS5 YouTube app.

## Requirements

- At least 4.03 firmware PS5

### For Jailbroken PS5 (Webkit, Lua, BD-JB)
- Fake or legit activated PS5
- For firmware 4.03 to 12.40 get YouTube app (PPSA01650) version 01.000.003 PKG
- For firmware 12.60 and up get YouTube app (PPSA01650) version 01.000.030 PKG
- FTP access to the console

### For Non-Jailbroken PS5
- USB flash drive
- Pre-made backup file

## Setup Instructions

### Configure Network DNS Settings (Optional, but highly recommended)

1. Navigate to **Settings > Network > Settings > Set Up Internet Connection**
2. Scroll to the bottom and select **Set Up Manually**
3. Choose your connection type:
   - **Use WiFi**: Enter your network name and password manually, then set security to "WPA-Personal..."
   - **Use a LAN Cable**: Proceed to the next step
4. Under **DNS Settings**, change from "Automatic" to **Manual**
5. Set **Primary DNS** to `127.0.0.2` (leave Secondary DNS blank)
6. Press **Done** and wait for the connection to establish

**Note:** You may see a network/PSN connection error - this is expected and can be safely ignored. The console will still function normally for YouTube payload delivery.

**Alternative:** Instead of using 127.0.0.2, you can block PSN servers using your custom DNS server.

#### Why is Setting DNS to 127.0.0.2 Required?

The DNS configuration is critical for Y2JB to function properly for two technical reasons:

1. **Blocking PSN Connections**: Setting the DNS to 127.0.0.2 (localhost) prevents the PS5 from reaching PlayStation Network servers. This blocks both the YouTube app and system firmware update prompts that would otherwise interfere with the exploit.

### Fake Account Activation

**Note:** If you're using the backup file from the releases page, you can skip this section.

Y2JB requires a **fake-activated account** to run properly.

**Important:** If you have a legit PSN-activated account (officially registered through PlayStation Network), you **cannot** use it directly with Y2JB. You must create and use a separate fake-activated account instead.

**To fake activate an account:**
1. Create a new offline account on your PS5
2. While logging in to this new account, open **etaHEN toolbox**
3. Navigate to the **"Remote Play"** menu
4. The account will be automatically fake activated

### Jailbroken PS5

1. Install YouTube app PKG on your PS5
2. Download `download0.dat` from the releases page.
3. Transfer `download0.dat` with [Prospero Manager](https://github.com/notmaj0r/ProsperoMgr), [FTP](https://github.com/ps5-payload-dev/ftpsrv), or any file manager to the path matching your YouTube app's TITLE ID (create the folder if it does not exist):
   ```
   /user/download/PPSA01650
   /user/download/PPSA01651
   /user/download/PPSA01652
   ```
   You only need to use one path. Choose the one matching your YouTube app's TITLE ID.

### Non-Jailbroken PS5

1. Download the backup file from the releases page  
**Firmware 4.03 – 12.40** → `Y2JB_backup_1.6(4.03)`  
**Firmware 12.60 and up** → `Y2JB_backup_1.6(12.20)`  
2. Follow Sony's official guide to [restore backup data from USB](https://www.playstation.com/en-gb/support/hardware/back-up-ps5-data-USB/)

**⚠️ WARNING:** Restoring backup data **WILL FACTORY RESET YOUR PS5**. All data on your console will be erased.

### Blocking YouTube Updates (appinfo_editor.py)

**⚠️ CRITICAL WARNING:** Database corruption can result in the deletion of **ALL installed FPKGs and savedata** stored on your internal storage. Before proceeding with this section, **backup your savedata** using the PS5's built-in backup and restore feature in Settings to prevent data loss.

This script prevents the YouTube app from updating if you accidentally connect to the internet. Allowing updates can cause a softlock that prevents YouTube from launching (see next section for fix instructions).  

**Steps:**
1. After installing the YouTube PKG, retrieve `/system_data/priv/mms/appinfo.db` from your PS5 using FTP
2. Place `appinfo.db` in the same directory as `appinfo_editor.py`
3. Run the script to modify `appinfo.db` and block YouTube updates:
   ```
   python appinfo_editor.py
   ```
4. **Before replacing the file** on your PS5 (to avoid database corruption):
   - Close the YouTube app completely
   - Navigate to the Settings page
   - Ensure no packages are currently being installed or updated
5. Use FTP to replace `/system_data/priv/mms/appinfo.db` with the modified version
6. If you don't receive any database corruption notification, reboot your PS5

### How to Escape from YouTube Softlock
![youtube_softlock](https://github.com/user-attachments/assets/62012e7f-e004-4e20-8c18-bd7d0bbd72b1)

This issue typically occurs when you connect to the internet **before** setting the 127.0.0.2 DNS (most common with WiFi users).

**Recovery steps:**
1. Once softlocked, connect to the internet normally without custom DNS
2. Launch YouTube again and deny the system software update popup
3. The YouTube app should now launch successfully
4. Run the jailbreak and load HEN
5. Set the DNS to 127.0.0.2 again, then uninstall YouTube
6. Follow the **Jailbroken PS5** section and **Blocking YouTube Updates (appinfo_editor.py)** section again
7. Restart your PS5. Done.

## Sending Payloads

**Note:** The Remote JS Server does not always use port 50000. While it typically defaults to port 50000, it may occasionally use a different port - this is normal behavior, not a bug.

You can send payloads using `payload_sender.py` (requires Python).

**Usage:**
```
python payload_sender.py <host> <file>
python payload_sender.py <host> <port> <file>
```

**Examples:**
```
python payload_sender.py 192.168.1.100 helloworld.js
python payload_sender.py 192.168.1.100 50000 helloworld.js
python payload_sender.py 192.168.1.100 9020 payload.bin
```

### Lapse Payload

**Firmware Compatibility:** Only works up to firmware 10.01

After the Lapse payload succeeds, you need to send the HEN or other elf binary to port **9021**. You can use any TCP payload sender such as:
- `netcat`
- `payload_sender.py`

**Example:**
```
python payload_sender.py 192.168.1.100 9021 hen.bin
```

### Relapse Payload

**Firmware Compatibility:** Works up to firmware 13.60
- Requires an active network connection (Wi-Fi or Ethernet). 

After the Relapse payload succeeds, elfldr starts listening on port **9021**. If YouTube is opened again while the PS5 is already jailbroken, Auto Load skips the exploit and retries Payload Manager. Reopen YouTube to relaunch it after it closes or fails, as long as elfldr is still listening on port 9021.

### Automatic YouTube home-screen icon and name

After Relapse succeeds, Auto Load copies the 512×512 SKYBOZ icon to `/user/appmeta/PPSA01650/icon0.png` and to the persistent file `SKYBOZ_LOADER_icon0.png` in the same folder. Its helper backs up `/system_data/priv/mms/app.db` and `/system_data/priv/mms/appinfo.db` under `/data/skyboz-loader/`, then updates the icon path and the displayed tile name to `SKYBOZ LOADER` for PPSA01650. The YouTube application itself remains YouTube. Restart the console once after the first successful installation so the home-screen cache reloads. A YouTube update or reinstall can reset the metadata; launching Auto Load again reapplies it.

**Database safety:** before trying this build, copy both databases to a PC over FTP as recovery copies. The helper also creates verified pre-change backups named `app.db.before-skyboz-branding` and `appinfo.db.before-skyboz-branding` in `/data/skyboz-loader/`. Each database is changed in its own transaction; if the helper reports an error, keep the backups and copy the error from the YouTube/Relapse log before retrying.
## Credits

* **[shahrilnet](https://github.com/shahrilnet), [null_ptr](https://github.com/n0llptr)** - Referenced many codes from [Remote Lua Loader](https://github.com/shahrilnet/remote_lua_loader)
* **[BenNoxXD](https://github.com/BenNoxXD)** - [ClosePlayer](https://github.com/BenNoxXD/PS5-BDJ-HEN-loader) reference
* **[ntfargo](https://github.com/ntfargo)** - Thanks for providing V8 CVEs and CTF writeups
* **abc and psfree team** - Lapse implementation
* **[flat_z](https://github.com/flatz) and [LM](https://github.com/LightningMods)** - Helping implement GPU rw using direct ioctl
* **[john-tornblom](https://github.com/john-tornblom) and [EchoStretch](https://github.com/EchoStretch)** - Providing elfldr.elf payload
* **[hammer-83](https://github.com/hammer-83)** - Various BD-J PS5 exploit references
* **[zecoxao](https://github.com/zecoxao), [idlesauce](https://github.com/idlesauce), and [TheFlow](https://github.com/theofficialflow)** - Helping troubleshoot dlsym
* **[Dr.Yenyen](https://github.com/DrYenyen) and PS5 R&D community** - Testing Y2JB
* **Rush** - Creating Y2JB backup file
* **[ufm42](https://github.com/ufm42)** - [kexp](https://github.com/ufm42/kexp) used for PS5 post JB all-in-one shellcode
* **[maj0r](https://github.com/notmaj0r)** - Relapse implementation

## Disclaimer

This tool is provided as-is for research and development purposes only.  
Use at your own risk.  
The developers are not responsible for any damage, data loss, or consequences resulting from the use of this software.  
