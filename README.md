# 🚀 edgetunnel
This is a script based on the CF Worker platform, modified from the original version to display VLESS configuration information and convert it into subscription content. With this script, you can easily convert VLESS configuration information into tools like Clash or Singbox using online configuration conversion.

- **Latest edgetunnel tutorial**: https://www.youtube.com/watch?v=tKe9xUuFODA ***Must-watch content! Must-watch content! Must-watch content!!!***
- **Error 1101 explanation**: https://www.youtube.com/watch?v=r4uVTEJptdE

- Telegram discussion group: [@CMLiussss](https://t.me/CMLiussss)

## ⚠️ Disclaimer

This disclaimer applies to the "edgetunnel" project on GitHub (hereinafter referred to as "this project"), project link: https://github.com/cmliu/edgetunnel.

### Purpose
This project is designed and developed for educational, research, and security testing purposes only. It aims to provide a tool for security researchers, academics, and technology enthusiasts to explore and practice network communication technologies.

### Legality
When downloading and using the code of this project, you must comply with the laws and regulations applicable to the user. The user is responsible for ensuring that their actions comply with the legal framework, rules, and other relevant regulations of their region.

### Disclaimer
1. As the **secondary development author** of this project (hereinafter referred to as "the author"), I, **cmliu**, emphasize that this project should only be used for legal, ethical, and educational purposes.
2. The author does not endorse, support, or encourage any form of illegal use. If this project is found to be used for any illegal or unethical activities, the author will strongly condemn it.
3. The author is not responsible for any illegal activities carried out by any person or organization using the code of this project. Any consequences arising from the use of this project's code shall be borne by the user.
4. The author is not responsible for any direct or indirect damages that may be caused by using the code of this project.
5. To avoid any unexpected consequences or legal risks, users should delete the code within 24 hours of using it.

By using the code of this project, the user indicates that they understand and agree to all the terms of this disclaimer. If the user does not agree to these terms, they should immediately stop using this project.

The author reserves the right to update this disclaimer at any time without prior notice. The latest version of the disclaimer will be posted on the project's GitHub page.

## 🔥 Risk Warning
- Avoid leaking node configuration information by submitting fake node configurations to the subscription service.
- Alternatively, you can choose to deploy the [WorkerVless2sub subscription generation service](https://github.com/cmliu/WorkerVless2sub) yourself, so you can take advantage of the convenience of the subscription generator.

## 💡 How to use?
### ⚙️ Workers Deployment Method [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=191s)

<details>
<summary><code><strong>"Workers Deployment Text Tutorial"</strong></code></summary>

1. Deploy CF Worker:
   - Create a new Worker in the CF Worker console.
   - Paste the content of [worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) into the Worker editor.
   - Change the `userID` on line 4 to your own **UUID**.

2. Access subscription content:
   - Visit `https://[YOUR-WORKERS-URL]/[UUID]` to get the subscription content.
   - For example, `https://vless.google.workers.dev/90cd4a77-141a-43c9-991b-08263cfe9c10` is your universal adaptive subscription address.
   - For example, `https://vless.google.workers.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sub` is the Base64 subscription format, suitable for PassWall, SSR+, etc.
   - For example, `https://vless.google.workers.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?clash` is the Clash subscription format, suitable for OpenClash, etc.
   - For example, `https://vless.google.workers.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sb` is the singbox subscription format, suitable for singbox, etc.

3. Bind a custom domain to workers:
   - In the workers console, under the `Triggers` tab, click `Add Custom Domain`.
   - Enter the subdomain you have transferred to the CF domain name resolution service, for example: `vless.google.com`, then click `Add Custom Domain` and wait for the certificate to take effect.
   - **If you are a beginner, you can take off now, you don't need to read any further!!!**

4. Use your own `preferred domain`/`preferred IP` subscription content:
   - If you want to use your own preferred domain or preferred IP, you can refer to the deployment instructions in the [WorkerVless2sub GitHub repository](https://github.com/cmliu/WorkerVless2sub) to build it yourself.
   - Open the [worker.js](https://github.com/cmliu/edgetunnel/blob/main/_worker.js) file, find the `sub` variable on line 12, and change it to the address of your deployed subscription generator. For example, `let sub = 'sub.cmliussss.workers.dev';`, note that you should not include protocol information and symbols such as https.
   - Note that if you use your own subscription address, the `sub` domain of the subscription generator and the domain of `[YOUR-WORKER-URL]` must not belong to the same top-level domain, otherwise an exception will occur. You can assign the domain assigned by workers.dev to the `sub` variable.

</details>

### 🛠 Pages Upload Deployment Method **Best Recommendation!!!** [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=436s)

<details>
<summary><code><strong>"Pages Upload File Deployment Text Tutorial"</strong></code></summary>

1. Deploy CF Pages:
   - Download the [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file and give it a Star!!!
   - In the CF Pages console, select `Upload asset`, name your project, and click `Create project`. Then upload the downloaded [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file and click `Deploy site`.
   - After the deployment is complete, click `Continue to site`, then select `Settings` > `Environment variables` > **Define variables for production environment** > `Add variable`.
     Enter **UUID** for the variable name and your UUID for the value, then click `Save`.
   - Return to the `Deployments` tab, click `Create new deployment` in the lower right corner, re-upload the [main.zip](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip) file, and click `Save and deploy`.

2. Access subscription content:
   - Visit `https://[YOUR-PAGES-URL]/[YOUR-UUID]` to get the subscription content.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10` is your universal adaptive subscription address.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sub` is the Base64 subscription format, suitable for PassWall, SSR+, etc.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?clash` is the Clash subscription format, suitable for OpenClash, etc.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sb` is the singbox subscription format, suitable for singbox, etc.

3. Bind a CNAME custom domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console, under the `Custom domains` tab, click `Set up a custom domain`.
   - Enter your custom subdomain, be careful not to use your root domain, for example:
     If the domain assigned to you is `fuck.cloudns.biz`, then enter `lizi.fuck.cloudns.biz` for the custom domain;
   - Follow CF's requirements to return to your domain's DNS service provider, add a CNAME record `edgetunnel.pages.dev` for this custom domain `lizi`, and then click `Activate domain`.
   - **If you are a beginner, then after your pages are bound to a `custom domain`, you can take off directly, you don't need to read any further!!!**

4. Use your own `preferred domain`/`preferred IP` subscription content:
   - If you want to use your own preferred domain or preferred IP, you can refer to the deployment instructions in the [WorkerVless2sub GitHub repository](https://github.com/cmliu/WorkerVless2sub) to build it yourself.
   - In the Pages console, under the `Settings` tab, select `Environment variables` > `Production` > `Edit variables` > `Add variable`;
   - Set the variable name to `SUB` and the corresponding value to the address of your deployed subscription generator. For example, `sub.cmliussss.workers.dev`, then click **Save**.
   - Then in the Pages console, under the `Deployments` tab, select `All deployments` > `...` on the far right of the latest deployment > `Retry deployment`.
   - Note that if you use your own subscription address, the `SUB` domain of the subscription generator and the domain of `[YOUR-PAGES-URL]` must not belong to the same top-level domain, otherwise an exception will occur. You can assign the domain assigned by Pages.dev to the `SUB` variable.

</details>

### 🛠 Pages GitHub Deployment Method [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=317s)

<details>
<summary><code><strong>"Pages GitHub Deployment Text Tutorial"</strong></code></summary>

1. Deploy CF Pages:
   - First, Fork this project on Github and give it a Star!!!
   - In the CF Pages console, select `Connect to Git`, select the `edgetunnel` project, and click `Start setup`.
   - On the `Set up builds and deployments` page, select `Environment variables (advanced)` and `Add variable`.
     Enter **UUID** for the variable name and your UUID for the value, then click `Save and deploy`.

2. Access subscription content:
   - Visit `https://[YOUR-PAGES-URL]/[YOUR-UUID]` to get the subscription content.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10` is your universal adaptive subscription address.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sub` is the Base64 subscription format, suitable for PassWall, SSR+, etc.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?clash` is the Clash subscription format, suitable for OpenClash, etc.
   - For example, `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sb` is the singbox subscription format, suitable for singbox, etc.

3. Bind a CNAME custom domain to Pages: [Video Tutorial](https://www.youtube.com/watch?v=LeT4jQUh8ok&t=851s)
   - In the Pages console, under the `Custom domains` tab, click `Set up a custom domain`.
   - Enter your custom subdomain, be careful not to use your root domain, for example:
     If the domain assigned to you is `fuck.cloudns.biz`, then enter `lizi.fuck.cloudns.biz` for the custom domain;
   - Follow CF's requirements to return to your domain's DNS service provider, add a CNAME record `edgetunnel.pages.dev` for this custom domain `lizi`, and then click `Activate domain`.
   - **If you are a beginner, then after your pages are bound to a `custom domain`, you can take off directly, you don't need to read any further!!!**

4. Use your own `preferred domain`/`preferred IP` subscription content:
   - If you want to use your own preferred domain or preferred IP, you can refer to the deployment instructions in the [WorkerVless2sub GitHub repository](https://github.com/cmliu/WorkerVless2sub) to build it yourself.
   - In the Pages console, under the `Settings` tab, select `Environment variables` > `Production` > `Edit variables` > `Add variable`;
   - Set the variable name to `SUB` and the corresponding value to the address of your deployed subscription generator. For example, `sub.cmliussss.workers.dev`, then click **Save**.
   - Then in the Pages console, under the `Deployments` tab, select `All deployments` > `...` on the far right of the latest deployment > `Retry deployment`.
   - Note that if you use your own subscription address, the `SUB` domain of the subscription generator and the domain of `[YOUR-PAGES-URL]` must not belong to the same top-level domain, otherwise an exception will occur. You can assign the domain assigned by Pages.dev to the `SUB` variable.

</details>

## 🔑 Variable Description

| Variable Name | Example | Required | Remarks | YT |
|---|---|---|---|---|
| UUID | `90cd4a77-141a-43c9-991b-08263cfe9c10` |✅| Any value can be entered (non-UUIDv4 standard values will automatically switch to dynamic UUID) | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=72s) |
| KEY | `token` |❌| Dynamic UUID secret key. When using the `KEY` variable, the `UUID` variable will no longer be enabled. | |
| TIME | `7` |❌| Dynamic UUID validity period (default: `7` days) | |
| UPTIME | `3` |❌| Dynamic UUID update time (default: update at `3` o'clock Beijing time) | |
| SCV | `false` or `0` |❌| Whether to skip TLS certificate verification (default `true` to skip certificate verification) | |
| PROXYIP | `proxyip.cmliussss.net:443` |❌| Alternative proxy node for accessing CFCDN sites (supports custom ProxyIP ports, multiple ProxyIPs, separated by `,` or `newline`) | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=166s) |
| HTTP | `user:password@127.0.0.1:8080` or `127.0.0.1:8080` |❌| Preferred HTTP proxy for accessing CFCDN sites (supports multiple HTTP proxies, separated by `,` or `newline`) | |
| SOCKS5 | `user:password@127.0.0.1:1080` or `127.0.0.1:1080` |❌| Preferred SOCKS5 proxy for accessing CFCDN sites (supports multiple socks5, separated by `,` or `newline`) | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=826s) |
| GO2SOCKS5 | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` |❌| After setting the `SOCKS5` or `HTTP` variable, you can set a list of forced access using socks5 (set to `*` for global proxy) | |
| NAT64 | `dns64.cmi.ztvi.org` or `2001:67c:2960:6464::/96` |❌| As a fallback for PROXYIP failure, query [nat64.xyz](https://nat64.xyz/) for `DNS64 Server` or `NAT64 Prefix` | |
| ADD | `icook.tw:2053#Official Preferred Domain` |❌| Local preferred TLS domain/preferred IP (supports multiple elements, separated by `,` or `newline`) | |
| ADDAPI | [https://raw.github.../addressesapi.txt](https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt) |❌| API address for preferred IPs (supports multiple elements, separated by `,` or `newline`) | |
| ADDNOTLS | `icook.hk:8080#Official Preferred Domain` |❌| Local preferred noTLS domain/preferred IP (supports multiple elements, separated by `,` or `newline`) | |
| ADDNOTLSAPI | [https://raw.github.../addressesapi.txt](https://raw.githubusercontent.com/cmliu/CFcdnVmess2sub/main/addressesapi.txt) |❌| API address for preferred IPs (supports multiple elements, separated by `,` or `newline`) | |
| ADDCSV | [https://raw.github.../addressescsv.csv](https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressescsv.csv) |❌| iptest speed test results (supports multiple elements, separated by `,`) | |
| DLS | `8` |❌| `ADDCSV` speed test results meet the minimum speed limit | |
| CSVREMARK | `1` |❌| CSV remark column offset | |
| TGTOKEN | `6894123456:XXXXXXXXXX0qExVsBPUhHDAbXXX` |❌| Telegram bot token for sending notifications |
| TGID | `6946912345` |❌| Telegram account numeric ID for receiving notifications |
| SUB | `SUB.cmliussss.net` | ❌ | Preferred subscription generator domain | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=1193s) |
| SUBAPI | `SUBAPI.cmliussss.net` |❌| clash, singbox, etc. subscription conversion backend | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=1446s) |
| SUBCONFIG | [https://raw.github.../ACL4SSR_Online_Full_MultiMode.ini](https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini) |❌| clash, singbox, etc. subscription conversion configuration file | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=1605s) |
| SUBEMOJI | `false` |❌| Whether to enable Emoji for subscription conversion (default `true`) | |
| SUBNAME | `edgetunnel` |❌| Subscription name | |
| RPROXYIP | `false` |❌| Set to true to force obtaining the ProxyIP assigned by the subscriber (requires subscriber support) | [Video](https://www.youtube.com/watch?v=s91zjpw3-P8&t=1816s) |
| URL302 | `https://t.me/CMLiussss` |❌| Home page 302 redirect (supports multiple urls, separated by `,` or `newline`, not for beginners) | |
| URL | `https://blog.cmliussss.com` |❌| Home page reverse proxy camouflage (supports multiple urls, separated by `,` or `newline`, setting it randomly may trigger anti-fraud) | |
| CFPORTS | `2053`,`2096`,`8443` |❌| CF account standard port list | |

## ❗ Notes

### Enable online editing of preferred list [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=630s)
- Bind a **KV namespace** with the **variable name** `KV` to enable online editing of the `ADD` and `ADDAPI` preferred lists on the configuration page without `SUB`;

### **About `KEY` and `UUID`:**
- After filling in the `KEY` variable, the `UUID` variable will be disabled. Please make sure to **use one of them**!
1. After filling in `KEY`, your **permanent subscription** address is: `https://[YOUR-URL]/[YOUR-KEY]`;
2. When using a dynamic `UUID` subscription:
   - The dynamic `UUID` needs to be obtained manually on the permanent subscription configuration page;
   - The temporary subscription address is: `https://[YOUR-URL]/[dynamic UUID]`;
   - The subscription validity period is: **1 `TIME` cycle**;
   - The node can be used for: **2 `TIME` cycles**, that is, after the dynamic `UUID` expires, the node can still be used for an additional cycle, but the subscription cannot be updated.

### **About `SOCKS5` and `PROXYIP`:**
- After filling in `SOCKS5`, `PROXYIP` will be disabled. Please make sure to **use one of them**!

### **About `SUB` and `ADD*` variables:**
- After filling in `SUB`, the subscription content generated by the `ADD*` class variables will be disabled. Please make sure to **use one of them**!

### **When `SUB` and `ADD*` are both empty:**
- The script will automatically generate lines based on random CF IPs. Each time the subscription is updated, a different random IP will be generated to ensure that your subscription will not be lost!


## 🔧 Practical Skills
This project provides a flexible subscription configuration solution that supports rapid customization of subscription content through URL parameters.
- Example subscription address: `https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10`

1. Change the subscription address of the **subscription generator** [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=1019s)

   Quickly switch the subscription generator to `VLESS.cmliussss.net`:
   ```url
   https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sub=VLESS.cmliussss.net
   ```

2. Change the subscription address of **PROXYIP** [Video Tutorial](https://www.youtube.com/watch?v=tKe9xUuFODA&t=1094s)

   Quickly change PROXYIP to `proxyip.cmliussss.net`:
   ```url
   https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?proxyip=proxyip.cmliussss.net
   ```

3. Change the subscription address of **SOCKS5**

   Quickly set the SOCKS5 proxy to `user:password@127.0.0.1:1080`:
   ```url
   https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?socks5=user:password@127.0.0.1:1080
   ```

- Quickly modify the subscription address by submitting multiple parameters

   For example, modify both the **subscription generator** and **PROXYIP** at the same time:
   ```url
   https://edgetunnel.pages.dev/90cd4a77-141a-43c9-991b-08263cfe9c10?sub=VLESS.cmliussss.net&proxyip=proxyip.cmliussss.net
   ```

4. The nodes deployed by this project can use the specified `PROXYIP` or `SOCKS5` through the node PATH!!!**

- Specify `PROXYIP` case
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   /proxyip.cmliussss.net (only for domains starting with 'proxyip.')
   ```

- Specify `SOCKS5` case
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (global SOCKS5 is activated by default)
   /socks5://user:password@127.0.0.1:1080 (global SOCKS5 is activated by default)
   ```

- Specify `HTTP proxy` case
   ```url
   /http://user:password@127.0.0.1:8080 (global SOCKS5 is activated by default)
   ```

5. **When your `ADDAPI` can be used as `PROXYIP`, you can add `?proxyip=true` to the end of the `ADDAPI` variable, so that the preferred IP itself can be used as `PROXYIP` when generating nodes**
- Specify `ADDAPI` as `PROXYIP` case
   ```url
   https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt?proxyip=true
   ```

## ⭐ Star
[![Stargazers over time](https://starchart.cc/cmliu/edgetunnel.svg?variant=adaptive)](https://starchart.cc/cmliu/edgetunnel)

## 💻 Adapted Clients
### Windows
   - [v2rayN](https://github.com/2dust/v2rayN)
   - clash.meta ([FlClash](https://github.com/chen08209/FlClash), [mihomo-party](https://github.com/mihomo-party-org/mihomo-party), [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev), [Clash Nyanpasu](https://github.com/keiko233/clash-nyanpasu))
### IOS
   - Surge, Shadowrocket
   - sing-box ([SFI](https://sing-box.sagernet.org/zh/clients/apple/))
### Android
   - clash.meta ([ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid), [FlClash](https://github.com/chen08209/FlClash))
   - sing-box ([SFA](https://github.com/SagerNet/sing-box))
### MacOS
   - clash.meta ([FlClash](https://github.com/chen08209/FlClash), [mihomo-party](https://github.com/mihomo-party-org/mihomo-party))


# 🙏 Special Thanks
### 💖 Sponsorship - providing cloud servers to maintain the [subscription conversion service](https://sub.cmliussss.net/)
- [Alice Networks LTD](https://url.cmliussss.com/alice)
- [VTEXS Enterprise Cloud](https://console.vtexs.com/?affid=1532)
### 🛠 Open Source Code Reference
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [股神](https://t.me/CF_NAT/38889)
