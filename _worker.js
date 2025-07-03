import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
let DNS64Server = '';
//let sub = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
let noTLS = 'false';
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV remark column offset
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let validityDuration = 7;
let updateTime = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let dynamicUUID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';
export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                dynamicUUID = env.KEY || env.TOKEN || userID;
                validityDuration = Number(env.TIME) || validityDuration;
                updateTime = Number(env.UPTIME) || updateTime;
                const userIDs = await generateDynamicUUID(dynamicUUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            }

            if (!userID) {
                return new Response('Please set your UUID variable, or try redeploying and check if the variable is effective.', {
                    status: 404,
                    headers: {
                        "Content-Type": "text/plain;charset=utf-8",
                    }
                });
            }
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIDMD5 = await doubleHash(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await organize(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            DNS64Server = env.DNS64 || env.NAT64 || (DNS64Server != '' ? DNS64Server : atob("ZG5zNjQuY21saXVzc3NzLm5ldA=="));
            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await organize(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await organize(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await organize(env.CFPORTS);
            if (env.BAN) banHosts = await organize(env.BAN);
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    RproxyIP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await organize(env.ADD);
                if (env.ADDAPI) addressesapi = await organize(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await organize(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await organize(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await organize(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await organize(env.LINK);
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/proxyip=${url.searchParams.get('proxyip')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks5')) {
                    path = `/?socks5=${url.searchParams.get('socks5')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks')) {
                    path = `/?socks5=${url.searchParams.get('socks')}`;
                    RproxyIP = 'false';
                }

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';
                const pathname = url.pathname.toLowerCase();
                if (pathname == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await proxyURL(env.URL, url);
                    else return new Response(JSON.stringify(request.cf, null, 4), {
                        status: 200,
                        headers: {
                            'content-type': 'application/json',
                        },
                    });
                } else if (pathname == `/${fakeUserID}`) {
                    const fakeConfig = await generateConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, fakeUserID, fakeHostName, env);
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (url.pathname == `/${dynamicUUID}/edit` || pathname == `/${userID}/edit`) {
                    return await KV(request, env);
                } else if (url.pathname == `/${dynamicUUID}/bestip` || pathname == `/${userID}/bestip`) {
                    return await bestIP(request, env);
                } else if (url.pathname == `/${dynamicUUID}` || pathname == `/${userID}`) {
                    await sendMessage(`#GetSubscription ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\nDomain: ${url.hostname}\n<tg-spoiler>Entry: ${url.pathname + url.search}</tg-spoiler>`);
                    const vlessConfig = await generateConfig(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);
                    const now = Date.now();
                    //const timestamp = Math.floor(now / 1000);
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;

                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(vlessConfig, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(vlessConfig, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                //"Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await proxyURL(env.URL, url);
                    else return new Response('Don\'t doubt it! Your UUID is wrong!!!', { status: 404 });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || socks5Address;
                if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname) || new RegExp('/http://', 'i').test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        let userPassword = socks5Address.split('@')[0].replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
                    }
                    go2Socks5s = ['all in'];
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        let e = err;
                        console.log(e.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has('proxyip')) {
                    proxyIP = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
                    proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                    enableSocks = false;
                } else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                return await vlessOverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    },
};

async function vlessOverWSHandler(request) {

    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    // Accept WebSocket connection
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    // Log function for recording connection information
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    // Get early data header, which may contain some initialization data
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    // Create a readable WebSocket stream to receive client data
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    // Wrapper for storing the remote Socket
    let remoteSocketWapper = {
        value: null,
    };
    // Flag to indicate if it's a DNS query
    let isDns = false;

    // Pipe WebSocket data stream to the remote server
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns) {
                // If it's a DNS query, call the DNS handling function
                return await handleDNSQuery(chunk, webSocket, null, log);
            }
            if (remoteSocketWapper.value) {
                // If there is already a remote Socket, write data directly
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // Process VLESS protocol header
            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                vlessVersion = new Uint8Array([0, 0]),
                isUDP,
            } = processVlessHeader(chunk, userID);
            // Set address and port information for logging
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
            if (hasError) {
                // If there is an error, throw an exception
                throw new Error(message);
                return;
            }
            // If it's UDP and the port is not the DNS port (53), close the connection
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP proxy is only enabled for DNS (port 53)');
                    return;
                }
            }
            // Build VLESS response header
            const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
            // Get the actual client data
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                // If it's a DNS query, call the DNS handling function
                return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
            }
            // Handle TCP outbound connection
            if (!banHosts.includes(addressRemote)) {
                log(`Handling TCP outbound connection ${addressRemote}:${portRemote}`);
                handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
            } else {
                throw new Error(`Blacklisted, closing TCP outbound connection ${addressRemote}:${portRemote}`);
            }
        },
        close() {
            log(`readableWebSocketStream has been closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream has been aborted`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipe error', err);
    });

    // Return a WebSocket upgrade response
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connected to ${address}:${port}`);
        //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
        // First determine the connection method, then create the connection
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        //log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        // First write, usually the TLS client Hello message
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function nat64() {
        if (!useSocks) {
            const nat64Proxyip = `[${await resolveToIPv6(addressRemote)}]`;
            log(`NAT64 proxy connecting to ${nat64Proxyip}:443`);
            tcpSocket = await connectAndWrite(nat64Proxyip, '443');
        }
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    }

    /**
     * Retry function: When Cloudflare's TCP Socket does not receive data, we try to redirect the IP
     * This may be due to connection failure caused by some network problems
     */
    async function retry() {
        if (enableSocks) {
            // If SOCKS5 is enabled, retry the connection through the SOCKS5 proxy
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            // Otherwise, try to reconnect using the preset proxy IP (if any) or the original address
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
            } else if (proxyIP.includes(']:')) {
                portRemote = proxyIP.split(']:')[1] || portRemote;
                proxyIP = proxyIP.split(']:')[0] + "]" || proxyIP;
            } else if (proxyIP.split(':').length === 2) {
                portRemote = proxyIP.split(':')[1] || portRemote;
                proxyIP = proxyIP.split(':')[0] || proxyIP;
            }
            if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP.toLowerCase() || addressRemote, portRemote);
        }
        /* Regardless of whether the retry is successful, the WebSocket must be closed (possibly to re-establish the connection)
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        */
        // Establish a data flow from the remote Socket to the WebSocket
        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, nat64, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    // First attempt to connect to the remote server
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    // When the remote Socket is ready, pass it to the WebSocket
    // Establish a data flow from the remote server to the WebSocket to send the remote server's response back to the client
    // If the connection fails or there is no data, the retry function will be called to retry
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    // Flag indicating whether the readable stream has been canceled
    let readableStreamCancel = false;

    // Create a new readable stream
    const stream = new ReadableStream({
        // Initialization function when the stream starts
        start(controller) {
            // Listen for WebSocket message events
            webSocketServer.addEventListener('message', (event) => {
                // If the stream has been canceled, no longer process new messages
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                // Add the message to the stream's queue
                controller.enqueue(message);
            });

            // Listen for WebSocket close events
            // Note: This event means the client has closed the client -> server stream
            // However, the server -> client stream is still open until close() is called on the server side
            // The WebSocket protocol requires a separate close message to be sent in each direction to completely close the Socket
            webSocketServer.addEventListener('close', () => {
                // The client sent a close signal, the server side needs to be closed
                safeCloseWebSocket(webSocketServer);
                // If the stream has not been canceled, close the controller
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            // Listen for WebSocket error events
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server error');
                // Pass the error to the controller
                controller.error(err);
            });

            // Process WebSocket 0-RTT (Zero Round Trip Time) early data
            // 0-RTT allows data to be sent before the connection is fully established, improving efficiency
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                // If there is an error decoding the early data, pass the error to the controller
                controller.error(error);
            } else if (earlyData) {
                // If there is early data, add it to the stream's queue
                controller.enqueue(earlyData);
            }
        },

        // Called when the user pulls data from the stream
        pull(controller) {
            // Backpressure mechanism can be implemented here
            // If the WebSocket can stop reading when the stream is full, we can implement backpressure
            // See: https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        // Called when the stream is canceled
        cancel(reason) {
            // Several situations where the stream is canceled:
            // 1. When the pipe's WritableStream has an error, this cancel function will be called, so handle the WebSocket server's close here
            // 2. If the ReadableStream is canceled, all controller.close/enqueue need to be skipped
            // 3. But after testing, even if the ReadableStream is canceled, controller.error is still valid
            if (readableStreamCancel) {
                return;
            }
            log(`Readable stream canceled, reason is ${reason}`);
            readableStreamCancel = true;
            // Safely close the WebSocket
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Parses the header data of the VLESS protocol
 * @param { ArrayBuffer} vlessBuffer The raw header data of the VLESS protocol
 * @param {string} userID The user ID for verification
 * @returns {Object} The parsing result, including whether there is an error, error message, remote address information, etc.
 */
function processVlessHeader(vlessBuffer, userID) {
    // Check if the data length is sufficient (at least 24 bytes)
    if (vlessBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }

    // Parse the VLESS protocol version (the first byte)
    const version = new Uint8Array(vlessBuffer.slice(0, 1));

    let isValidUser = false;
    let isUDP = false;

    // Verify the user ID (the next 16 bytes)
    function isUserIDValid(userID, userIDLow, buffer) {
        const userIDArray = new Uint8Array(buffer.slice(1, 17));
        const userIDString = stringify(userIDArray);
        return userIDString === userID || userIDString === userIDLow;
    }

    // Use the function to verify
    isValidUser = isUserIDValid(userID, userIDLow, vlessBuffer);

    // If the user ID is invalid, return an error
    if (!isValidUser) {
        return {
            hasError: true,
            message: `invalid user ${(new Uint8Array(vlessBuffer.slice(1, 17)))}`,
        };
    }

    // Get the length of the additional options (the 17th byte)
    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    // Temporarily skip the additional options

    // Parse the command (1 byte immediately following the options)
    // 0x01: TCP, 0x02: UDP, 0x03: MUX (multiplexing)
    const command = new Uint8Array(
        vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
        // TCP command, no special handling required
    } else if (command === 2) {
        // UDP command
        isUDP = true;
    } else {
        // Unsupported command
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }

    // Parse the remote port (big-endian, 2 bytes)
    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    // Parse the address type and address
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        vlessBuffer.slice(addressIndex, addressIndex + 1)
    );

    // Address type: 1-IPv4(4 bytes), 2-domain name(variable length), 3-IPv6(16 bytes)
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            // IPv4 address
            addressLength = 4;
            // Convert 4 bytes to dotted decimal format
            addressValue = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            // Domain name
            // The first byte is the length of the domain name
            addressLength = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            // Decode the domain name
            addressValue = new TextDecoder().decode(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            // IPv6 address
            addressLength = 16;
            const dataView = new DataView(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            // Every 2 bytes constitutes a part of the IPv6 address
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            // seems no need add [] for ipv6
            break;
        default:
            // Invalid address type
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }

    // Ensure the address is not empty
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    // Return the parsing result
    return {
        hasError: false,
        addressRemote: addressValue,  // Parsed remote address
        addressType,                 // Address type
        portRemote,                 // Remote port
        rawDataIndex: addressValueIndex + addressLength,  // Actual starting position of the raw data
        vlessVersion: version,      // VLESS protocol version
        isUDP,                     // Whether it is a UDP request
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
    // Forward data from the remote server to the WebSocket
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let vlessHeader = vlessResponseHeader;
    let hasIncomingData = false; // Check if the remote Socket has incoming data

    // Use a pipe to connect the readable stream of the remote Socket to a writable stream
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                    // No operation required at initialization
                },
                /**
                 * Process each data chunk
                 * @param {Uint8Array} chunk Data chunk
                 * @param {*} controller Controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true; // Mark that data has been received
                    // remoteChunkCount++; // Used for flow control, now seems unnecessary

                    // Check if the WebSocket is in the open state
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                    }

                    if (vlessHeader) {
                        // If there is a VLESS response header, send it with the first data chunk
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null; // Clear the header, no longer send it
                    } else {
                        // Send the data chunk directly
                        // There was flow control code here before, limiting the sending rate of large amounts of data
                        // But now Cloudflare seems to have fixed this problem
                        // if (remoteChunkCount > 20000) {
                        // \t// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // \tawait delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    // When the readable stream of the remote connection is closed
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // No need to actively close the WebSocket, as this may cause HTTP ERR_CONTENT_LENGTH_MISMATCH problems
                    // The client will send a close event anyway
                    // safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    // When the readable stream of the remote connection is interrupted
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            // Catch and record any exceptions
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            // Safely close the WebSocket when an error occurs
            safeCloseWebSocket(webSocket);
        });

    // Handle special error conditions for Cloudflare connection Sockets
    // 1. Socket.closed will have an error
    // 2. Socket.readable will be closed, but without any data
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry(); // Call the retry function to try to re-establish the connection
    }
}

/**
 * Converts a Base64 encoded string to an ArrayBuffer
 * 
 * @param {string} base64Str Base64 encoded input string
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} Returns the decoded ArrayBuffer or an error
 */
function base64ToArrayBuffer(base64Str) {
    // If the input is empty, return an empty result directly
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        // Go language uses a URL-safe Base64 variant (RFC 4648)
        // This variant uses '-' and '_' instead of '+' and '/' in standard Base64
        // JavaScript's atob function does not directly support this variant, so we need to convert it first
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

        // Use the atob function to decode the Base64 string
        // atob converts a Base64 encoded ASCII string to a raw binary string
        const decode = atob(base64Str);

        // Convert the binary string to a Uint8Array
        // This is done by iterating through each character in the string and getting its Unicode encoding value (0-255)
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));

        // Return the underlying ArrayBuffer of the Uint8Array
        // This is the actual binary data that can be used for network transmission or other binary operations
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        // If an error occurs in any step (such as an illegal Base64 character), return the error
        return { earlyData: undefined, error };
    }
}

/**
 * This is not a real UUID validation, but a simplified version
 * @param {string} uuid The UUID string to be validated
 * @returns {boolean} Returns true if the string matches the UUID format, otherwise returns false
 */
function isValidUUID(uuid) {
    // Define a regular expression to match the UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    // Use the regular expression to test the UUID string
    return uuidRegex.test(uuid);
}

// Two important state constants for WebSocket
const WS_READY_STATE_OPEN = 1;     // WebSocket is in the open state, can send and receive messages
const WS_READY_STATE_CLOSING = 2;  // WebSocket is in the process of closing

function safeCloseWebSocket(socket) {
    try {
        // Only call close() when the WebSocket is in the open or closing state
        // This avoids calling close() on a WebSocket that is already closed or connecting
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        // Record any possible errors, although according to the specification there should be no errors
        console.error('safeCloseWebSocket error', error);
    }
}

// Pre-calculate the hexadecimal representation of each byte from 0-255
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    // (i + 256).toString(16) ensures that a two-digit hexadecimal is always obtained
    // .slice(1) removes the leading "1", leaving only two hexadecimal digits
    byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * Quickly converts a byte array to a UUID string without validity checking
 * This is a low-level function that operates directly on bytes and does no validation
 * @param {Uint8Array} arr An array containing UUID bytes
 * @param {number} offset The starting position of the UUID in the array, defaults to 0
 * @returns {string} UUID string
 */
function unsafeStringify(arr, offset = 0) {
    // Directly get the hexadecimal representation of each byte from the lookup table and concatenate it into UUID format
    // The 8-4-4-4-12 grouping is achieved by carefully placed hyphens "-"
    // toLowerCase() ensures that the entire UUID is lowercase
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

/**
 * Converts a byte array to a UUID string and validates its validity
 * This is a safe function that ensures the returned UUID is in the correct format
 * @param {Uint8Array} arr An array containing UUID bytes
 * @param {number} offset The starting position of the UUID in the array, defaults to 0
 * @returns {string} A valid UUID string
 * @throws {TypeError} If the generated UUID string is invalid
 */
function stringify(arr, offset = 0) {
    // Use the unsafe function to quickly generate a UUID string
    const uuid = unsafeStringify(arr, offset);
    // Validate whether the generated UUID is valid
    if (!isValidUUID(uuid)) {
        // Original: throw TypeError("Stringified UUID is invalid");
        throw TypeError(`The generated UUID does not conform to the specification ${uuid}`);
        //uuid = userID;
    }
    return uuid;
}

/**
 * Function to handle DNS queries
 * @param {ArrayBuffer} udpChunk - DNS query data sent by the client
 * @param {ArrayBuffer} vlessResponseHeader - VLESS protocol response header data
 * @param {(string)=> void} log - Logging function
 */
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
    // Regardless of which DNS server the client sends to, we always use a hardcoded server
    // because some DNS servers do not support DNS over TCP
    try {
        // Choose Google's DNS server (note: it may be changed to Cloudflare's 1.1.1.1 later)
        const dnsServer = '8.8.4.4'; // After Cloudflare fixes the bug of connecting to its own IP, it will be changed to 1.1.1.1
        const dnsPort = 53; // Standard port for DNS service

        let vlessHeader = vlessResponseHeader; // Save the VLESS response header for later sending

        // Establish a TCP connection with the specified DNS server
        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`Connecting to ${dnsServer}:${dnsPort}`); // Record connection information
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk); // Send the client's DNS query data to the DNS server
        writer.releaseLock(); // Release the writer to allow other parts to use it

        // Send the response data received from the DNS server back to the client via WebSocket
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (vlessHeader) {
                        // If there is a VLESS header, merge it with the DNS response data and send it
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null; // The header is sent only once, then set to null
                    } else {
                        // Otherwise, send the DNS response data directly
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS server (${dnsServer}) TCP connection has been closed`); // Record connection closure information
            },
            abort(reason) {
                console.error(`DNS server (${dnsServer}) TCP connection abnormally interrupted`, reason); // Record the reason for the abnormal interruption
            },
        }));
    } catch (error) {
        // Catch and record any possible errors
        console.error(
            `An exception occurred in the handleDNSQuery function, error message: ${error.message}`
        );
    }
}

/**
 * Establish a SOCKS5 proxy connection
 * @param {number} addressType Target address type (1: IPv4, 2: domain name, 3: IPv6)
 * @param {string} addressRemote Target address (can be IP or domain name)
 * @param {number} portRemote Target port
 * @param {function} log Logging function
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    // Connect to the SOCKS5 proxy server
    const socket = connect({
        hostname, // Hostname of the SOCKS5 server
        port,    // Port of the SOCKS5 server
    });

    // Request header format (Worker -> SOCKS5 server):
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
    // Meaning of the METHODS field:
    // 0x00 No authentication required
    // 0x02 Username/password authentication https://datatracker.ietf.org/doc/html/rfc1929
    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    // 5: SOCKS5 version number, 2: number of supported authentication methods, 0 and 2: two authentication methods (no authentication and username/password)

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log('SOCKS5 greeting message sent');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    // Response format (SOCKS5 server -> Worker):
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    if (res[0] !== 0x05) {
        log(`SOCKS5 server version error: received ${res[0]}, expected 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("Server does not accept any authentication methods");
        return;
    }

    // If 0x0502 is returned, it means username/password authentication is required
    if (res[1] === 0x02) {
        log("SOCKS5 server requires authentication");
        if (!username || !password) {
            log("Please provide username and password");
            return;
        }
        // Authentication request format:
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        const authRequest = new Uint8Array([
            1,                   // Authentication sub-protocol version
            username.length,    // Username length
            ...encoder.encode(username), // Username
            password.length,    // Password length
            ...encoder.encode(password)  // Password
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        // Expect 0x0100 to be returned, indicating successful authentication
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 server authentication failed");
            return;
        }
    }

    // Request data format (Worker -> SOCKS5 server):
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // ATYP: Address type
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    // DST.ADDR: Destination address
    // DST.PORT: Destination port (network byte order)

    // addressType
    // 1 --> IPv4 address length = 4
    // 2 --> Domain name
    // 3 --> IPv6 address length = 16
    let DSTADDR;    // DSTADDR = ATYP + DST.ADDR
    switch (addressType) {
        case 1: // IPv4
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 2: // Domain name
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 3: // IPv6
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            log(`Invalid address type: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    // 5: SOCKS5 version, 1: indicates CONNECT request, 0: reserved field
    // ...DSTADDR: destination address, portRemote >> 8 and & 0xff: convert the port to network byte order
    await writer.write(socksRequest);
    log('SOCKS5 request sent');

    res = (await reader.read()).value;
    // Response format (SOCKS5 server -> Worker):
    //  +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    if (res[1] === 0x00) {
        log("SOCKS5 connection established");
    } else {
        log("SOCKS5 connection establishment failed");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 * Establish an HTTP proxy connection
 * @param {string} addressRemote Target address (can be IP or domain name)
 * @param {number} portRemote Target port
 * @param {function} log Logging function
 */
async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    // Build HTTP CONNECT request
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    // Add proxy authentication (if needed)
    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`; // Add standard Connection header
    connectRequest += `\r\n`;

    log(`Connecting to ${addressRemote}:${portRemote} via proxy ${hostname}:${port}`);

    try {
        // Send connection request
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('Failed to send HTTP CONNECT request:', err);
        throw new Error(`Failed to send HTTP CONNECT request: ${err.message}`);
    }

    // Read HTTP response
    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('HTTP proxy connection interrupted');
                throw new Error('HTTP proxy connection interrupted');
            }

            // Merge received data
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            // Convert received data to text
            respText = new TextDecoder().decode(responseBuffer);

            // Check if the complete HTTP response header has been received
            if (respText.includes('\r\n\r\n')) {
                // Separate the HTTP header and possible data part
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                log(`Received HTTP proxy response: ${headers.split('\r\n')[0]}`);

                // Check response status
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    // If there is data after the response header, we need to save this data for subsequent processing
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        // Create a buffer to store this data for later use
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        // Create a new TransformStream to process additional data
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('Error processing remaining data:', err));

                        // Replace the original readable stream
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP proxy connection failed: ${headers.split('\r\n')[0]}`;
                    console.error(errorMsg);
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`Failed to process HTTP proxy response: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP proxy connection failed: No successful response received');
    }

    log(`HTTP proxy connection successful: ${addressRemote}:${portRemote}`);
    return sock;
}

/**
 * SOCKS5 proxy address parser
 * This function is used to parse the SOCKS5 proxy address string and extract the username, password, hostname, and port number
 * 
 * @param {string} address SOCKS5 proxy address, the format can be:
 *   - "username:password@hostname:port" (with authentication)
 *   - "hostname:port" (without authentication)
 *   - "username:password@[ipv6]:port" (IPv6 address needs to be enclosed in square brackets)
 */
function socks5AddressParser(address) {
    // Use "@" to split the address into an authentication part and a server address part
    // reverse() is to handle the case where there is no authentication information, ensuring that latter always contains the server address
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    // If the former part exists, it means that authentication information is provided
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('Invalid SOCKS address format: the authentication part must be in the form of "username:password"');
        }
        [username, password] = formers;
    }

    // Parse the server address part
    const latters = latter.split(":");
    // From the end, extract the port number (because IPv6 addresses also contain colons)
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('Invalid SOCKS address format: the port number must be a number');
    }

    // The remaining part is the hostname (can be a domain name, IPv4 or IPv6 address)
    hostname = latters.join(":");

    // Handle the special case of IPv6 addresses
    // IPv6 addresses contain multiple colons, so they must be enclosed in square brackets, such as [2001:db8::1]
    const regex = /^\\[.*\\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('Invalid SOCKS address format: IPv6 addresses must be enclosed in square brackets, such as [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // Return the parsed result
    return {
        username,  // Username, undefined if not present
        password,  // Password, undefined if not present
        hostname,  // Hostname, can be a domain name, IPv4 or IPv6 address
        port,    // Port number, converted to a number type
    }
}

/**
 * Restore disguised information
 * This function is used to replace the fake user ID and fake hostname in the content with the real values
 * 
 * @param {string} content The content to be processed
 * @param {string} userID The real user ID
 * @param {string} hostName The real hostname
 * @param {boolean} isBase64 Whether the content is Base64 encoded
 * @returns {string} The content after restoring the real information
 */
function restoreDisguisedInfo(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
    if (isBase64) content = atob(content);  // If the content is Base64 encoded, decode it first

    // Use regular expressions for global replacement ('g' flag)
    // Replace all occurrences of the fake user ID and fake hostname with the real values
    content = content.replace(new RegExp(fakeUserID, 'g'), userID)
        .replace(new RegExp(fakeHostName, 'g'), hostName);

    if (isBase64) content = btoa(content);  // If the original content was Base64 encoded, encode it again after processing

    return content;
}

/**
 * Double MD5 hash function
 * This function performs two MD5 hashes on the input text to enhance security
 * The second hash uses a part of the first hash result as input
 * 
 * @param {string} text The text to be hashed
 * @returns {Promise<string>} The lowercase hexadecimal string after double hashing
 */
async function doubleHash(text) {
    const encoder = new TextEncoder();

    const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
    const firstHashArray = Array.from(new Uint8Array(firstHash));
    const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
    const secondHashArray = Array.from(new Uint8Array(secondHash));
    const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return secondHex.toLowerCase();
}

async function proxyURL(proxyUrl, targetUrl) {
    const urlList = await organize(proxyUrl);
    const fullUrl = urlList[Math.floor(Math.random() * urlList.length)];

    // Parse the target URL
    let parsedUrl = new URL(fullUrl);
    console.log(parsedUrl);
    // Extract and possibly modify URL components
    let protocol = parsedUrl.protocol.slice(0, -1) || 'https';
    let hostname = parsedUrl.hostname;
    let pathname = parsedUrl.pathname;
    let search = parsedUrl.search;

    // Process the pathname
    if (pathname.charAt(pathname.length - 1) == '/') {
        pathname = pathname.slice(0, -1);
    }
    pathname += targetUrl.pathname;

    // Build the new URL
    let newUrl = `${protocol}://${hostname}${pathname}${search}`;

    // Reverse proxy the request
    let response = await fetch(newUrl);

    // Create a new response
    let newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
    });

    // Add custom headers with URL information
    //newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //newResponse.headers.set('X-Original-URL', fullUrl);
    newResponse.headers.set('X-New-URL', newUrl);

    return newResponse;
}

const what_the_heck_is_this = atob('ZG14bGMzTT0=');
function configInfo(UUID, domainAddress) {
    const protocolType = atob(what_the_heck_is_this);

    const alias = FileName;
    let address = domainAddress;
    let port = 443;

    const userID = UUID;
    const encryptionMethod = 'none';

    const transportProtocol = 'ws';
    const camouflageDomain = domainAddress;
    const path = path;

    let transportLayerSecurity = ['tls', true];
    const SNI = domainAddress;
    const fingerprint = 'randomized';

    if (domainAddress.includes('.workers.dev')) {
        address = atob('dmlzYS5jbg==');
        port = 80;
        transportLayerSecurity = ['', false];
    }

    const vmessLink = `${protocolType}://${userID}@${address}:${port}\u003f\u0065\u006e\u0063\u0072\u0079` + 'p' + `${atob('dGlvbj0=') + encryptionMethod}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${transportLayerSecurity[0]}&sni=${SNI}&fp=${fingerprint}&type=${transportProtocol}&host=${camouflageDomain}&path=${encodeURIComponent(path) + allowInsecure}&fragment=1,40-60,30-50,tlshello#${encodeURIComponent(alias)}`;
    const clashMeta = `- {name: ${FileName}, server: ${address}, port: ${port}, type: ${protocolType}, uuid: ${userID}, tls: ${transportLayerSecurity[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: ${SCV}, servername: ${camouflageDomain}, client-fingerprint: ${fingerprint}, network: ${transportProtocol}, ws-opts: {path: "${path}", headers: {${camouflageDomain}}}}`;
    return [vmessLink, clashMeta];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));
/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function generateConfig(userID, hostName, sub, UA, RproxyIP, _url, fakeUserID, fakeHostName, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await organize(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            await migrateAddressList(env);
            const preferredAddressList = await env.KV.get('ADD.txt');
            if (preferredAddressList) {
                const preferredAddressArray = await organize(preferredAddressList);
                const classifiedAddresses = {
                    apiAddresses: new Set(),
                    linkAddresses: new Set(),
                    preferredAddresses: new Set()
                };

                for (const element of preferredAddressArray) {
                    if (element.startsWith('https://')) {
                        classifiedAddresses.apiAddresses.add(element);
                    } else if (element.includes('://')) {
                        classifiedAddresses.linkAddresses.add(element);
                    } else {
                        classifiedAddresses.preferredAddresses.add(element);
                    }
                }

                addressesapi = [...classifiedAddresses.apiAddresses];
                link = [...classifiedAddresses.linkAddresses];
                addresses = [...classifiedAddresses.preferredAddresses];
            }
        }

        if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
            // Define a list of CIDRs for Cloudflare IP ranges
            let cfips = [
                '103.21.244.0/24',
                '104.16.0.0/13',
                '104.24.0.0/14',
                '172.64.0.0/14',
                '104.16.0.0/14',
                '104.24.0.0/15',
                '141.101.64.0/19',
                '172.64.0.0/14',
                '188.114.96.0/21',
                '190.93.240.0/21',
                '162.159.152.0/23',
                '104.16.0.0/13',
                '104.24.0.0/14',
                '172.64.0.0/14',
                '104.16.0.0/14',
                '104.24.0.0/15',
                '141.101.64.0/19',
                '172.64.0.0/14',
                '188.114.96.0/21',
                '190.93.240.0/21',
            ];

            // Generate a random IP address that conforms to the given CIDR range
            function generateRandomIPFromCIDR(cidr) {
                const [base, mask] = cidr.split('/');
                const baseIP = base.split('.').map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);

                const randomIP = baseIP.map((octet, index) => {
                    if (index < 2) return octet;
                    if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });

                return randomIP.join('.');
            }
            addresses = addresses.concat('127.0.0.1:1234#CFnat');
            let counter = 1;
            if (hostName.includes("worker") || hostName.includes("notls")) {
                const randomPorts = httpPorts.concat('80');
                addressesnotls = addressesnotls.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CFRandomNode' + String(counter++).padStart(2, '0'))
                );
            } else {
                const randomPorts = httpsPorts.concat('443');
                addresses = addresses.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CFRandomNode' + String(counter++).padStart(2, '0'))
                );
            }
        }
    }

    const uuid = (_url.pathname == `/${dynamicUUID}`) ? dynamicUUID : userID;
    const userAgent = UA.toLowerCase();
    const Config = configInfo(userID, hostName);
    const v2ray = Config[0];
    const clash = Config[1];
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    console.error('Error getting address:', response.status, response.statusText);
                    return; // If there is an error, return directly
                }

                const text = await response.text();
                const lines = text.split('\n');
                // Filter out empty lines or lines containing only whitespace characters
                const nonEmptyLines = lines.filter(line => line.trim() !== '');

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) {
                //console.error('Error getting address:', error);
            }
        }
        if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
        const newSocks5s = socks5s.map(socks5Address => {
            if (socks5Address.includes('@')) return socks5Address.split('@')[1];
            else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
            else return socks5Address;
        });

        let socks5List = '';
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${(enableHttp ? "HTTP" : "Socks5") + decodeURIComponent('%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
            else socks5List += `<br>&nbsp;&nbsp;${go2Socks5s.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        let subscriber = '<br>';
        if (sub) {
            if (enableSocks) subscriber += `CFCDN (Access method): ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') subscriber += `CFCDN (Access method): ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else if (RproxyIP == 'true') subscriber += `CFCDN (Access method): Automatically obtain ProxyIP<br>`;
            else subscriber += `CFCDN (Access method): Unable to access, you need to set proxyIP/PROXYIP!!!<br>`
            subscriber += `<br>SUB (Preferred subscription generator): ${sub}`;
        } else {
            if (enableSocks) subscriber += `CFCDN (Access method): ${enableHttp ? "HTTP" : "Socks5"}<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') subscriber += `CFCDN (Access method): ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else subscriber += `CFCDN (Access method): Unable to access, you need to set proxyIP/PROXYIP!!!<br>`;
            let checkKVBinding = '';
            if (env.KV) checkKVBinding = ` [<a href='${_url.pathname}/edit'>Edit preferred list</a>]  [<a href='${_url.pathname}/bestip'>Online preferred IP</a>]`;
            subscriber += `<br>Your subscription content is provided by the built-in addresses/ADD* parameter variables${checkKVBinding}<br>`;
            if (addresses.length > 0) subscriber += `ADD (TLS preferred domain & IP): <br>&nbsp;&nbsp;${addresses.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotls.length > 0) subscriber += `ADDNOTLS (noTLS preferred domain & IP): <br>&nbsp;&nbsp;${addressesnotls.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesapi.length > 0) subscriber += `ADDAPI (API for TLS preferred domain & IP): <br>&nbsp;&nbsp;${addressesapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressesnotlsapi.length > 0) subscriber += `ADDNOTLSAPI (API for noTLS preferred domain & IP): <br>&nbsp;&nbsp;${addressesnotlsapi.join('<br>&nbsp;&nbsp;')}<br>`;
            if (addressescsv.length > 0) subscriber += `ADDCSV (IPTest speed test csv file, speed limit ${DLS}): <br>&nbsp;&nbsp;${addressescsv.join('<br>&nbsp;&nbsp;')}<br>`;
        }

        if (dynamicUUID && _url.pathname !== `/${dynamicUUID}`) subscriber = '';
        else subscriber += `<br>SUBAPI (Subscription conversion backend): ${subProtocol}://${subConverter}<br>SUBCONFIG (Subscription conversion configuration file): ${subConfig}`;
        const dynamicUUIDInfo = (uuid != userID) ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME (Dynamic UUID validity period): ${validityDuration} days<br>UPTIME (Dynamic UUID update time): ${updateTime} o'clock (Beijing time)<br><br>` : `${userIDTime}`;
        const nodeConfigPage = `
            ################################################################<br>
            Subscribe / sub subscription address, click the link to automatically <strong>copy the subscription link</strong> and <strong>generate a subscription QR code</strong> <br>
            ---------------------------------------------------------------<br>
            Adaptive subscription address:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
            <div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
            Base64 subscription address:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
            <div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
            clash subscription address:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
            <div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
            singbox subscription address:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
            <div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
            loon subscription address:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?loon</a><br>
            <div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
            <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">Practical subscription tips∨</a></strong><br>
                <div id="noticeContent" class="notice-content" style="display: none;">
                    <strong>1.</strong> If you are using the PassWall or PassWall2 router plugin, set the <strong>User-Agent</strong> in the subscription editor to <strong>PassWall</strong>;<br>
                    <br>
                    <strong>2.</strong> If you are using the SSR+ router plugin, it is recommended to use the <strong>Base64 subscription address</strong> for subscription;<br>
                    <br>
                    <strong>3.</strong> Quickly switch the <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>preferred subscription generator</a> to: sub.google.com, you can add the "?sub=sub.google.com" parameter to the end of the link, for example:<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
                    <br>
                    <strong>4.</strong> Quickly change PROXYIP to: proxyip.cmliussss.net:443, you can add the "?proxyip=proxyip.cmliussss.net:443" parameter to the end of the link, for example:<br>
                    &nbsp;&nbsp; https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.cmliussss.net:443</strong><br>
                    <br>
                    <strong>5.</strong> Quickly change SOCKS5 to: user:password@127.0.0.1:1080, you can add the "?socks5=user:password@127.0.0.1:1080" parameter to the end of the link, for example:<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
                    <br>
                    <strong>6.</strong> If you need to specify multiple parameters, you need to use '&' as a separator, for example:<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.cmliussss.net<br>
                </div>
            <script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
            <script>
            function copyToClipboard(text, qrcode) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Copied to clipboard');
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
                const qrcodeDiv = document.getElementById(qrcode);
                qrcodeDiv.innerHTML = '';
                new QRCode(qrcodeDiv, {
                    text: text,
                    width: 220, // Adjust width
                    height: 220, // Adjust height
                    colorDark: "#000000", // QR code color
                    colorLight: "#ffffff", // Background color
                    correctLevel: QRCode.CorrectLevel.Q, // Set error correction level
                    scale: 1 // Adjust pixel granularity
                });
            }

            function toggleNotice() {
                const noticeContent = document.getElementById('noticeContent');
                const noticeToggle = document.getElementById('noticeToggle');
                if (noticeContent.style.display === 'none') {
                    noticeContent.style.display = 'block';
                    noticeToggle.textContent = 'Practical subscription tips∧';
                } else {
                    noticeContent.style.display = 'none'; 
                    noticeToggle.textContent = 'Practical subscription tips∨';
                }
            }
            </script>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${FileName} Configuration Information<br>
            ---------------------------------------------------------------<br>
            ${dynamicUUIDInfo}HOST: ${hostName}<br>
            UUID: ${userID}<br>
            FKID: ${fakeUserID}<br>
            UA: ${UA}<br>
            SCV (Skip TLS certificate verification): ${SCV}<br>
            ${subscriber}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            v2ray<br>
            ---------------------------------------------------------------<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('${v2ray}','qrcode_v2ray')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2ray}</a><br>
            <div id="qrcode_v2ray" style="margin: 10px 10px 10px 10px;"></div>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            clash-meta<br>
            ---------------------------------------------------------------<br>
            ${clash}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${cmad}
            `;
        return `<div style="font-size:13px;">${nodeConfigPage}</div>`;
    } else {
        if (typeof fetch != 'function') {
            return 'Error: fetch is not available in this environment.';
        }

        let newAddressesapi = [];
        let newAddressescsv = [];
        let newAddressesnotlsapi = [];
        let newAddressesnotlscsv = [];

        // If using the default domain, change it to a workers domain, the subscriber will add a proxy
        if (hostName.includes(".workers.dev")) {
            noTLS = 'true';
            fakeHostName = `${fakeHostName}.workers.dev`;
            newAddressesnotlsapi = await organizePreferredList(addressesnotlsapi);
            newAddressesnotlscsv = await organizeSpeedTestResults('FALSE');
        } else if (hostName.includes(".pages.dev")) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
            noTLS = 'true';
            fakeHostName = `notls${fakeHostName}.net`;
            newAddressesnotlsapi = await organizePreferredList(addressesnotlsapi);
            newAddressesnotlscsv = await organizeSpeedTestResults('FALSE');
        } else {
            fakeHostName = `${fakeHostName}.xyz`
        }
        console.log(`Fake HOST: ${fakeHostName}`);
        let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            if (hostName.includes('workers.dev')) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);

                        if (!response.ok) {
                            console.error('Error getting address:', response.status, response.statusText);
                            return; // If there is an error, return directly
                        }

                        const text = await response.text();
                        const lines = text.split('\n');
                        // Filter out empty lines or lines containing only whitespace characters
                        const nonEmptyLines = lines.filter(line => line.trim() !== '');

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) {
                        console.error('Error getting address:', error);
                    }
                }
                // Use Set object to remove duplicates
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await organizePreferredList(addressesapi);
            newAddressescsv = await organizeSpeedTestResults('TRUE');
            url = `https://${hostName}/${fakeUserID + _url.search}`;
            if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
                if (_url.search) url += '&notls';
                else url += '?notls';
            }
            console.log(`Fake subscription: ${url}`);
        }

        if (!userAgent.includes(('CF-Workers-SUB').toLowerCase()) && !_url.searchParams.has('b64') && !_url.searchParams.has('base64')) {
            if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((_url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('loon') || (_url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            }
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await generateLocalSubscription(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
            } else {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
                    }
                });
                content = await response.text();
            }

            if (_url.pathname == `/${fakeUserID}`) return content;

            return restoreDisguisedInfo(content, userID, hostName, fakeUserID, fakeHostName, isBase64);

        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function organizePreferredList(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";

    // Create an AbortController object to control the cancellation of fetch requests
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort(); // Cancel all requests
    }, 2000); // Trigger after 2 seconds

    try {
        // Use Promise.allSettled to wait for all API requests to complete, regardless of success or failure
        // Iterate through the api array and initiate a fetch request for each API address
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal // Add the AbortController's signal to the fetch request so that the request can be canceled if necessary
        }).then(response => response.ok ? response.text() : Promise.reject())));

        // Iterate through all responses
        for (const [index, response] of responses.entries()) {
            // Check if the response status is 'fulfilled', i.e., the request was successfully completed
            if (response.status === 'fulfilled') {
                // Get the content of the response
                const content = await response.value;

                const lines = content.split(/\r?\n/);
                let nodeRemark = '';
                let speedTestPort = '443';

                if (lines[0].split(',').length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) nodeRemark = idMatch[1];

                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) speedTestPort = portMatch[1];

                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(',')[0];
                        if (columns) {
                            newapi += `${columns}:${speedTestPort}${nodeRemark ? `#${nodeRemark}` : ''}\n`;
                            if (api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${speedTestPort}`);
                        }
                    }
                } else {
                    // Verify if the current apiUrl has 'proxyip=true'
                    if (api[index].includes('proxyip=true')) {
                        // If the URL has 'proxyip=true', add the content to proxyIPPool
                        proxyIPPool = proxyIPPool.concat((await organize(content)).map(item => {
                            const baseItem = item.split('#')[0] || item;
                            if (baseItem.includes(':')) {
                                const port = baseItem.split(':')[1];
                                if (!httpsPorts.includes(port)) {
                                    return baseItem;
                                }
                            } else {
                                return `${baseItem}:443`;
                            }
                            return null; // Return null if the condition is not met
                        }).filter(Boolean)); // Filter out null values
                    }
                    // Add the content to newapi
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        // Whether successful or not, finally clear the set timeout timer
        clearTimeout(timeout);
    }

    const newAddressesapi = await organize(newapi);

    // Return the processed result
    return newAddressesapi;
}

async function organizeSpeedTestResults(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    let newAddressescsv = [];

    for (const csvUrl of addressescsv) {
        try {
            const response = await fetch(csvUrl);

            if (!response.ok) {
                console.error('Error getting CSV address:', response.status, response.statusText);
                continue;
            }

            const text = await response.text();// Use the correct character encoding to parse the text content
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            // Check if the CSV header contains the required fields
            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0;// IP address position in the CSV header
            const portIndex = 1;// Port position in the CSV header
            const dataCenterIndex = tlsIndex + remarkIndex; // Data center is the field after TLS

            if (tlsIndex === -1) {
                console.error('CSV file is missing required fields');
                continue;
            }

            // Iterate through the CSV rows starting from the second row
            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1; // The last field
                // Check if TLS is "TRUE" and the speed is greater than DLS
                if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
                        // If the URL has 'proxyip=true', add the content to proxyIPPool
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            console.error('Error getting CSV address:', error);
            continue;
        }
    }

    return newAddressescsv;
}

function generateLocalSubscription(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\\[.*\\]):?(\d+)?#?(.*)?$/;
    addresses = addresses.concat(newAddressesapi);
    addresses = addresses.concat(newAddressescsv);
    let notlsresponseBody;
    if (noTLS == 'true') {
        addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
        addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
        const uniqueAddressesnotls = [...new Set(addressesnotls)];

        notlsresponseBody = uniqueAddressesnotls.map(address => {
            let port = "-1";
            let addressid = address;

            const match = addressid.match(regex);
            if (!match) {
                if (address.includes(':') && address.includes('#')) {
                    const parts = address.split(':');
                    address = parts[0];
                    const subParts = parts[1].split('#');
                    port = subParts[0];
                    addressid = subParts[1];
                } else if (address.includes(':')) {
                    const parts = address.split(':');
                    address = parts[0];
                    port = parts[1];
                } else if (address.includes('#')) {
                    const parts = address.split('#');
                    address = parts[0];
                    addressid = parts[1];
                }

                if (addressid.includes(':')) {
                    addressid = addressid.split(':')[0];
                }
            } else {
                address = match[1];
                port = match[2] || port;
                addressid = match[3] || address;
            }

            if (!isValidIPv4(address) && port == "-1") {
                for (let httpPort of httpPorts) {
                    if (address.includes(httpPort)) {
                        port = httpPort;
                        break;
                    }
                }
            }
            if (port == "-1") port = "80";

            let camouflageDomain = host;
            let finalPath = path;
            let nodeRemark = '';
            const protocolType = atob(what_the_heck_is_this);

            const vlessLink = `${protocolType}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==') + camouflageDomain}&path=${encodeURIComponent(finalPath)}#${encodeURIComponent(addressid + nodeRemark)}`;

            return vlessLink;

        }).join('\n');

    }

    // Use Set object to remove duplicates
    const uniqueAddresses = [...new Set(addresses)];

    const responseBody = uniqueAddresses.map(address => {
        let port = "-1";
        let addressid = address;

        const match = addressid.match(regex);
        if (!match) {
            if (address.includes(':') && address.includes('#')) {
                const parts = address.split(':');
                address = parts[0];
                const subParts = parts[1].split('#');
                port = subParts[0];
                addressid = subParts[1];
            } else if (address.includes(':')) {
                const parts = address.split(':');
                address = parts[0];
                port = parts[1];
            } else if (address.includes('#')) {
                const parts = address.split('#');
                address = parts[0];
                addressid = parts[1];
            }

            if (addressid.includes(':')) {
                addressid = addressid.split(':')[0];
            }
        } else {
            address = match[1];
            port = match[2] || port;
            addressid = match[3] || address;
        }

        if (!isValidIPv4(address) && port == "-1") {
            for (let httpsPort of httpsPorts) {
                if (address.includes(httpsPort)) {
                    port = httpsPort;
                    break;
                }
            }
        }
        if (port == "-1") port = "443";

        let camouflageDomain = host;
        let finalPath = path;
        let nodeRemark = '';
        const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
        if (matchingProxyIP) finalPath = `/proxyip=${matchingProxyIP}`;

        if (proxyhosts.length > 0 && (camouflageDomain.includes('.workers.dev'))) {
            finalPath = `/${camouflageDomain}${finalPath}`;
            camouflageDomain = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
            nodeRemark = ` A temporary domain name transit service has been enabled, please bind a custom domain as soon as possible!`;
        }

        const protocolType = atob(what_the_heck_is_this);
        const vlessLink = `${protocolType}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==') + camouflageDomain}&fp=random&type=ws&host=${camouflageDomain}&path=${encodeURIComponent(finalPath) + allowInsecure}&fragment=1,40-60,30-50,tlshello#${encodeURIComponent(addressid + nodeRemark)}`;

        return vlessLink;
    }).join('\n');

    let base64Response = responseBody; // Re-encode with Base64
    if (noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

async function organize(input) {
    if (typeof input !== 'string') {
        return [];
    }

    // Remove possible BOM characters
    input = input.replace(/^\uFEFF/, '');

    // Use regular expressions to match various delimiters (newline, comma, semicolon, vertical bar)
    const delimiter = /[\n,;|]/;

    // Split the string and filter out empty strings
    const array = input.split(delimiter).filter(Boolean);

    // Further processing, remove whitespace from both ends of each element
    const organizedArray = array.map(item => item.trim());

    return organizedArray;
}

async function sendMessage(message, ip, user_info) {
    if (BotToken && ChatID) {
        const url = `https://api.telegram.org/bot${BotToken}/sendMessage`;
        const body = {
            chat_id: ChatID,
            text: `${message}\nIP: ${ip}\n<tg-spoiler>${user_info}`,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });
            const result = await response.json();
            console.log(result.ok);
        } catch (error) {
            console.error('Error sending message to Telegram:', error);
        }
    }
}

async function generateDynamicUUID(key) {
    const now = new Date();
    const beijingTime = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    const today = beijingTime.toISOString().slice(0, 10);
    const currentHour = beijingTime.getUTCHours();

    let dateToHash;
    if (currentHour < updateTime) {
        const yesterday = new Date(beijingTime);
        yesterday.setUTCDate(beijingTime.getUTCDate() - 1);
        dateToHash = yesterday.toISOString().slice(0, 10);
    } else {
        dateToHash = today;
    }

    const hash = await crypto.subtle.digest('MD5', new TextEncoder().encode(key + dateToHash));
    const hashArray = Array.from(new Uint8Array(hash));
    const uuid = [
        hashArray.slice(0, 4).map(b => b.toString(16).padStart(2, '0')).join(''),
        hashArray.slice(4, 6).map(b => b.toString(16).padStart(2, '0')).join(''),
        '4' + hashArray.slice(6, 8).map(b => b.toString(16).padStart(2, '0')).join('').slice(1),
        (hashArray[8] & 0x3f | 0x80).toString(16).padStart(2, '0') + hashArray.slice(9, 10).map(b => b.toString(16).padStart(2, '0')).join(''),
        hashArray.slice(10, 16).map(b => b.toString(16).padStart(2, '0')).join('')
    ].join('-');

    const nextDay = new Date(beijingTime);
    nextDay.setUTCDate(beijingTime.getUTCDate() + validityDuration);
    const expirationDate = nextDay.toISOString().slice(0, 10);
    userIDTime = `UUIDExpire: ${expirationDate}<br>`;

    return [uuid, uuid.toLowerCase()];
}

async function migrateAddressList(env) {
    const add = await env.KV.get('add');
    const addapi = await env.KV.get('addapi');
    if (add) {
        await env.KV.put('ADD.txt', add);
        await env.KV.delete('add');
    }
    if (addapi) {
        const preferredAddressList = await env.KV.get('ADD.txt');
        await env.KV.put('ADD.txt', `${preferredAddressList}\n${addapi}`);
        await env.KV.delete('addapi');
    }
}

async function KV(request, env) {
    if (!env.KV) {
        return new Response('KV namespace not bound', { status: 400 });
    }

    await migrateAddressList(env);

    if (request.method === 'POST') {
        const {preferredAddresses} = await request.json();
        if (preferredAddresses) {
            await env.KV.put('ADD.txt', preferredAddresses);
            return new Response('Preferred address list updated', { status: 200 });
        }
        return new Response('Missing preferred addresses in request body', { status: 400 });
    }

    if (request.method === 'GET') {
        const preferredAddressList = await env.KV.get('ADD.txt');
        const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Edit Preferred Address List</title>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          textarea { width: 100%; height: 400px; }
          button { margin-top: 10px; }
        </style>
      </head>
      <body>
        <h1>Edit Preferred Address List</h1>
        <form id="edit-form">
          <textarea id="addresses" name="addresses">${preferredAddressList || ''}</textarea>
          <button type="submit">Save</button>
        </form>
        <script>
          document.getElementById('edit-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const addresses = document.getElementById('addresses').value;
            const response = await fetch(window.location.href, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ preferredAddresses: addresses })
            });
            if (response.ok) {
              alert('Saved successfully!');
            } else {
              alert('Save failed.');
            }
          });
        </script>
      </body>
      </html>
    `;
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }

    return new Response('Method not supported', { status: 405 });
}

async function bestIP(request, env) {
    const url = new URL(request.url);
    const host = url.searchParams.get('host') || 'ip.sb';
    const port = parseInt(url.searchParams.get('port'), 10) || 443;
    const max = parseInt(url.searchParams.get('max'), 10) || 10;
    const i = parseInt(url.searchParams.get('i'), 10) || 0;
    const m = parseInt(url.searchParams.get('m'), 10) || 0;
    const p = parseInt(url.searchParams.get('p'), 10) || 0;
    const s = parseInt(url.searchParams.get('s'), 10) || 0;
    const cf = request.cf;
    const html = `
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Online Preferred IP</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f2f5;
            color: #333;
            padding: 20px;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 800px;
            margin: auto;
        }
        h1, h2 {
            color: #1877f2;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="number"] {
            width: calc(100% - 22px);
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #1877f2;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #166fe5;
        }
        #results {
            margin-top: 20px;
            padding: 10px;
            background-color: #f9f9f9;
            border: 1px solid #eee;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .info {
            margin-top: 20px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloudflare Online Preferred IP</h1>
        <div class="form-group">
            <label for="host">Target domain (host):</label>
            <input type="text" id="host" value="${host}">
        </div>
        <div class="form-group">
            <label for="port">Port (port):</label>
            <input type="number" id="port" value="${port}">
        </div>
        <div class="form-group">
            <label for="max">Maximum number of IPs (max):</label>
            <input type="number" id="max" value="${max}">
        </div>
        <button onclick="start()">Start</button>
        <h2>Results:</h2>
        <pre id="results"></pre>
        <div class="info">
            <p>Current Cloudflare node information:</p>
            <p>IP: ${cf.remoteAddr}</p>
            <p>Country: ${cf.country}</p>
            <p>Data center: ${cf.colo}</p>
        </div>
    </div>

    <script>
        const host = document.getElementById('host');
        const port = document.getElementById('port');
        const max = document.getElementById('max');
        const results = document.getElementById('results');
        let controller;

        async function start() {
            controller = new AbortController();
            const { signal } = controller;
            results.textContent = '';
            const url = `?host=${host.value}&port=${port.value}&max=${max.value}&p=1`;
            try {
                const response = await fetch(url, { signal });
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    results.textContent += decoder.decode(value, { stream: true });
                }
            } catch (err) {
                if (err.name === 'AbortError') {
                    results.textContent += '\n\nOperation canceled.';
                } else {
                    results.textContent += `\n\nAn error occurred: ${err.message}`;
                }
            }
        }
    </script>
</body>
</html>
`;

    if (p === 0) {
        return new Response(html, {
            headers: { 'Content-Type': 'text/html;charset=utf-8' },
        });
    }

    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    writer.write(encoder.encode(`Cloudflare Best IP running...\n`));
    writer.write(encoder.encode(`Scan IP: ${host}:${port}\n`));
    writer.write(encoder.encode(`Max connections: ${max}\n`));

    const ips = [
        "104.16.123.96/28", "104.17.0.0/14", "104.18.0.0/15", "104.20.0.0/14", "104.22.0.0/15", "104.24.0.0/14", "104.26.0.0/15", "104.28.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
    ];

    const randomIps = [];
    while (randomIps.length < max) {
        const cidr = ips[Math.floor(Math.random() * ips.length)];
        const [ip, mask] = cidr.split('/');
        if (ip.includes(':')) { // IPv6
            const ipBigInt = BigInt('0x' + ip.replace(/:/g, ''));
            const range = BigInt(2) ** BigInt(128 - parseInt(mask));
            const randomIpBigInt = ipBigInt + (BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) % range);
            const randomIp = [...Array(8)].map((_, i) => ((randomIpBigInt >> BigInt(112 - i * 16)) & BigInt(0xffff)).toString(16)).join(':');
            randomIps.push(randomIp);
        } else { // IPv4
            const ipParts = ip.split('.').map(Number);
            const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
            const range = 1 << (32 - parseInt(mask));
            const randomIpInt = (ipInt & (-1 << (32 - parseInt(mask)))) + Math.floor(Math.random() * range);
            const randomIp = [...Array(4)].map((_, i) => (randomIpInt >> (24 - i * 8)) & 0xff).join('.');
            randomIps.push(randomIp);
        }
    }

    const promises = randomIps.map(async (ip) => {
        const start = Date.now();
        try {
            const socket = await connect({ hostname: ip, port: port });
            const duration = Date.now() - start;
            socket.close();
            return { ip, duration };
        } catch (e) {
            return { ip, duration: Infinity };
        }
    });

    (async () => {
        const results = await Promise.all(promises);
        results.sort((a, b) => a.duration - b.duration);
        results.forEach(result => {
            writer.write(encoder.encode(`IP: ${result.ip}, Delay: ${result.duration}ms\n`));
        });
        writer.close();
    })();

    return new Response(readable, {
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    });
}

function isValidIPv4(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}