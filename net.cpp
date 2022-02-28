//
// Subscription methods for the broadcast and subscription system.
// Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
//
// The subscription system uses a meet-in-the-middle strategy.
// With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
// subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
//

bool AnySubscribed(unsigned int nChannel)
{
    if (pnodeLocalHost->IsSubscribed(nChannel))
        return true;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->IsSubscribed(nChannel))
                return true;
    return false;
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Initiate network connections
    int nTry = 0;
    bool fIRCOnly = false;
    const int nMaxConnections = 15;
    loop
    {
        // Wait
        vfThreadRunning[1] = false;
        Sleep(500);
        while (vNodes.size() >= nMaxConnections || vNodes.size() >= mapAddresses.size())
        {
            CheckForShutdown(1);
            Sleep(2000);
        }
        vfThreadRunning[1] = true;
        CheckForShutdown(1);


        //
        // The IP selection process is designed to limit vulnerability to address flooding.
        // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
        // chosen within the class C.  An attacker may be able to allocate many IPs, but
        // they would normally be concentrated in blocks of class C's.  They can hog the
        // attention within their class C, but not the whole IP address space overall.
        // A lone node in a class C will get as much attention as someone holding all 255
        // IPs in another class C.
        //

        // Every other try is with IRC addresses only
        fIRCOnly = !fIRCOnly;
        if (mapIRCAddresses.empty())
            fIRCOnly = false;
        else if (nTry++ < 30 && vNodes.size() < nMaxConnections/2)
            fIRCOnly = true;

        // Make a list of unique class C's
        unsigned char pchIPCMask[4] = { 0xff, 0xff, 0xff, 0x00 };
        unsigned int nIPCMask = *(unsigned int*)pchIPCMask;
        vector<unsigned int> vIPC;
        CRITICAL_BLOCK(cs_mapIRCAddresses)
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            vIPC.reserve(mapAddresses.size());
            unsigned int nPrev = 0;
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (!addr.IsIPv4())
                    continue;
                if (fIRCOnly && !mapIRCAddresses.count(item.first))
                    continue;

                // Taking advantage of mapAddresses being in sorted order,
                // with IPs of the same class C grouped together.
                unsigned int ipC = addr.ip & nIPCMask;
                if (ipC != nPrev)
                    vIPC.push_back(nPrev = ipC);
            }
        }
        if (vIPC.empty())
            continue;

        // Choose a random class C
        unsigned int ipC = vIPC[GetRand(vIPC.size())];

        // Organize all addresses in the class C by IP
        map<unsigned int, vector<CAddress> > mapIP;
        CRITICAL_BLOCK(cs_mapIRCAddresses)
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            int64 nDelay = ((30 * 60) << vNodes.size());
            if (!fIRCOnly)
            {
                nDelay *= 2;
                if (vNodes.size() >= 3)
                    nDelay *= 4;
                if (!mapIRCAddresses.empty())
                    nDelay *= 100;
            }

            for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.lower_bound(CAddress(ipC, 0).GetKey());
                 mi != mapAddresses.upper_bound(CAddress(ipC | ~nIPCMask, 0xffff).GetKey());
                 ++mi)
            {
                const CAddress& addr = (*mi).second;
                if (fIRCOnly && !mapIRCAddresses.count((*mi).first))
                    continue;

                int64 nRandomizer = (addr.nLastFailed * addr.ip * 7777U) % 20000;
                if (GetTime() - addr.nLastFailed > nDelay * nRandomizer / 10000)
                    mapIP[addr.ip].push_back(addr);
            }
        }
        if (mapIP.empty())
            continue;

        // Choose a random IP in the class C
        map<unsigned int, vector<CAddress> >::iterator mi = mapIP.begin();
        advance(mi, GetRand(mapIP.size()));

        // Once we've chosen an IP, we'll try every given port before moving on
        foreach(const CAddress& addrConnect, (*mi).second)
        {
            //
            // Initiate outbound network connection
            //
            CheckForShutdown(1);
            if (addrConnect.ip == addrLocalHost.ip || !addrConnect.IsIPv4() || FindNode(addrConnect.ip))
                continue;

            vfThreadRunning[1] = false;
            CNode* pnode = ConnectNode(addrConnect);
            vfThreadRunning[1] = true;
            CheckForShutdown(1);
            if (!pnode)
                continue;
            pnode->fNetworkNode = true;

            if (addrLocalHost.IsRoutable())
            {
                // Advertise our address
                vector<CAddress> vAddrToSend;
                vAddrToSend.push_back(addrLocalHost);
                pnode->PushMessage("addr", vAddrToSend);
            }

            // Get as many addresses as we can
            pnode->PushMessage("getaddr");

            ////// should the one on the receiving end do this too?
            // Subscribe our local subscription list
            const unsigned int nHops = 0;
            for (unsigned int nChannel = 0; nChannel < pnodeLocalHost->vfSubscribe.size(); nChannel++)
                if (pnodeLocalHost->vfSubscribe[nChannel])
                    pnode->PushMessage("subscribe", nChannel, nHops);

            break;
        }
    }
}

//// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
void ThreadBitcoinMiner(void* parg)
{
    vfThreadRunning[3] = true;
    CheckForShutdown(3);
    try
    {
        bool fRet = BitcoinMiner();
        printf("BitcoinMiner returned %s\n\n\n", fRet ? "true" : "false");
    }
    CATCH_PRINT_EXCEPTION("BitcoinMiner()")
    vfThreadRunning[3] = false;
}

bool StartNode(string& strError)
{
    strError = "";

    // Sockets startup
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get local host ip
    char pszHostName[255];
    if (gethostname(pszHostName, 255) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    struct hostent* phostent = gethostbyname(pszHostName);
    if (!phostent)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostbyname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    addrLocalHost = CAddress(*(long*)(phostent->h_addr_list[0]),
                             DEFAULT_PORT,
                             nLocalServices);
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Create socket for listening for incoming connections
    SOCKET hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Set to nonblocking, incoming connections will also inherit this
    u_long nOne = 1;
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (ioctlsocket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    int nRetryLimit = 15;
    struct sockaddr_in sockaddr = addrLocalHost.GetSockAddr();
    if (bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Error: Unable to bind to port %s on this computer. The program is probably already running.", addrLocalHost.ToString().c_str());
        else
            strError = strprintf("Error: Unable to bind to port %s on this computer (bind returned error %d)", addrLocalHost.ToString().c_str(), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("bound to addrLocalHost = %s\n\n", addrLocalHost.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get our external IP address for incoming connections
    if (addrIncoming.ip)
        addrLocalHost.ip = addrIncoming.ip;

    if (GetMyExternalIP(addrLocalHost.ip))
    {
        addrIncoming = addrLocalHost;
        CWalletDB().WriteSetting("addrIncoming", addrIncoming);
    }

    // Get addresses from IRC and advertise ours
    if (_beginthread(ThreadIRCSeed, 0, NULL) == -1)
        printf("Error: _beginthread(ThreadIRCSeed) failed\n");

    //
    // Start threads
    //
    if (_beginthread(ThreadSocketHandler, 0, new SOCKET(hListenSocket)) == -1)
    {
        strError = "Error: _beginthread(ThreadSocketHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadOpenConnections, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadOpenConnections) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadMessageHandler, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadMessageHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}
