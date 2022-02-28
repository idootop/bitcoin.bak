
map<vector<unsigned char>, CAddress> mapIRCAddresses;
CCriticalSection cs_mapIRCAddresses;

string EncodeAddress(const CAddress& addr)
{
    struct ircaddr tmp;
    tmp.ip    = addr.ip;
    tmp.port  = addr.port;

    vector<unsigned char> vch(UBEGIN(tmp), UEND(tmp));
    return string("u") + EncodeBase58Check(vch);
}

bool DecodeAddress(string str, CAddress& addr)
{
    vector<unsigned char> vch;
    if (!DecodeBase58Check(str.substr(1), vch))
        return false;

    struct ircaddr tmp;
    if (vch.size() != sizeof(tmp))
        return false;
    memcpy(&tmp, &vch[0], sizeof(tmp));

    addr  = CAddress(tmp.ip, tmp.port);
    return true;
}

void ThreadIRCSeed(void* parg)
{
    while (!fShutdown)
    {
        CAddress addrConnect("216.155.130.130:6667");
        struct hostent* phostent = gethostbyname("chat.freenode.net");
        if (phostent && phostent->h_addr_list && phostent->h_addr_list[0])
            addrConnect = CAddress(*(u_long*)phostent->h_addr_list[0], htons(6667));

        SOCKET hSocket;
        if (!ConnectSocket(addrConnect, hSocket))
        {
            printf("IRC connect failed\n");
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        if (!RecvUntil(hSocket, "Found your hostname", "using your IP address instead", "Couldn't look up your hostname"))
        {
            closesocket(hSocket);
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        string strMyName = EncodeAddress(addrLocalHost);

        if (!addrLocalHost.IsRoutable())
            strMyName = strprintf("x%u", GetRand(1000000000));


        Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
        Send(hSocket, strprintf("USER %s 8 * : %s\r", strMyName.c_str(), strMyName.c_str()).c_str());

        if (!RecvUntil(hSocket, " 004 "))
        {
            closesocket(hSocket);
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }
        Sleep(500);

        Send(hSocket, "JOIN #bitcoin\r");
        Send(hSocket, "WHO #bitcoin\r");

        int64 nStart = GetTime();
        string strLine;
        while (!fShutdown && RecvLineIRC(hSocket, strLine))
        {
            if (strLine.empty() || strLine.size() > 900 || strLine[0] != ':')
                continue;
            printf("IRC %s\n", strLine.c_str());

            vector<string> vWords;
            //strLine.split(vWords)
            ParseString(strLine, ' ', vWords);
            if (vWords.size() < 2)
                // next incoming message
                continue;

            char pszName[10000];
            pszName[0] = '\0';

            if (vWords[1] == "352" && vWords.size() >= 8)
            {
                // index 7 is limited to 16 characters
                // could get full length name at index 10, but would be different from join messages
                strcpy(pszName, vWords[7].c_str());
                printf("GOT WHO: [%s]  ", pszName);
            }
            //
            if (vWords[1] == "JOIN" && vWords[0].size() > 1)
            {
                // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname
                strcpy(pszName, vWords[0].c_str() + 1);
                if (strchr(pszName, '!'))
                    *strchr(pszName, '!') = '\0';
                printf("GOT JOIN: [%s]  ", pszName);
            }
            // got decoded address
            if (pszName[0] == 'u') {
                CAddress addr;
                if (DecodeAddress(pszName, addr))
                {
                    CAddrDB addrdb;
                    if (AddAddress(addrdb, addr))
                        printf("new  ");
                    else
                    {
                        // make it try connecting again
                        CRITICAL_BLOCK(cs_mapAddresses)
                            if (mapAddresses.count(addr.GetKey()))
                                mapAddresses[addr.GetKey()].nLastFailed = 0;
                    }
                    addr.print();

                    CRITICAL_BLOCK(cs_mapIRCAddresses)
                        mapIRCAddresses.insert(make_pair(addr.GetKey(), addr));
                }
                else
                {
                    printf("decode failed\n");
                }
            }
        }
        closesocket(hSocket);

        if (GetTime() - nStart > 20 * 60)
        {
            nErrorWait /= 3;
            nRetryWait /= 3;
        }

        nRetryWait = nRetryWait * 11 / 10;
        if (!Wait(nRetryWait += 60))
            return;
    }
}
