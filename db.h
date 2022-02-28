class CTxDB : public CDB
{
public:
    CTxDB(const char* pszMode="r+", bool fTxn=false) : CDB(!fClient ? "blkindex.dat" : NULL, pszMode, fTxn) { }
private:
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);
public:
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    bool ReadOwnerTxes(uint160 hash160, int nHeight, vector<CTransaction>& vtx);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(uint256 hash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    bool LoadBlockIndex();
};





class CReviewDB : public CDB
{
public:
    CReviewDB(const char* pszMode="r+", bool fTxn=false) : CDB("reviews.dat", pszMode, fTxn) { }
private:
    CReviewDB(const CReviewDB&);
    void operator=(const CReviewDB&);
public:
    bool ReadUser(uint256 hash, CUser& user)
    {
        return Read(make_pair(string("user"), hash), user);
    }

    bool WriteUser(uint256 hash, const CUser& user)
    {
        return Write(make_pair(string("user"), hash), user);
    }

    bool ReadReviews(uint256 hash, vector<CReview>& vReviews);
    bool WriteReviews(uint256 hash, const vector<CReview>& vReviews);
};





class CMarketDB : public CDB
{
public:
    CMarketDB(const char* pszMode="r+", bool fTxn=false) : CDB("market.dat", pszMode, fTxn) { }
private:
    CMarketDB(const CMarketDB&);
    void operator=(const CMarketDB&);
};





class CAddrDB : public CDB
{
public:
    CAddrDB(const char* pszMode="r+", bool fTxn=false) : CDB("addr.dat", pszMode, fTxn) { }
private:
    CAddrDB(const CAddrDB&);
    void operator=(const CAddrDB&);
public:
    bool WriteAddress(const CAddress& addr);
    bool LoadAddresses();
};

bool LoadAddresses();





class CWalletDB : public CDB
{
public:
    CWalletDB(const char* pszMode="r+", bool fTxn=false) : CDB("wallet.dat", pszMode, fTxn) { }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    bool ReadName(const string& strAddress, string& strName)
    {
        strName = "";
        return Read(make_pair(string("name"), strAddress), strName);
    }

    bool WriteName(const string& strAddress, const string& strName)
    {
        mapAddressBook[strAddress] = strName;
        return Write(make_pair(string("name"), strAddress), strName);
    }

    bool EraseName(const string& strAddress)
    {
        mapAddressBook.erase(strAddress);
        return Erase(make_pair(string("name"), strAddress));
    }

    bool ReadTx(uint256 hash, CWalletTx& wtx)
    {
        return Read(make_pair(string("tx"), hash), wtx);
    }

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        return Write(make_pair(string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        return Erase(make_pair(string("tx"), hash));
    }

    bool ReadKey(const vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey)
    {
        vchPrivKey.clear();
        return Read(make_pair(string("key"), vchPubKey), vchPrivKey);
    }

    bool WriteKey(const vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey)
    {
        return Write(make_pair(string("key"), vchPubKey), vchPrivKey, false);
    }

    bool ReadDefaultKey(vector<unsigned char>& vchPubKey)
    {
        vchPubKey.clear();
        return Read(string("defaultkey"), vchPubKey);
    }

    bool WriteDefaultKey(const vector<unsigned char>& vchPubKey)
    {
        return Write(string("defaultkey"), vchPubKey);
    }

    template<typename T>
    bool ReadSetting(const string& strKey, T& value)
    {
        return Read(make_pair(string("setting"), strKey), value);
    }

    template<typename T>
    bool WriteSetting(const string& strKey, const T& value)
    {
        return Write(make_pair(string("setting"), strKey), value);
    }

    bool LoadWallet(vector<unsigned char>& vchDefaultKeyRet);
};

bool LoadWallet();

inline bool SetAddressBookName(const string& strAddress, const string& strName)
{
    return CWalletDB().WriteName(strAddress, strName);
}
