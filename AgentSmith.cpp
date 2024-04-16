// AgentSmith.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <filesystem>
#include <conio.h>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <initguid.h>
#include <chrono>
using namespace std::chrono_literals;
#include <thread>

#pragma comment(lib, "Fwpuclnt.lib")

#include <colorconsole.hpp> // https://github.com/aafulei/color-console
#include <cpr/cpr.h>

char getKeyPress()
{
    if (_kbhit())
    {
        return _getch();
    }
    return '\0';
}

class Isolator final
{
public:
    Isolator()
    {
    }

    void Free()
    {
        if (!_isolated)
            return;

        std::cout << dye::yellow("#########################################") << std::endl;
        std::cout << dye::yellow("Free endpoint so everyone may communicate") << std::endl;
        std::cout << dye::yellow("#########################################") << std::endl;

        _engine.Close();

        _isolated = false;
    }

    void Isolate(const std::vector<std::filesystem::path>& trustedApps)
    {
        if (!_isolated && trustedApps.size() == 0)
            return;

        if (_isolated && trustedApps.size() == 0)
        {
            Free();
            return;
        }

        if (_isolated)
        {
            _engine.Close();
            _isolated = false;
        }

        Install();

        std::cout << dye::yellow("###########################################") << std::endl;
        std::cout << dye::yellow("Isolate endpoint so only these trusted apps may communicate:") << std::endl;

        // https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

        std::vector<FWPM_FILTER_CONDITION0> conds;
        std::vector<FWP_BYTE_BLOB*>         appBlobs;

        for (const auto& ta : trustedApps)
        {
            std::cout << hue::yellow << ta << hue::reset << std::endl;

            FWPM_FILTER_CONDITION0 cond;

            // appPath must be a fully-qualified file name, and the file must exist on the local machine.
            FWP_BYTE_BLOB* appBlob = nullptr;
            DWORD          result  = ::FwpmGetAppIdFromFileName0(ta.c_str(), &appBlob);

            cond.fieldKey                = FWPM_CONDITION_ALE_APP_ID;
            cond.matchType               = FWP_MATCH_EQUAL;
            cond.conditionValue.type     = FWP_BYTE_BLOB_TYPE;
            cond.conditionValue.byteBlob = appBlob;

            conds.push_back(cond);
            appBlobs.push_back(appBlob);
        }
        std::cout << dye::yellow("###########################################") << std::endl;

        // Permit filter for all trusted apps
        FWPM_FILTER0 filter {};
        filter.displayData.name    = const_cast<wchar_t*>(L"AgentSmith isolation <permit> filter");
        filter.flags               = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; // hard permit
        filter.providerKey         = Provider::Key;
        filter.layerKey            = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey         = __uuidof(SubLayer);
        filter.weight.type         = FWP_UINT8;
        filter.weight.uint8        = 15; // should be highest in our sublayer
        filter.numFilterConditions = (UINT32)conds.size();
        filter.filterCondition     = &conds[0];
        filter.action.type         = FWP_ACTION_PERMIT;

        try
        {
            DWORD result = ::FwpmTransactionBegin0(_engine, 0);
            ThrowIfFailed("FwpmTransactionBegin0", result);

            result = ::FwpmFilterAdd0(_engine, &filter, nullptr, nullptr);
            ThrowIfFailed("FwpmFilterAdd0", result);

            // same filter for IPv6
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            result          = ::FwpmFilterAdd0(_engine, &filter, nullptr, nullptr);
            ThrowIfFailed("FwpmFilterAdd0", result);

            // Block ALL filter (hard block)
            filter.displayData.name    = const_cast<wchar_t*>(L"AgentSmith isolation <block> filter");
            filter.layerKey            = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter.weight.uint8        = 0; // lower prio than the above permit filter
            filter.numFilterConditions = 0;
            filter.filterCondition     = nullptr;
            filter.action.type         = FWP_ACTION_BLOCK;

            // TODO Should we only block TCP?

            result = ::FwpmFilterAdd0(_engine, &filter, nullptr, nullptr);
            ThrowIfFailed("FwpmFilterAdd0", result);

            // same filter for IPv6
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            result          = ::FwpmFilterAdd0(_engine, &filter, nullptr, nullptr);
            ThrowIfFailed("FwpmFilterAdd0", result);

            // TODO block all ingress? => FWPM_LAYER_ALE_AUTH_LISTEN_V4/FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
            // https://learn.microsoft.com/en-us/windows/win32/fwp/tcp-packet-flows

            // TODO How about local comm? Allow loopback?

            result = ::FwpmTransactionCommit0(_engine);
            ThrowIfFailed("FwpmTransactionCommit0", result);

            _isolated = true;
        }
        catch (std::exception& ex)
        {
            ::FwpmTransactionAbort0(_engine);

            std::cout << dye::red("###########################################") << std::endl;
            std::cout << hue::red << ex.what() << hue::reset << std::endl;
            std::cout << dye::red("###########################################") << std::endl;
        }

        // free appBlobs
        for (const auto& appBlob : appBlobs)
        {
            ::FwpmFreeMemory0((void**)&appBlob);
        }
    }

private:
    bool _installed = false;
    bool _isolated  = false;

    class Engine final
    {
    public:
        static constexpr const wchar_t* const SessionName = L"AgentSmith Isolation Session";

        void Open()
        {
            if (_handle)
                return;

            FWPM_SESSION0 session {};

            // The session name isn't required but may be useful for diagnostics.
            session.displayData.name = const_cast<wchar_t*>(SessionName);
            // Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
            // errors while waiting to acquire the transaction lock.
            session.txnWaitTimeoutInMSec = INFINITE;
            // When this flag is set, any objects added during the session are automatically deleted when the session
            // ends.
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            // The authentication service should always be RPC_C_AUTHN_DEFAULT.
            DWORD result = ::FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &_handle);
            ThrowIfFailed("FwpmEngineOpen0", result);
        }
        void Close()
        {
            if (!_handle)
                return;

            ::FwpmEngineClose0(_handle);
            _handle = nullptr;
        }
        ~Engine()
        {
            Close();
        }
        operator HANDLE()
        {
            return _handle;
        }

    private:
        HANDLE _handle = nullptr;
    };

    Engine _engine;

    struct __declspec(uuid("{DE6F528A-8578-4B0E-A127-EB1EE5C6817F}")) Provider
    {
        static constexpr GUID*                Key  = const_cast<GUID*>(&__uuidof(Provider));
        static constexpr const wchar_t* const Name = L"AgentSmith Isolation Provider";

        static void Install(HANDLE engine)
        {
            FWPM_PROVIDER0 provider {};
            // The provider and sublayer keys are going to be used repeatedly when
            // adding filters and other objects. It's easiest to use well-known GUIDs
            // defined in a header somewhere, rather than having BFE generate the keys.
            provider.providerKey = __uuidof(Provider);
            // For MUI compatibility, object names should be indirect strings. See
            // SHLoadIndirectString for details.
            provider.displayData.name = const_cast<wchar_t*>(Provider::Name);
            // Since we always want the provider and sublayer to be present, it's
            // easiest to add them as persistent objects during install.  Alternatively,
            // we could add non-persistent objects every time our service starts.
            provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

            DWORD result = ::FwpmProviderAdd0(engine, &provider, nullptr);
            // Ignore FWP_E_ALREADY_EXISTS. This allows install to be re-run as needed
            // to repair a broken configuration.
            if (result != FWP_E_ALREADY_EXISTS)
            {
                ThrowIfFailed("FwpmProviderAdd0", result);
            }
        }
    };
    struct __declspec(uuid("{076119FA-6A84-4F93-97E5-F0A16BB50DAC}")) SubLayer
    {
        static constexpr const wchar_t* const Name = L"AgentSmith Isolation SubLayer";

        static void Install(HANDLE engine)
        {
            FWPM_SUBLAYER0 subLayer {};

            subLayer.subLayerKey      = __uuidof(SubLayer);
            subLayer.displayData.name = const_cast<wchar_t*>(Name);
            // Causes sublayer to be persistent, surviving across BFE stop/start.
            subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;

            // Link all our other objects to our provider. When multiple providers are
            // installed on a computer, this makes it easy to determine who added what.
            subLayer.providerKey = Provider::Key;
            // We don't care what our sublayer weight is, so we pick a weight in the
            // middle and let BFE assign the closest available.
            subLayer.weight = 0x8000;

            DWORD result = ::FwpmSubLayerAdd0(engine, &subLayer, NULL);
            if (result != FWP_E_ALREADY_EXISTS)
            {
                ThrowIfFailed("FwpmSubLayerAdd0", result);
            }
        }
    };

    void Install()
    {
        // https://learn.microsoft.com/en-us/windows/win32/fwp/installing-a-provider

        _engine.Open();

        if (_installed)
            return;

        // We add the provider and sublayer from within a single transaction to make
        // it easy to clean up partial results in error paths.
        DWORD result = ::FwpmTransactionBegin0(_engine, 0);
        ThrowIfFailed("FwpmTransactionBegin0", result);

        Provider::Install(_engine);
        SubLayer::Install(_engine);

        // Once all the adds have succeeded, we commit the transaction to persist
        // the new objects.
        result = ::FwpmTransactionCommit0(_engine);
        ThrowIfFailed("FwpmTransactionCommit0", result);

        _installed = true;
    }

    static void ThrowIfFailed(const char* name, DWORD result)
    {
        if (result == ERROR_SUCCESS)
            return;

        throw new std::exception(std::format("{} failed with {}", name, result).c_str());
    }
};

int main(int argc, char* argv[])
{
    std::filesystem::path programPath {argv[0]};

    auto processName = programPath.stem().string();

    std::vector<std::filesystem::path> trustedApps;
    std::vector<std::filesystem::path> trustedAppsEx;

    std::unique_ptr<Isolator> isolator;
    if (processName == "Neo")
    {
        isolator = std::make_unique<Isolator>();

        trustedApps.push_back(programPath);
        trustedAppsEx.push_back(programPath);

        auto trinity = programPath.replace_filename(L"Trinity.exe");
        trustedAppsEx.push_back(trinity);
    }

    std::cout << hue::green << "Hello " << processName << hue::reset << std::endl;

    // https://docs.libcpr.org/advanced-usage.html#session-objects
    cpr::Url     url = cpr::Url {"https://api64.ipify.org"};
    cpr::Session session;
    session.SetUrl(url);

    int send = 10;
    while (1)
    {
        char c = getKeyPress();
        if (c != '\0')
        {
            if (c == 'x')
                break;

            if (isolator.get())
            {
                if (c == 'f')
                    isolator->Free();
                else if (c == 'i')
                    isolator->Isolate(trustedApps);
                else if (c == 'e')
                    isolator->Isolate(trustedAppsEx);
            }
        }

        if (--send == 0)
        {
            send            = 10;
            cpr::Response r = session.Get();
            if (r.status_code == 200)
                std::cout << r.text << std::endl;
            else
                std::cout << hue::red << "Request failed with " << r.status_code << hue::reset << std::endl;
        }
        std::this_thread::sleep_for(100ms);
    }
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started:
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files
//   to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
