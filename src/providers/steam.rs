


fn steam_main() -> Result<(), Error>{
    const char* pszInternalCheckInterfaceVersions = "SteamUtils010\0SteamController008\0SteamInput006\0SteamUser023\0\0";

    switch (SteamReplace::init_steam(pszInternalCheckInterfaceVersions)) {
    case  1: std::cout << "steam is already running" << std::endl; break;
    case  2: std::cout << "Cannot create IPC pipe to Steam client process.  Steam is probably not running." << std::endl; break;
    case  3: std::cout << "ConnectToGlobalUser failed." << std::endl; break;
    case  4: std::cout << "interface check failed" << std::endl; break;
    case  5: std::cout << "failed to load 'SteamUtils010' interface" << std::endl; break;
    case  6: std::cout << "failed to load 'SteamUser023' interface" << std::endl; break;
    case  7: std::cout << "No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder." << std::endl; break;
    case  8: std::cout << "[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam." << std::endl; break;
    case  9: std::cout << "Could not determine Steam client install directory." << std::endl; break;
    case 10: std::cout << "couldn't convert path to wide string" << std::endl; break;
    case 11: std::cout << "Failed to load steam client module" << std::endl; break;
    case 12: std::cout << "Unable to locate interface factory in steamclient64.dll" << std::endl; break;
    case 13: std::cout << "failed to load 'SteamClient021' interface" << std::endl; break;
    case  0:{
        std::atomic<bool> bHaltBackgroundThread{ false };
        // Set up a background thread to run
        std::thread HandlerThread = std::thread([&]() {
            while (!bHaltBackgroundThread) {
                //Modio::RunPendingHandlers();
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                SteamReplace::SteamAPI_RunCallbacks();
            }
            bHaltBackgroundThread = false;
        });

        //EPacket::SteamAuthHelper* SteamCallbacks = new EPacket::SteamAuthHelper();
        // Get the Steam Encrypted App Ticket
        char k_unSecretData[] = { 0x39, 0x66, 0x37, 0x61, 0x62, 0x64, 0x36, 0x33, 0x37, 0x35, 0x63, 0x34, 0x61, 0x33, 0x66, 0x64, 0x35, 0x30, 0x61, 0x37, 0x32, 0x62, 0x30, 0x39, 0x31, 0x31, 0x31, 0x35, 0x63, 0x62, 0x32, 0x33, 0x37, 0x32, 0x64, 0x35, 0x65, 0x35, 0x61, 0x63, 0x37, 0x61, 0x37, 0x37, 0x31, 0x39, 0x65, 0x35, 0x34, 0x30, 0x35, 0x33, 0x30, 0x62, 0x32, 0x39, 0x37, 0x65, 0x63, 0x34, 0x62, 0x65, 0x37, 0x39, 0x00 };
        SteamAPICall_t hSteamAPICall = SteamReplace::SteamUser()->RequestEncryptedAppTicket(&k_unSecretData, sizeof(k_unSecretData));
        cout << "API call num: " << hSteamAPICall << "\n";
        cout << "Callback expected: " << EncryptedAppTicketResponse_t::k_iCallback << "\n";
        /*SteamCallbacks->*/EPacket::m_SteamCallResultEncryptedAppTicket.Set(/*hSteamAPICall,*/ /*SteamCallbacks,*/ &EPacket::/*SteamAuthHelper::*/OnEncryptedAppTicketResponse);

        SteamReplace::registered_callbacks[EncryptedAppTicketResponse_t::k_iCallback] = (s_deps::CCallbackBase*)&EPacket::m_SteamCallResultEncryptedAppTicket;

        EPacket::SteamAuthComplete.get_future().wait();

        bHaltBackgroundThread = false;
        HandlerThread.join();
    }}
}