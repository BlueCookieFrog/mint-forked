use std::{fs::File, path::Path};


type SteamAPICall_t = u64;
type HSteamPipe = i32;
type HSteamUser = u32;
type HMODULE = u64;
type HAuthTicket = u32;
type CGameID = u64;
type CSteamID = u64;
type AppId_t = u32;
type EAccountType = i32;
type EVoiceResult = i32;
type EUserHasLicenseForAppResult = i32;
type EBeginAuthSessionResult = i32;
type EDurationControlOnlineState = i32;
type SteamAPIWarningMessageHook_t = u64;
type SteamAPI_CheckCallbackRegistered_t = u64; // uhh i dont think this one is right
type HKEY = u64;
type LSTATUS = i32;
type HANDLE = u64;
type EncryptedAppTicketResponse_t = i32;

type CreateInterface = extern "stdcall" fn(*const u8, *mut i32) -> UNK_PTR;
type Steam_IsKnownInterface = extern "stdcall" fn(*const u8) -> bool;
type client_ReleaseThreadLocalMemory = extern "stdcall" fn(bool) -> UNK_PTR;
type BGetCallback_func = extern "stdcall" fn(HSteamPipe, *mut CallbackMsg_t) -> bool;
type FreeLastCallback_func = extern "stdcall" fn(HSteamPipe) -> bool;
type GetAPICallResult_func = extern "stdcall" fn(HSteamPipe, SteamAPICall_t, *mut u8, i32, i32, *mut bool) -> bool;
    

#[repr(C)]
struct CallbackMsg_t{ m_hSteamUser: HSteamUser, m_iCallback: i32, m_pubParam: *mut u8, m_cubParam: i32 }
#[repr(C)]
#[derive(Copy, Clone)]
struct SteamAPICallCompleted_t{ m_hAsyncCall: SteamAPICall_t, m_iCallback:i32, m_cubParam:i32}

type UNK_PTR = *mut ();
const PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS: &str = "SteamUtils010\0SteamController008\0SteamInput006\0SteamUser023\0\0";
const HKCR:HKEY = 0xffffffff80000000; // HKEY_CLASSES_ROOT
const HKCU:HKEY = 0xffffffff80000001; // HKEY_CURRENT_USER
const HKLM:HKEY = 0xffffffff80000002; // HKEY_LOCAL_MACHINE
const STILL_ACTIVE:i32 = 0x00000103;


#[repr(C)]
pub struct ISteamInput__bindgen_vtable{
    Init:                           extern "stdcall" fn(*mut ISteamInput, bool) -> bool,
    Shutdown:                       extern "stdcall" fn(*mut ISteamInput) -> bool,
    SetInputActionManifestFilePath: extern "stdcall" fn(*mut ISteamInput, *mut u8) -> bool,
    RunFrame:                       extern "stdcall" fn(*mut ISteamInput, bool),
}
pub unsafe fn ISteamInput_RunFrame(_self: *mut ISteamInput, bReservedValue: bool){ return ((*(*_self).vtable_).RunFrame)(_self, bReservedValue); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamInput {
    pub vtable_: *const ISteamInput__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamController__bindgen_vtable{
    Init:                           extern "stdcall" fn(*mut ISteamController) -> bool,
    Shutdown:                       extern "stdcall" fn(*mut ISteamController) -> bool,
    RunFrame:                       extern "stdcall" fn(*mut ISteamController),
}
pub unsafe fn ISteamController_RunFrame(_self: *mut ISteamController){ return ((*(*_self).vtable_).RunFrame)(_self); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamController {
    pub vtable_: *const ISteamController__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamUser__bindgen_vtable{
    GetHSteamUser:                  extern "stdcall" fn(*mut ISteamUser) -> HSteamUser,
    BLoggedOn:                      extern "stdcall" fn(*mut ISteamUser) -> bool,
    GetSteamID:                     extern "stdcall" fn(*mut ISteamUser) -> CSteamID,
    InitiateGameConnection_DEPRECATED:  extern "stdcall" fn(*mut ISteamUser, UNK_PTR, i32, CSteamID, u32, u16, bool) -> i32, // p2: void *pAuthBlob
    TerminateGameConnection_DEPRECATED: extern "stdcall" fn(*mut ISteamUser, u32, u16),
    TrackAppUsageEvent:             extern "stdcall" fn(*mut ISteamUser, CGameID, i32, *const u8), // p4 is optional??
    GetUserDataFolder:              extern "stdcall" fn(*mut ISteamUser,  *mut u8, i32) -> bool,
    StartVoiceRecording:            extern "stdcall" fn(*mut ISteamUser),
    StopVoiceRecording:             extern "stdcall" fn(*mut ISteamUser),
    GetAvailableVoice:              extern "stdcall" fn(*mut ISteamUser, *mut u32, *mut u32, u32) -> EVoiceResult, // default params 3,4
    GetVoice:                       extern "stdcall" fn(*mut ISteamUser, bool, UNK_PTR, u32, u32, bool, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    DecompressVoice:                extern "stdcall" fn(*mut ISteamUser, UNK_PTR, u32, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    GetVoiceOptimalSampleRate:      extern "stdcall" fn(*mut ISteamUser) -> u32,
    GetAuthSessionTicket:           extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, *mut u32, UNK_PTR) -> HAuthTicket, // p5 : SteamNetworkingIdentity
    GetAuthTicketForWebApi:         extern "stdcall" fn(*mut ISteamUser, *mut u8) -> HAuthTicket,
    BeginAuthSession:               extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, CSteamID) -> EBeginAuthSessionResult,
    EndAuthSession:                 extern "stdcall" fn(*mut ISteamUser, CSteamID),
    CancelAuthTicket:               extern "stdcall" fn(*mut ISteamUser, HAuthTicket),
    UserHasLicenseForApp:           extern "stdcall" fn(*mut ISteamUser, CSteamID, AppId_t) -> EUserHasLicenseForAppResult,
    BIsBehindNAT:                   extern "stdcall" fn(*mut ISteamUser) -> bool,
    AdvertiseGame:                  extern "stdcall" fn(*mut ISteamUser, CSteamID, u32, u16),
    RequestEncryptedAppTicket:      extern "stdcall" fn(*mut ISteamUser, *const u8, i32) -> SteamAPICall_t,
    GetEncryptedAppTicket:          extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, *mut u32) -> bool,
    GetGameBadgeLevel:              extern "stdcall" fn(*mut ISteamUser, i32, bool) -> i32,
    GetPlayerSteamLevel:            extern "stdcall" fn(*mut ISteamUser) -> i32,
    RequestStoreAuthURL:            extern "stdcall" fn(*mut ISteamUser, *mut u8) -> SteamAPICall_t,
    BIsPhoneVerified:               extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsTwoFactorEnabled:            extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsPhoneIdentifying:            extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsPhoneRequiringVerification:  extern "stdcall" fn(*mut ISteamUser) -> bool,
    GetMarketEligibility:           extern "stdcall" fn(*mut ISteamUser) -> SteamAPICall_t,
    GetDurationControl:             extern "stdcall" fn(*mut ISteamUser) -> SteamAPICall_t,
    BSetDurationControlOnlineState: extern "stdcall" fn(*mut ISteamUser, EDurationControlOnlineState) -> bool,
}
pub unsafe fn ISteamUser_RequestEncryptedAppTicket(_self: *mut ISteamUser, data: *const u8, data_length: i32) -> SteamAPICall_t{ return ((*(*_self).vtable_).RequestEncryptedAppTicket)(_self, data, data_length); }
pub unsafe fn ISteamUser_GetEncryptedAppTicket(_self: *mut ISteamUser, data: *mut u8, data_size: i32, size_used: *mut u32) -> bool{ return ((*(*_self).vtable_).GetEncryptedAppTicket)(_self, data, data_size, size_used); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUser {
    pub vtable_: *const ISteamUser__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamUtils__bindgen_vtable{
    GetSecondsSinceAppActive:      extern "stdcall" fn(*mut ISteamUtils) -> u32,
    GetSecondsSinceComputerActive: extern "stdcall" fn(*mut ISteamUtils) -> u32,
    GetConnectedUniverse:          extern "stdcall" fn(*mut ISteamUtils) -> u32,
    GetServerRealTime:             extern "stdcall" fn(*mut ISteamUtils) -> u32,
    GetIPCountry:                  extern "stdcall" fn(*mut ISteamUtils) -> *const u8,
    GetImageSize:                  extern "stdcall" fn(*mut ISteamUtils, i32, *mut u32, *mut u32) -> bool,
    GetImageRGBA:                  extern "stdcall" fn(*mut ISteamUtils, i32, *mut u8, i32) -> bool,
    GetCSERIPPort:                 extern "stdcall" fn(*mut ISteamUtils, *mut u32, *mut u16) -> bool,
    GetCurrentBatteryPower:        extern "stdcall" fn(*mut ISteamUtils) -> u8,
    GetAppID:                      extern "stdcall" fn(*mut ISteamUtils) -> u32,
    SetOverlayNotificationPosition:extern "stdcall" fn(*mut ISteamUtils, u32),
    IsAPICallCompleted:            extern "stdcall" fn(*mut ISteamUtils, SteamAPICall_t, *mut bool) -> bool,
    GetAPICallFailureReason:       extern "stdcall" fn(*mut ISteamUtils, SteamAPICall_t) -> i32,
    GetAPICallResult:              extern "stdcall" fn(*mut ISteamUtils, SteamAPICall_t, *const (), i32, i32, *mut bool) -> bool,
    RunFrame:                      extern "stdcall" fn(*mut ISteamUtils),
    // ... (more functions but i cant be bothered writing them in)
}
pub unsafe fn ISteamUtils_RunFrame(_self: *mut ISteamUtils){ return ((*(*_self).vtable_).RunFrame)(_self); }
pub unsafe fn ISteamUtils_GetAppID(_self: *mut ISteamUtils)-> u32{ return ((*(*_self).vtable_).GetAppID)(_self); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUtils {
    pub vtable_: *const ISteamUtils__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamClient__bindgen_vtable{
    CreateSteamPipe:                extern "stdcall" fn(*mut ISteamClient) -> HSteamPipe,
    BReleaseSteamPipe:              extern "stdcall" fn(*mut ISteamClient, HSteamPipe) -> bool,
    ConnectToGlobalUser:            extern "stdcall" fn(*mut ISteamClient, HSteamPipe) -> HSteamUser,
    CreateLocalUser:                extern "stdcall" fn(*mut ISteamClient, *mut HSteamPipe, EAccountType) -> HSteamUser,
    ReleaseUser:                    extern "stdcall" fn(*mut ISteamClient, HSteamPipe, HSteamUser),
    GetISteamUser:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> *mut ISteamUser,
    GetISteamGameServer:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServer
    SetLocalIPBinding:              extern "stdcall" fn(*mut ISteamClient, UNK_PTR, u16), // not sure if this one is right????
    GetISteamFriends:               extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamFriends,
    GetISteamUtils:                 extern "stdcall" fn(*mut ISteamClient, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUtils,
    GetISteamMatchmaking:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmaking,
    GetISteamMatchmakingServers:    extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmakingServers,
    GetISteamGenericInterface:      extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: void,
    GetISteamUserStats:             extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUserStats,
    GetISteamGameServerStats:       extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServerStats,
    GetISteamApps:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamApps,
    GetISteamNetworking:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamNetworking,
    GetISteamRemoteStorage:         extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemoteStorage,
    GetISteamScreenshots:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamScreenshots,
    GetISteamGameSearch:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameSearch,
    RunFrame:                       extern "stdcall" fn(*mut ISteamClient),
    GetIPCCallCount:                extern "stdcall" fn(*mut ISteamClient) -> u32,
    SetWarningMessageHook:          extern "stdcall" fn(*mut ISteamClient, SteamAPIWarningMessageHook_t),
    BShutdownIfAllPipesClosed:      extern "stdcall" fn(*mut ISteamClient) -> bool,
    GetISteamHTTP:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTTP,
    GetISteamController:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamController,
    GetISteamUGC:                   extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUGC,
    GetISteamMusic:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusic,
    GetISteamMusicRemote:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusicRemote,
    GetISteamHTMLSurface:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTMLSurface,
    DEPRECATED_Set_SteamAPI_CPostAPIResultInProcess:    extern "stdcall" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    DEPRECATED_Remove_SteamAPI_CPostAPIResultInProcess: extern "stdcall" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    Set_SteamAPI_CCheckCallbackRegisteredInProcess:     extern "stdcall" fn(*mut ISteamClient, SteamAPI_CheckCallbackRegistered_t),
    GetISteamInventory:             extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInventory,
    GetISteamVideo:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamVideo,
    GetISteamParentalSettings:      extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamParentalSettings,
    GetISteamInput:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInput,
    ISteamParties:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: GetISteamParties,
    GetISteamRemotePlay:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemotePlay,
    DestroyAllInterfaces:           extern "stdcall" fn(*mut ISteamClient),
}
pub unsafe fn ISteamClient_CreateSteamPipe(_self: *mut ISteamClient) -> HSteamPipe{ return ((*(*_self).vtable_).CreateSteamPipe)(_self); }
pub unsafe fn ISteamClient_ConnectToGlobalUser(_self: *mut ISteamClient, pipe: HSteamPipe) -> HSteamUser{ return ((*(*_self).vtable_).ConnectToGlobalUser)(_self, pipe); }
pub unsafe fn ISteamClient_GetISteamGenericInterface(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> UNK_PTR{ return ((*(*_self).vtable_).GetISteamGenericInterface)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_GetISteamUser(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> *mut ISteamUser{ return ((*(*_self).vtable_).GetISteamUser)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_ReleaseUser(_self: *mut ISteamClient, pipe: HSteamPipe, user: HSteamUser) { ((*(*_self).vtable_).ReleaseUser)(_self, pipe, user); }
pub unsafe fn ISteamClient_BReleaseSteamPipe(_self: *mut ISteamClient, pipe: HSteamPipe) -> bool{ return ((*(*_self).vtable_).BReleaseSteamPipe)(_self, pipe); }
pub unsafe fn ISteamClient_BShutdownIfAllPipesClosed(_self: *mut ISteamClient) -> bool{ return ((*(*_self).vtable_).BShutdownIfAllPipesClosed)(_self); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamClient {
    pub vtable_: *const ISteamClient__bindgen_vtable,
}

#[link(name = "kernel32")]
#[link(name = "user32")]
extern "stdcall" {
    pub fn LoadLibraryA(lpFileName: *const u8) -> HMODULE;
    pub fn LoadLibraryExA( lpLibFileName: *const u8, hFile:u64, dwFlags: u32) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *const ();
    pub fn FreeLibrary(hModule: HMODULE) -> bool;
    pub fn RegOpenKeyExA(hKey: HKEY, lpSubKey: *const u8, ulOptions:u32, samDesired:i32, phkResult:*mut HKEY) -> LSTATUS;
    pub fn RegQueryValueExA(hKey: HKEY, lpValueName: *const u8, lpReserved:u64, lpType: *mut i32, lpData: *mut u8, lpcbData:*mut u32) -> LSTATUS;
    pub fn RegCloseKey(hKey: HKEY) -> LSTATUS;
    pub fn OpenProcess(dwDesiredAccess: i32, bInheritHandle: bool, dwProcessId:u32) -> HANDLE;
    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut i32) -> bool;
    pub fn CloseHandle(hObject: HANDLE) -> bool;
}

pub struct steam_data{
    DAT_ISteamClient_ptr: *mut ISteamClient,
    DAT_steam_IPC_pipe: HSteamPipe,
    
    DAT_ISteamUser_ptr: *mut ISteamUser,
    DAT_steamclient_hmodule: HMODULE,
    DAT_steam_alt_IPC_pipe: HSteamPipe,
    DAT_steam_user: HSteamUser,

    DAT_steam_client_ReleaseThreadLocalMemory: client_ReleaseThreadLocalMemory,
    DAT_steam_BGetCallback_func: BGetCallback_func,
    DAT_steam_FreeLastCallback_func: FreeLastCallback_func,
    DAT_steam_GetAPICallResult_func: GetAPICallResult_func,
    DAT_SteamUtils010: *mut ISteamUtils,
    DAT_SteamInput006: *mut ISteamInput,
    DAT_SteamController008: *mut ISteamController,
    result: i32,
}

// FINISHED
unsafe fn SteamAPI_IsSteamRunning() -> bool{
    let mut proc_key: HKEY = 0;
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess\0".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        return false;
    }

    let mut dwProcessId:u32 = 0;
    let mut cbdata:u32 = 4;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "pid\0".as_ptr(), 0, &mut _type as *mut i32, &mut dwProcessId as *mut u32 as *mut u8, &mut cbdata as *mut u32) != 0 {
        RegCloseKey(proc_key);
        return false;
    }
    RegCloseKey(proc_key);
    
    let hProcess: HANDLE = OpenProcess(0x400, false, dwProcessId);
    if hProcess == 0{
        return false;
    }

    let mut exit_code:i32 = 0;
    if GetExitCodeProcess(hProcess, &mut exit_code as *mut i32)
    && (exit_code == STILL_ACTIVE) {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

unsafe fn steam_write_install_path() -> Vec<u8>{
    let mut proc_key: HKEY = 0;
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess\0".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        return vec![0u8; 0];
    }
    let mut out_proc_path = [0u8; 0x410];
    let mut cbdata:u32 = 0x410;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "SteamClientDll64\0".as_ptr(), 0, &mut _type as *mut i32, out_proc_path.as_mut_ptr(), &mut cbdata as *mut u32) != 0 {
        RegCloseKey(proc_key);
        return vec![0u8; 0];
    }
    RegCloseKey(proc_key);

    // manually terminate wstring
    out_proc_path[cbdata as usize] = 0;

    // alternative method to get filename if that failed (pretty sure this cant work with our setup)
    // if (!out_buf[0]) {
    //     WCHAR alt_proc_path[0x103];
    //     alt_proc_path[0] = L'\0';
    //     if (!GetModuleFileNameW(GetModuleHandleA("steamclient64.dll"), alt_proc_path, 0x104) < 0x104){
    //         return false;
    //     }
    //     if (!WideCharToMultiByte(0xfde9, 0, alt_proc_path, -1, out_buf, 0x410, 0, 0)){
    //         return false;
    //     }
    // }
    return out_proc_path.to_vec();
}
unsafe fn init_steam_client(steam: &mut steam_data) -> i32{
    if SteamAPI_IsSteamRunning() == false{
        return 8;
    }

    let steam_install_path = steam_write_install_path();
    if steam_install_path.len() == 0{
        return 9;
    }

    let s = String::from_utf8(steam_install_path.clone()).expect("Found invalid UTF-8");
    print!("\nBOLD: path: {} \n\n", s); // NOTE: for some reason this prints the WHOLE *non-delimited* string, however its perfectly fine when cast to just a ptr
    
    let steamclient_library = LoadLibraryExA(steam_install_path.as_ptr(), 0, 8);
    if steamclient_library == 0{
        return 11;
    }

    let create_interface_func: CreateInterface = std::mem::transmute(GetProcAddress(steamclient_library, "CreateInterface\0".as_ptr()));
    if create_interface_func as *const () == std::ptr::null_mut() {
        FreeLibrary(steamclient_library);
        return 12;
    }

    steam.DAT_steam_client_ReleaseThreadLocalMemory = std::mem::transmute(GetProcAddress(steamclient_library, "Steam_ReleaseThreadLocalMemory\0".as_ptr()));

    steam.DAT_ISteamClient_ptr = (create_interface_func)("SteamClient021\0".as_ptr(), std::ptr::null_mut()).cast::<ISteamClient>();
    steam.DAT_steamclient_hmodule = steamclient_library; // not sure why this is set without resulting_interface being true
    if steam.DAT_steamclient_hmodule == 0 {
        FreeLibrary(steamclient_library);
        return 13;
    }
    return 0;
}
unsafe fn SteamAPI_Shutdown(steam: &mut steam_data){
    if steam.DAT_steam_IPC_pipe != 0 && steam.DAT_steam_user != 0{
        ISteamClient_ReleaseUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe, steam.DAT_steam_user);
        steam.DAT_steam_user = 0;}

    if steam.DAT_steam_IPC_pipe != 0{
        ISteamClient_BReleaseSteamPipe(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe);
        steam.DAT_steam_IPC_pipe = 0;}

    if steam.DAT_steam_alt_IPC_pipe != 0 {
        ISteamClient_BReleaseSteamPipe(steam.DAT_ISteamClient_ptr, steam.DAT_steam_alt_IPC_pipe);
        steam.DAT_steam_alt_IPC_pipe = 0;}
    steam.DAT_steam_client_ReleaseThreadLocalMemory = std::mem::transmute(0u64);

    if steam.DAT_ISteamClient_ptr != std::ptr::null_mut(){
        ISteamClient_BShutdownIfAllPipesClosed(steam.DAT_ISteamClient_ptr);
        steam.DAT_ISteamClient_ptr = std::ptr::null_mut();}

    if steam.DAT_steamclient_hmodule != 0{
        FreeLibrary(steam.DAT_steamclient_hmodule);
        steam.DAT_steamclient_hmodule = 0;}
}
unsafe fn init_steam() -> steam_data{
    let mut steam = steam_data {
        DAT_ISteamClient_ptr: std::ptr::null_mut(),
        DAT_steam_IPC_pipe: 0,
        DAT_ISteamUser_ptr: std::ptr::null_mut(),
        DAT_steamclient_hmodule: 0,
        DAT_steam_alt_IPC_pipe: 0,
        DAT_steam_user: 0,
        DAT_steam_client_ReleaseThreadLocalMemory: std::mem::transmute(0u64),
        DAT_steam_BGetCallback_func: std::mem::transmute(0u64),
        DAT_steam_FreeLastCallback_func: std::mem::transmute(0u64),
        DAT_steam_GetAPICallResult_func: std::mem::transmute(0u64),
        DAT_SteamUtils010: std::ptr::null_mut(),
        DAT_SteamInput006: std::ptr::null_mut(),
        DAT_SteamController008: std::ptr::null_mut(),
        result: 0,
    };

    // ensure we have a steam_appid.txt with the correct appid
    const app_id:u32 = 0x00085E4E;
    let text_path = Path::new("steam_appid.txt");
    if text_path.exists(){
        use std::fs;
        let contents = fs::read_to_string(text_path);
        if contents.is_err(){
            steam.result = 15; 
            return steam;
        }
        if contents.unwrap() != "548430"{
            steam.result = 16;
            return steam; 
        }
    } else {
        use std::io::Write;
        let mut output = File::create(text_path);
        if output.is_err(){
            steam.result = 17;
            return steam;
        }
        let write_result = write!(output.unwrap(), "548430");
        if write_result.is_err(){
            steam.result = 18;
            return steam;
        }
    }

    if steam.DAT_ISteamClient_ptr != std::ptr::null_mut() {
        steam.result = 1;
        return steam;
    }

    let result = init_steam_client(&mut steam);
    if result != 0 {
        steam.result = result;
        return steam;
    }

    steam.DAT_steam_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    if steam.DAT_steam_IPC_pipe == 0 {
        SteamAPI_Shutdown(&mut steam);
        steam.result = 2;
        return steam;
    }

    steam.DAT_steam_user = ISteamClient_ConnectToGlobalUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe);
    if steam.DAT_steam_user == 0 {
        SteamAPI_Shutdown(&mut steam);
        steam.result = 3;
        return steam;
    }

    //let interface_str_ptr = PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS;
    // let interface_check_func: Steam_IsKnownInterface = (Steam_IsKnownInterface)GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_IsKnownInterface");
    // if (interface_check_func) {
    //     while (*interface_str_ptr) {
    //         if (!(*interface_check_func)(interface_str_ptr)) {
    //             SteamAPI_Shutdown();
    //             return 4;}
    //         // iterate string till we reach the next null terminator
    //         while (*interface_str_ptr++);
    //     }
    // }

    if steam.DAT_steam_client_ReleaseThreadLocalMemory as *const () == std::ptr::null_mut(){
        steam.DAT_steam_alt_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    }
    
    steam.DAT_SteamUtils010 = ISteamClient_GetISteamGenericInterface(steam.DAT_ISteamClient_ptr, 0, steam.DAT_steam_IPC_pipe, "SteamUtils010\0".as_ptr()).cast::<ISteamUtils>();
    if steam.DAT_SteamUtils010 == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        steam.result = 5;
        return steam;
    }

    steam.DAT_ISteamUser_ptr = ISteamClient_GetISteamUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_user, steam.DAT_steam_IPC_pipe, "SteamUser023\0".as_ptr());
    if steam.DAT_ISteamUser_ptr == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        steam.result = 6;
        return steam;
    }

    if std::env::var("SteamAppId").is_err() {
        std::env::set_var("SteamAppId", app_id.to_string());}
    if std::env::var("SteamGameId").is_err() {
        std::env::set_var("SteamGameId", app_id.to_string());
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    if std::env::var("SteamOverlayGameId").is_err() {
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    steam.DAT_steam_BGetCallback_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_BGetCallback\0".as_ptr()));
    steam.DAT_steam_FreeLastCallback_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_FreeLastCallback\0".as_ptr()));
    steam.DAT_steam_GetAPICallResult_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_GetAPICallResult\0".as_ptr()));
    
    if steam.DAT_steam_BGetCallback_func     as *const () == std::ptr::null_mut()
    || steam.DAT_steam_FreeLastCallback_func as *const () == std::ptr::null_mut()
    || steam.DAT_steam_GetAPICallResult_func as *const () == std::ptr::null_mut(){
        SteamAPI_Shutdown(&mut steam);
        steam.result = 14;
        return steam;
    }
    
    // load some extra junk (which is theoretically not needed?)
    steam.DAT_SteamInput006 = ISteamClient_GetISteamGenericInterface(steam.DAT_ISteamClient_ptr, 0, steam.DAT_steam_IPC_pipe, "SteamInput006\0".as_ptr()).cast::<ISteamInput>();
    steam.DAT_SteamController008 = ISteamClient_GetISteamGenericInterface(steam.DAT_ISteamClient_ptr, 0, steam.DAT_steam_IPC_pipe, "SteamController008\0".as_ptr()).cast::<ISteamController>();
    
    // init the utils thing by getting appid??
    let test_id = ISteamUtils_GetAppID(steam.DAT_SteamUtils010);
    if test_id == 0 {
        SteamAPI_Shutdown(&mut steam);
        steam.result = 19;
        return steam;
    }

    return steam;
}


// 
unsafe fn route_callback(iCallback:i32, data: *mut u8) -> Option<i32>{
    if iCallback == 154 { return Some(*(data as *mut i32)); }
    return None;
}

unsafe fn process_callbacks(steam: &steam_data) -> Option<i32> {
    let mut cb_output = CallbackMsg_t { m_hSteamUser: 0, m_iCallback: 0, m_pubParam: std::ptr::null_mut(), m_cubParam: 0};
    while (steam.DAT_steam_BGetCallback_func)(steam.DAT_steam_IPC_pipe, &mut cb_output as *mut CallbackMsg_t){

        print!("\nCallback recieved: {}\n\n", cb_output.m_iCallback);

        // if the callback type is 'SteamAPICallCompleted_t' then we have to manually await the thing
        if cb_output.m_iCallback == 703 {
            let pCallCompleted  = *std::mem::transmute::<*mut u8, *mut SteamAPICallCompleted_t>(cb_output.m_pubParam);
            let mut pTmpCallResult = vec![0u8; pCallCompleted.m_cubParam as usize];
            let mut bFailed = false;
            if ((steam.DAT_steam_GetAPICallResult_func)(steam.DAT_steam_IPC_pipe, pCallCompleted.m_hAsyncCall, pTmpCallResult.as_mut_ptr(), pCallCompleted.m_cubParam, pCallCompleted.m_iCallback, &mut bFailed as *mut bool)){
                let var: Option<i32> = route_callback(pCallCompleted.m_iCallback, pTmpCallResult.as_mut_ptr());
                if var.is_some(){
                    return var;
                }
            }
        } else {
             let var: Option<i32> = route_callback(cb_output.m_iCallback, cb_output.m_pubParam);
             if var.is_some(){
                return var;
            }
        }
        
        
        // memset recieved memory (this is just what steam does)
        for i in 0..cb_output.m_cubParam {
            *cb_output.m_pubParam = 0;
        }
        (steam.DAT_steam_FreeLastCallback_func)(steam.DAT_steam_IPC_pipe);
    }
    return None;
}


unsafe fn flush_alt_callbacks(steam: &steam_data){
    if steam.DAT_steam_BGetCallback_func as *const () == std::ptr::null() { 
        return; 
    }
    let mut cb_output = CallbackMsg_t { m_hSteamUser: 0, m_iCallback: 0, m_pubParam: std::ptr::null_mut(), m_cubParam: 0};
    loop {
        if (steam.DAT_steam_BGetCallback_func)(steam.DAT_steam_IPC_pipe, &mut cb_output as *mut CallbackMsg_t) == false{
            break;
        }

        if steam.DAT_steam_FreeLastCallback_func as *const () != std::ptr::null() {
            (steam.DAT_steam_FreeLastCallback_func)(steam.DAT_steam_IPC_pipe);
        }
    }
}
unsafe fn SteamAPI_RunCallbacks(steam: &steam_data) -> Option<i32>{
    // init/run steam untils
    if steam.DAT_SteamUtils010 != std::ptr::null_mut() {ISteamUtils_RunFrame(steam.DAT_SteamUtils010);}
    // init/run steam input
    if steam.DAT_SteamInput006 != std::ptr::null_mut() {ISteamInput_RunFrame(steam.DAT_SteamInput006, false);}
    // init/run steam controller
    if steam.DAT_SteamController008 != std::ptr::null_mut(){ISteamController_RunFrame(steam.DAT_SteamController008);}

    let result = process_callbacks(steam);
    if steam.DAT_steam_alt_IPC_pipe != 0{
        flush_alt_callbacks(steam);
    }
    return result;
}


pub unsafe fn steam_main() -> Result<String, &'static str>{
    let mut init = init_steam();
    match init.result {
     1 => return Err("steam is already running"),
     2 => return Err("Cannot create IPC pipe to Steam client process.  Steam is probably not running."),
     3 => return Err("ConnectToGlobalUser failed."),
     4 => return Err("interface check failed"),
     5 => return Err("failed to load 'SteamUtils010' interface"),
     6 => return Err("failed to load 'SteamUser023' interface"),
     7 => return Err("No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder."),
     8 => return Err("[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam."),
     9 => return Err("Could not determine Steam client install directory."),
    10 => return Err("couldn't convert path to wide string"),
    11 => return Err("Failed to load steam client module"),
    12 => return Err("Unable to locate interface factory in steamclient64.dll"),
    13 => return Err("failed to load 'SteamClient021' interface"),
    14 => return Err("failed to load callback API interface functions"),
    15 => return Err("failed to open steam_appid.txt, however the file exists, maybe its in use by another process"),
    16 => return Err("contents of steam_appid.txt do not match the required text: \"548430\""),
    17 => return Err("failed to create steam_appid.txt file"),
    18 => return Err("failed to write to steam_appid.txt file"),
    19 => return Err("failed to read appid, implying likely failure of gettting encrypted app ticket"),
     0 => {

        // request the Steam Encrypted App Ticket
        let k_unSecretData = vec![0x39,0x66,0x37,0x61,0x62,0x64,0x36,0x33,0x37,0x35,0x63,0x34,0x61,0x33,0x66,0x64,0x35,0x30,0x61,0x37,0x32,0x62,0x30,0x39,0x31,0x31,0x31,0x35,0x63,0x62,0x32,0x33,0x37,0x32,0x64,0x35,0x65,0x35,0x61,0x63,0x37,0x61,0x37,0x37,0x31,0x39,0x65,0x35,0x34,0x30,0x35,0x33,0x30,0x62,0x32,0x39,0x37,0x65,0x63,0x34,0x62,0x65,0x37,0x39,0x00];
        let hSteamAPICall = ISteamUser_RequestEncryptedAppTicket(init.DAT_ISteamUser_ptr, k_unSecretData.as_ptr(), k_unSecretData.len() as i32);

        // loop sleep until we are given the green light to retrieve our encrypted app ticket
        let mut var: Option<i32> = None;
        let mut iter_count = 0; // used to abort after 30 seconds (300 attempts)
        while var.is_none(){
            iter_count += 1;
            if iter_count > 300{ SteamAPI_Shutdown(&mut init); return Err("Failed to recieve encrypted app ticket callback."); }
            use std::{thread, time::Duration};
            thread::sleep(Duration::from_millis(1000));
            var = SteamAPI_RunCallbacks(&init);
        }

        // evaluate outcome
        let mut error_log = "Unspecifed RequestEncryptedAppTicket error.";
        print!("\nBOLD: status {}!!!\n\n", var.unwrap());
        match var.unwrap(){
        1 => {
            let mut data_buffer = vec![0u8; 1024];
            let mut output_size = 0u32;
            if ISteamUser_GetEncryptedAppTicket(init.DAT_ISteamUser_ptr, data_buffer.as_mut_ptr(), 1024i32, &mut output_size as *mut u32) == false{
                SteamAPI_Shutdown(&mut init);
                return Err("GetEncryptedAppTicket call failed.");
            }
            SteamAPI_Shutdown(&mut init);

            use base64::{engine::general_purpose, Engine as _};
            return Ok(general_purpose::STANDARD.encode(&data_buffer[0..output_size as usize]));
        },
        3 => {error_log = "Calling RequestEncryptedAppTicket while not connected to steam results in this error."},
        29 => {error_log = "Calling RequestEncryptedAppTicket while there is already a pending request results in this error."},
        25 => {error_log = "Calling RequestEncryptedAppTicket more than once per minute returns this error."},
        _ => {}
        }

        

        SteamAPI_Shutdown(&mut init);
        return Err(error_log);
    }
    _ => return Err("invalid steam error")
    }
}