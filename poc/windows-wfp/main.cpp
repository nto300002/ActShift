#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>

#include <iostream>
#include <string>
#include <vector>

namespace {

// These IDs belong only to this PoC. Never reuse IDs from another WFP product.
GUID kProviderKey = {0xe8e8bdf7, 0x63bd, 0x4cbe, {0xa7, 0x8a, 0x54, 0x36, 0x6b, 0x47, 0xa4, 0xa1}};
GUID kSubLayerKey = {0xb382c09b, 0x8796, 0x4a6d, {0xb4, 0x65, 0x95, 0x8b, 0xed, 0xd8, 0x2b, 0x25}};
GUID kV4FilterKey = {0x4263ad4b, 0x23cb, 0x4ddb, {0xa9, 0x22, 0x30, 0x5a, 0x08, 0xf2, 0x2c, 0x43}};
GUID kV6FilterKey = {0x53fb0672, 0x6a0a, 0x4c1b, {0x87, 0x68, 0xd0, 0xa6, 0x6d, 0xe2, 0x4a, 0xf8}};

void PrintError(const wchar_t* operation, DWORD code) {
  std::wcerr << operation << L" failed (0x" << std::hex << std::uppercase << code
             << std::dec << L").\n";
}

bool IsElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD bytes = 0;
  const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation,
                                      sizeof(elevation), &bytes);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated != 0;
}

std::wstring FullExistingFilePath(const wchar_t* input) {
  const DWORD needed = GetFullPathNameW(input, 0, nullptr, nullptr);
  if (needed == 0) return {};
  std::vector<wchar_t> path(needed);
  const DWORD length = GetFullPathNameW(input, needed, path.data(), nullptr);
  if (length == 0 || length >= needed) return {};
  const DWORD attributes = GetFileAttributesW(path.data());
  if (attributes == INVALID_FILE_ATTRIBUTES ||
      (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) return {};
  return std::wstring(path.data(), length);
}

class Engine {
 public:
  Engine() = default;
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;
  ~Engine() { if (handle_ != nullptr) FwpmEngineClose0(handle_); }

  DWORD Open() {
    return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &handle_);
  }
  HANDLE Get() const { return handle_; }

 private:
  HANDLE handle_ = nullptr;
};

class Transaction {
 public:
  explicit Transaction(HANDLE engine) : engine_(engine) {}
  Transaction(const Transaction&) = delete;
  Transaction& operator=(const Transaction&) = delete;
  ~Transaction() { if (active_) FwpmTransactionAbort0(engine_); }

  DWORD Begin() {
    const DWORD result = FwpmTransactionBegin0(engine_, 0);
    active_ = result == ERROR_SUCCESS;
    return result;
  }
  DWORD Commit() {
    const DWORD result = FwpmTransactionCommit0(engine_);
    if (result == ERROR_SUCCESS) active_ = false;
    return result;
  }

 private:
  HANDLE engine_;
  bool active_ = false;
};

DWORD AddFilter(HANDLE engine, const GUID& key, const GUID& layer,
                wchar_t* name, FWP_BYTE_BLOB* appId) {
  FWPM_FILTER_CONDITION0 condition{};
  condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  condition.conditionValue.byteBlob = appId;

  FWPM_FILTER0 filter{};
  filter.filterKey = key;
  filter.displayData.name = name;
  filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
  filter.providerKey = &kProviderKey;
  filter.layerKey = layer;
  filter.subLayerKey = kSubLayerKey;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 15;
  filter.numFilterConditions = 1;
  filter.filterCondition = &condition;
  filter.action.type = FWP_ACTION_BLOCK;
  return FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
}

DWORD RemoveIfPresent(HANDLE engine, const GUID& key,
                      DWORD (*remove)(HANDLE, const GUID*), DWORD missing) {
  const DWORD result = remove(engine, &key);
  return result == missing ? ERROR_SUCCESS : result;
}

DWORD RemoveObjects(HANDLE engine) {
  DWORD result = RemoveIfPresent(engine, kV4FilterKey, FwpmFilterDeleteByKey0,
                                 static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND));
  if (result != ERROR_SUCCESS) return result;
  result = RemoveIfPresent(engine, kV6FilterKey, FwpmFilterDeleteByKey0,
                           static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND));
  if (result != ERROR_SUCCESS) return result;
  result = RemoveIfPresent(engine, kSubLayerKey, FwpmSubLayerDeleteByKey0,
                           static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND));
  if (result != ERROR_SUCCESS) return result;
  return RemoveIfPresent(engine, kProviderKey, FwpmProviderDeleteByKey0,
                         static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND));
}

int BlockApp(const std::wstring& path) {
  if (!IsElevated()) {
    std::wcerr << L"Run this command from an elevated terminal.\n";
    return 1;
  }
  const std::wstring fullPath = FullExistingFilePath(path.c_str());
  if (fullPath.empty()) {
    std::wcerr << L"The executable path does not exist or is a directory.\n";
    return 1;
  }
  std::vector<wchar_t> ownPath(32768);
  const DWORD ownLength = GetModuleFileNameW(nullptr, ownPath.data(),
                                             static_cast<DWORD>(ownPath.size()));
  if (ownLength == 0 || ownLength >= static_cast<DWORD>(ownPath.size())) {
    std::wcerr << L"Could not verify the PoC executable path.\n";
    return 1;
  }
  if (CompareStringOrdinal(fullPath.c_str(), -1, ownPath.data(), -1, TRUE) == CSTR_EQUAL) {
    std::wcerr << L"Refusing to block the recovery executable itself.\n";
    return 1;
  }

  FWP_BYTE_BLOB* appId = nullptr;
  DWORD result = FwpmGetAppIdFromFileName0(fullPath.c_str(), &appId);
  if (result != ERROR_SUCCESS) {
    PrintError(L"FwpmGetAppIdFromFileName0", result);
    return 1;
  }

  Engine engine;
  result = engine.Open();
  if (result != ERROR_SUCCESS) {
    PrintError(L"FwpmEngineOpen0", result);
    void* memory = appId;
    FwpmFreeMemory0(&memory);
    return 1;
  }

  Transaction transaction(engine.Get());
  result = transaction.Begin();
  if (result != ERROR_SUCCESS) {
    PrintError(L"FwpmTransactionBegin0", result);
    void* memory = appId;
    FwpmFreeMemory0(&memory);
    return 1;
  }

  FWPM_PROVIDER0 provider{};
  provider.providerKey = kProviderKey;
  provider.displayData.name = const_cast<wchar_t*>(L"ActShift WFP PoC provider");
  provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
  result = FwpmProviderAdd0(engine.Get(), &provider, nullptr);
  if (result == ERROR_SUCCESS) {
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kSubLayerKey;
    sublayer.displayData.name = const_cast<wchar_t*>(L"ActShift WFP PoC sublayer");
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = &kProviderKey;
    sublayer.weight = 0x8000;
    result = FwpmSubLayerAdd0(engine.Get(), &sublayer, nullptr);
  }
  if (result == ERROR_SUCCESS) {
    result = AddFilter(engine.Get(), kV4FilterKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                       const_cast<wchar_t*>(L"ActShift PoC app block IPv4"), appId);
  }
  if (result == ERROR_SUCCESS) {
    result = AddFilter(engine.Get(), kV6FilterKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                       const_cast<wchar_t*>(L"ActShift PoC app block IPv6"), appId);
  }
  if (result == ERROR_SUCCESS) result = transaction.Commit();

  void* memory = appId;
  FwpmFreeMemory0(&memory);
  if (result != ERROR_SUCCESS) {
    PrintError(L"Adding PoC WFP objects", result);
    std::wcerr << L"No changes were committed. If already installed, run remove first.\n";
    return 1;
  }
  std::wcout << L"Blocking outbound IPv4/IPv6 connections from: " << fullPath
             << L"\nThe filters persist after this program exits and after reboot.\n";
  return 0;
}

int Remove() {
  if (!IsElevated()) {
    std::wcerr << L"Run this command from an elevated terminal.\n";
    return 1;
  }
  Engine engine;
  DWORD result = engine.Open();
  if (result != ERROR_SUCCESS) {
    PrintError(L"FwpmEngineOpen0", result);
    return 1;
  }
  Transaction transaction(engine.Get());
  result = transaction.Begin();
  if (result == ERROR_SUCCESS) result = RemoveObjects(engine.Get());
  if (result == ERROR_SUCCESS) result = transaction.Commit();
  if (result != ERROR_SUCCESS) {
    PrintError(L"Removing PoC WFP objects", result);
    return 1;
  }
  std::wcout << L"ActShift PoC filters, sublayer and provider removed.\n";
  return 0;
}

int Status() {
  Engine engine;
  const DWORD opened = engine.Open();
  if (opened != ERROR_SUCCESS) {
    PrintError(L"FwpmEngineOpen0", opened);
    return 1;
  }
  struct Entry { const wchar_t* name; GUID* key; };
  const Entry entries[] = {{L"IPv4", &kV4FilterKey}, {L"IPv6", &kV6FilterKey}};
  for (const Entry& entry : entries) {
    FWPM_FILTER0* filter = nullptr;
    const DWORD result = FwpmFilterGetByKey0(engine.Get(), entry.key, &filter);
    if (result == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) {
      std::wcout << entry.name << L": not installed\n";
    } else if (result != ERROR_SUCCESS) {
      PrintError(L"FwpmFilterGetByKey0", result);
      return 1;
    } else {
      std::wcout << entry.name << L": installed; filter ID " << filter->filterId
                 << L"; persistent "
                 << ((filter->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0 ? L"yes" : L"no")
                 << L"\n";
      void* memory = filter;
      FwpmFreeMemory0(&memory);
    }
  }
  return 0;
}

void Usage() {
  std::wcerr << L"Usage:\n"
             << L"  actshift-wfp-poc.exe block-app \"C:\\full\\path\\app.exe\"\n"
             << L"  actshift-wfp-poc.exe status\n"
             << L"  actshift-wfp-poc.exe remove\n";
}

int Interactive() {
  std::wcout << L"ActShift WFP PoC - native application network test\n"
             << L"Opening this tool does not install a filter.\n"
             << L"This is a command-line test tool, not a background app.\n\n";
  while (true) {
    std::wcout << L"[1] Show filter status\n"
               << L"[2] Block one executable's outbound traffic (administrator)\n"
               << L"[3] Remove all ActShift PoC filters (administrator)\n"
               << L"[0] Exit\nSelection: " << std::flush;
    std::wstring selection;
    if (!std::getline(std::wcin, selection)) return 0;
    if (selection == L"0") return 0;
    if (selection == L"1") {
      Status();
    } else if (selection == L"2") {
      std::wcout << L"Full path to a disposable test .exe (no quotes): " << std::flush;
      std::wstring path;
      if (!std::getline(std::wcin, path)) return 0;
      BlockApp(path);
    } else if (selection == L"3") {
      Remove();
    } else {
      std::wcout << L"Unknown selection.\n";
    }
    std::wcout << L"\n";
  }
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 1) return Interactive();
  if (argc == 3 && std::wstring(argv[1]) == L"block-app") return BlockApp(argv[2]);
  if (argc == 2 && std::wstring(argv[1]) == L"status") return Status();
  if (argc == 2 && std::wstring(argv[1]) == L"remove") return Remove();
  Usage();
  return 2;
}
