// Named argument values only; opaque and secret buffers are never dereferenced.

void CaptureCoCreateGuid(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], GUID* guid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" guid="); AppendHexText(detailBuffer, ApiReturnBits(guid)); (void)resultValue; }

void CaptureCoGetCallerTID(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPDWORD tid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" tid="); AppendHexText(detailBuffer, ApiReturnBits(tid)); (void)resultValue; }

void CaptureCoGetCurrentLogicalThreadId(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], GUID* guid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" guid="); AppendHexText(detailBuffer, ApiReturnBits(guid)); (void)resultValue; }

void CaptureCoGetContextToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], ULONG_PTR* token, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" token="); AppendHexText(detailBuffer, ApiReturnBits(token)); (void)resultValue; }

void CaptureCoRevokeClassObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD cookie, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" cookie="); AppendHexText(detailBuffer, ApiReturnBits(cookie)); (void)resultValue; }

void CaptureCoResumeClassObjects(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HRESULT resultValue)
{ (void)detailBuffer; (void)resultValue; }

void CaptureCoSuspendClassObjects(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HRESULT resultValue)
{ (void)detailBuffer; (void)resultValue; }

void CaptureCoDisconnectObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPUNKNOWN object, DWORD reserved, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" reserved="); AppendHexText(detailBuffer, ApiReturnBits(reserved)); (void)resultValue; }

void CaptureCoLockObjectExternal(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPUNKNOWN object, BOOL lock, BOOL lastUnlockReleases, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" lock="); AppendHexText(detailBuffer, ApiReturnBits(lock)); AppendWideText(detailBuffer, L" lastUnlockReleases="); AppendHexText(detailBuffer, ApiReturnBits(lastUnlockReleases)); (void)resultValue; }

void CaptureCoGetPSClsid(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFIID iid, GUID* clsid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(clsid)); (void)resultValue; }

void CaptureCoRegisterPSClsid(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFIID iid, REFCLSID clsid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(&clsid)); (void)resultValue; }

void CaptureCoGetCallContext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFIID iid, LPVOID* object, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)resultValue; }

void CaptureCoRegisterClassObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID clsid, LPUNKNOWN object, DWORD context, DWORD flags, LPDWORD cookie, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(&clsid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" context="); AppendHexText(detailBuffer, ApiReturnBits(context)); (void)flags; (void)cookie; (void)resultValue; }

void CaptureCoMarshalHresult(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, HRESULT status, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); AppendWideText(detailBuffer, L" status="); AppendHexText(detailBuffer, ApiReturnBits(status)); (void)resultValue; }

void CaptureCoUnmarshalHresult(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, HRESULT* status, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); AppendWideText(detailBuffer, L" status="); AppendHexText(detailBuffer, ApiReturnBits(status)); (void)resultValue; }

void CaptureCoReleaseMarshalData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); (void)resultValue; }

void CaptureCoUnmarshalInterface(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, REFIID iid, LPVOID* object, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)resultValue; }

void CaptureCoMarshalInterface(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, REFIID iid, LPUNKNOWN object, DWORD context, LPVOID destination, DWORD flags, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)context; (void)destination; (void)flags; (void)resultValue; }

void CaptureCoGetMarshalSizeMax(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], ULONG* size, REFIID iid, LPUNKNOWN object, DWORD context, LPVOID destination, DWORD flags, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)context; (void)destination; (void)flags; (void)resultValue; }

void CaptureBCryptGetProperty(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HANDLE object, LPCWSTR property, PUCHAR output, ULONG outputSize, ULONG* resultSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" property="); AppendHexText(detailBuffer, ApiReturnBits(property)); AppendWideText(detailBuffer, L" output="); AppendHexText(detailBuffer, ApiReturnBits(output)); (void)outputSize; (void)resultSize; (void)flags; (void)resultValue; }

void CaptureBCryptSetProperty(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HANDLE object, LPCWSTR property, PUCHAR input, ULONG inputSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); AppendWideText(detailBuffer, L" property="); AppendHexText(detailBuffer, ApiReturnBits(property)); AppendWideText(detailBuffer, L" input="); AppendHexText(detailBuffer, ApiReturnBits(input)); (void)inputSize; (void)flags; (void)resultValue; }

void CaptureBCryptGenerateKeyPair(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE* key, ULONG length, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" algorithm="); AppendHexText(detailBuffer, ApiReturnBits(algorithm)); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, ApiReturnBits(length)); (void)flags; (void)resultValue; }

void CaptureBCryptFinalizeKeyPair(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE key, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); (void)resultValue; }

void CaptureBCryptDuplicateHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HASH_HANDLE hash, BCRYPT_HASH_HANDLE* duplicate, PUCHAR object, ULONG objectSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, ApiReturnBits(hash)); AppendWideText(detailBuffer, L" duplicate="); AppendHexText(detailBuffer, ApiReturnBits(duplicate)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)objectSize; (void)flags; (void)resultValue; }

void CaptureBCryptDuplicateKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE key, BCRYPT_KEY_HANDLE* duplicate, PUCHAR object, ULONG objectSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" duplicate="); AppendHexText(detailBuffer, ApiReturnBits(duplicate)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)objectSize; (void)flags; (void)resultValue; }

void CaptureBCryptExportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE key, BCRYPT_KEY_HANDLE exportKey, LPCWSTR blobType, PUCHAR output, ULONG outputSize, ULONG* resultSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" exportKey="); AppendHexText(detailBuffer, ApiReturnBits(exportKey)); AppendWideText(detailBuffer, L" blobType="); AppendHexText(detailBuffer, ApiReturnBits(blobType)); (void)output; (void)outputSize; (void)resultSize; (void)flags; (void)resultValue; }

void CaptureBCryptSignHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE key, VOID* padding, PUCHAR hash, ULONG hashSize, PUCHAR signature, ULONG signatureSize, ULONG* resultSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" padding="); AppendHexText(detailBuffer, ApiReturnBits(padding)); AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, ApiReturnBits(hash)); (void)hashSize; (void)signature; (void)signatureSize; (void)resultSize; (void)flags; (void)resultValue; }

void CaptureBCryptVerifySignature(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE key, VOID* padding, PUCHAR hash, ULONG hashSize, PUCHAR signature, ULONG signatureSize, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, ApiReturnBits(key)); AppendWideText(detailBuffer, L" padding="); AppendHexText(detailBuffer, ApiReturnBits(padding)); AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, ApiReturnBits(hash)); (void)hashSize; (void)signature; (void)signatureSize; (void)flags; (void)resultValue; }

void CaptureBCryptSecretAgreement(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE privateKey, BCRYPT_KEY_HANDLE publicKey, BCRYPT_SECRET_HANDLE* secret, ULONG flags, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" privateKey="); AppendHexText(detailBuffer, ApiReturnBits(privateKey)); AppendWideText(detailBuffer, L" publicKey="); AppendHexText(detailBuffer, ApiReturnBits(publicKey)); AppendWideText(detailBuffer, L" secret="); AppendHexText(detailBuffer, ApiReturnBits(secret)); (void)flags; (void)resultValue; }

void CaptureBCryptDestroySecret(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_SECRET_HANDLE secret, NTSTATUS resultValue)
{ AppendWideText(detailBuffer, L" secret="); AppendHexText(detailBuffer, ApiReturnBits(secret)); (void)resultValue; }

void CaptureCopySid(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD length, PSID destination, PSID source, BOOL resultValue)
{ AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, ApiReturnBits(length)); AppendWideText(detailBuffer, L" destination="); AppendHexText(detailBuffer, ApiReturnBits(destination)); AppendWideText(detailBuffer, L" source="); AppendHexText(detailBuffer, ApiReturnBits(source)); (void)resultValue; }

void CaptureInitializeSid(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSID sid, PSID_IDENTIFIER_AUTHORITY authority, BYTE subAuthorityCount, BOOL resultValue)
{ AppendWideText(detailBuffer, L" sid="); AppendHexText(detailBuffer, ApiReturnBits(sid)); AppendWideText(detailBuffer, L" authority="); AppendHexText(detailBuffer, ApiReturnBits(authority)); AppendWideText(detailBuffer, L" subAuthorityCount="); AppendHexText(detailBuffer, ApiReturnBits(subAuthorityCount)); (void)resultValue; }

void CaptureGetSecurityDescriptorOwner(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PSID* owner, LPBOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" owner="); AppendHexText(detailBuffer, ApiReturnBits(owner)); AppendWideText(detailBuffer, L" defaulted="); AppendHexText(detailBuffer, ApiReturnBits(defaulted)); (void)resultValue; }

void CaptureGetSecurityDescriptorGroup(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PSID* group, LPBOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" group="); AppendHexText(detailBuffer, ApiReturnBits(group)); AppendWideText(detailBuffer, L" defaulted="); AppendHexText(detailBuffer, ApiReturnBits(defaulted)); (void)resultValue; }

void CaptureInitializeSecurityDescriptor(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, DWORD revision, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" revision="); AppendHexText(detailBuffer, ApiReturnBits(revision)); (void)resultValue; }

void CaptureGetSecurityDescriptorControl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PSECURITY_DESCRIPTOR_CONTROL control, LPDWORD revision, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, ApiReturnBits(control)); AppendWideText(detailBuffer, L" revision="); AppendHexText(detailBuffer, ApiReturnBits(revision)); (void)resultValue; }

void CaptureGetSecurityDescriptorDacl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, LPBOOL present, PACL* acl, LPBOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" present="); AppendHexText(detailBuffer, ApiReturnBits(present)); AppendWideText(detailBuffer, L" acl="); AppendHexText(detailBuffer, ApiReturnBits(acl)); (void)defaulted; (void)resultValue; }

void CaptureGetSecurityDescriptorSacl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, LPBOOL present, PACL* acl, LPBOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" present="); AppendHexText(detailBuffer, ApiReturnBits(present)); AppendWideText(detailBuffer, L" acl="); AppendHexText(detailBuffer, ApiReturnBits(acl)); (void)defaulted; (void)resultValue; }

void CaptureQueryServiceStatus(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE service, LPSERVICE_STATUS status, BOOL resultValue)
{ AppendWideText(detailBuffer, L" service="); AppendHexText(detailBuffer, ApiReturnBits(service)); AppendWideText(detailBuffer, L" status="); AppendHexText(detailBuffer, ApiReturnBits(status)); (void)resultValue; }

void CaptureQueryServiceConfig2W(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE service, DWORD level, LPBYTE buffer, DWORD bufferSize, LPDWORD bytesNeeded, BOOL resultValue)
{ AppendWideText(detailBuffer, L" service="); AppendHexText(detailBuffer, ApiReturnBits(service)); AppendWideText(detailBuffer, L" level="); AppendHexText(detailBuffer, ApiReturnBits(level)); AppendWideText(detailBuffer, L" buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); (void)bufferSize; (void)bytesNeeded; (void)resultValue; }

void CaptureQueryServiceConfig2A(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE service, DWORD level, LPBYTE buffer, DWORD bufferSize, LPDWORD bytesNeeded, BOOL resultValue)
{ AppendWideText(detailBuffer, L" service="); AppendHexText(detailBuffer, ApiReturnBits(service)); AppendWideText(detailBuffer, L" level="); AppendHexText(detailBuffer, ApiReturnBits(level)); AppendWideText(detailBuffer, L" buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); (void)bufferSize; (void)bytesNeeded; (void)resultValue; }
