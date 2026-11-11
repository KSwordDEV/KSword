// Opaque argument addresses and scalar values only.

void CaptureCreateStreamOnHGlobal(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HGLOBAL memory, BOOL deleteOnRelease, LPSTREAM* stream, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" memory="); AppendHexText(detailBuffer, ApiReturnBits(memory)); AppendWideText(detailBuffer, L" deleteOnRelease="); AppendHexText(detailBuffer, ApiReturnBits(deleteOnRelease)); AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); (void)resultValue; }

void CaptureGetHGlobalFromStream(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTREAM stream, HGLOBAL* memory, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" stream="); AppendHexText(detailBuffer, ApiReturnBits(stream)); AppendWideText(detailBuffer, L" memory="); AppendHexText(detailBuffer, ApiReturnBits(memory)); (void)resultValue; }

void CaptureCoGetMalloc(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD context, LPMALLOC* allocator, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" context="); AppendHexText(detailBuffer, ApiReturnBits(context)); AppendWideText(detailBuffer, L" allocator="); AppendHexText(detailBuffer, ApiReturnBits(allocator)); (void)resultValue; }

void CaptureCoGetApartmentType(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], APTTYPE* type, APTTYPEQUALIFIER* qualifier, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, ApiReturnBits(type)); AppendWideText(detailBuffer, L" qualifier="); AppendHexText(detailBuffer, ApiReturnBits(qualifier)); (void)resultValue; }

void CaptureCLSIDFromString(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCOLESTR text, LPCLSID clsid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(clsid)); (void)resultValue; }

void CaptureStringFromCLSID(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID clsid, LPOLESTR* text, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(&clsid)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); (void)resultValue; }

void CaptureIIDFromString(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCOLESTR text, LPIID iid, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(iid)); (void)resultValue; }

void CaptureStringFromIID(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFIID iid, LPOLESTR* text, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); (void)resultValue; }

void CaptureProgIDFromCLSID(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID clsid, LPOLESTR* text, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" clsid="); AppendHexText(detailBuffer, ApiReturnBits(&clsid)); AppendWideText(detailBuffer, L" text="); AppendHexText(detailBuffer, ApiReturnBits(text)); (void)resultValue; }

void CaptureCoGetObjectContext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFIID iid, LPVOID* object, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" iid="); AppendHexText(detailBuffer, ApiReturnBits(&iid)); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, ApiReturnBits(object)); (void)resultValue; }

void CaptureCreateBindCtx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD reserved, LPBC* context, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" reserved="); AppendHexText(detailBuffer, ApiReturnBits(reserved)); AppendWideText(detailBuffer, L" context="); AppendHexText(detailBuffer, ApiReturnBits(context)); (void)resultValue; }

void CaptureGetRunningObjectTable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD reserved, LPRUNNINGOBJECTTABLE* table, HRESULT resultValue)
{ AppendWideText(detailBuffer, L" reserved="); AppendHexText(detailBuffer, ApiReturnBits(reserved)); AppendWideText(detailBuffer, L" table="); AppendHexText(detailBuffer, ApiReturnBits(table)); (void)resultValue; }

void CaptureSetSecurityDescriptorOwner(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PSID owner, BOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" owner="); AppendHexText(detailBuffer, ApiReturnBits(owner)); AppendWideText(detailBuffer, L" defaulted="); AppendHexText(detailBuffer, ApiReturnBits(defaulted)); (void)resultValue; }

void CaptureSetSecurityDescriptorGroup(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PSID group, BOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" group="); AppendHexText(detailBuffer, ApiReturnBits(group)); AppendWideText(detailBuffer, L" defaulted="); AppendHexText(detailBuffer, ApiReturnBits(defaulted)); (void)resultValue; }

void CaptureSetSecurityDescriptorDacl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, BOOL present, PACL acl, BOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" present="); AppendHexText(detailBuffer, ApiReturnBits(present)); AppendWideText(detailBuffer, L" acl="); AppendHexText(detailBuffer, ApiReturnBits(acl)); (void)defaulted; (void)resultValue; }

void CaptureSetSecurityDescriptorSacl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, BOOL present, PACL acl, BOOL defaulted, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" present="); AppendHexText(detailBuffer, ApiReturnBits(present)); AppendWideText(detailBuffer, L" acl="); AppendHexText(detailBuffer, ApiReturnBits(acl)); (void)defaulted; (void)resultValue; }

void CaptureSetSecurityDescriptorControl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, SECURITY_DESCRIPTOR_CONTROL mask, SECURITY_DESCRIPTOR_CONTROL control, BOOL resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" mask="); AppendHexText(detailBuffer, ApiReturnBits(mask)); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, ApiReturnBits(control)); (void)resultValue; }

void CaptureMakeSelfRelativeSD(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR absolute, PSECURITY_DESCRIPTOR relative, LPDWORD length, BOOL resultValue)
{ AppendWideText(detailBuffer, L" absolute="); AppendHexText(detailBuffer, ApiReturnBits(absolute)); AppendWideText(detailBuffer, L" relative="); AppendHexText(detailBuffer, ApiReturnBits(relative)); AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, ApiReturnBits(length)); (void)resultValue; }

void CaptureMakeAbsoluteSD(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR relative, PSECURITY_DESCRIPTOR absolute, LPDWORD absoluteSize, PACL dacl, LPDWORD daclSize, PACL sacl, LPDWORD saclSize, PSID owner, LPDWORD ownerSize, PSID group, LPDWORD groupSize, BOOL resultValue)
{ AppendWideText(detailBuffer, L" relative="); AppendHexText(detailBuffer, ApiReturnBits(relative)); AppendWideText(detailBuffer, L" absolute="); AppendHexText(detailBuffer, ApiReturnBits(absolute)); AppendWideText(detailBuffer, L" absoluteSize="); AppendHexText(detailBuffer, ApiReturnBits(absoluteSize)); (void)dacl; (void)daclSize; (void)sacl; (void)saclSize; (void)owner; (void)ownerSize; (void)group; (void)groupSize; (void)resultValue; }

void CaptureGetSecurityDescriptorRMControl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR descriptor, PUCHAR control, DWORD resultValue)
{ AppendWideText(detailBuffer, L" descriptor="); AppendHexText(detailBuffer, ApiReturnBits(descriptor)); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, ApiReturnBits(control)); (void)resultValue; }
